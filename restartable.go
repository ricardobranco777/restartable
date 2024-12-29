//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

import flag "github.com/spf13/pflag"

const version string = "2.3.0"

type proc struct {
	command string
	deleted []string
	ppid    string
	uid     int
	service string
}

var usernames map[int]string

var opts struct {
	short   int
	user    bool
	verbose bool
	version bool
}

var pid1 string

var (
	regexDeleted       = regexp.MustCompile(`/.* \(deleted\)$`)
	regexIgnored       = regexp.MustCompile(`[^/]*/(dev|memfd:|run| )`)
	regexExecMap       = regexp.MustCompile(`^[0-9a-f]+-[0-9a-f]+ r(w|-)x`)
	regexName          = regexp.MustCompile(`(?m)^Name:\t(.*)$`)
	regexPpid          = regexp.MustCompile(`(?m)^PPid:\t(.*)$`)
	regexRuid          = regexp.MustCompile(`(?m)^Uid:\t([0-9]+)\t`)
	regexSystemService = regexp.MustCompile(`\d+:[^:]*:/system\.slice/(?:.*/)?(.*)\.service$`)
	regexUserService   = regexp.MustCompile(`\d+:[^:]*:/user\.slice/(?:.*/)?(.*)\.service$`)
	regexOpenRC        = regexp.MustCompile(`\d+:name=openrc:/(.*)$`)
)

// Quote special characters
func quoteString(str string) string {
	if len(str) > 0 {
		str = strconv.Quote(str)
		return str[1 : len(str)-1]
	}
	return ""
}

func readFile(dirFd int, path string) ([]byte, error) {
	fd, err := unix.Openat(dirFd, path, unix.O_NOFOLLOW, unix.O_RDONLY)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: path, Err: err}
	}
	defer unix.Close(fd)

	data := make([]byte, 0, 1024)
	for {
		if len(data) >= cap(data) {
			d := append(data[:cap(data)], 0)
			data = d[:len(data)]
		}
		if n, err := unix.Read(fd, data[len(data):cap(data)]); n > 0 {
			data = data[:len(data)+n]
		} else {
			if err != nil {
				err = &os.PathError{Op: "read", Path: path, Err: err}
			}
			return data, err
		}
	}
}

func readLink(dirFd int, path string) (string, error) {
	for size := unix.PathMax; ; size *= 2 {
		data := make([]byte, unix.PathMax)
		if n, err := unix.Readlinkat(dirFd, path, data); err != nil {
			return "", &os.PathError{Op: "readlinkat", Path: path, Err: err}
		} else if n != size {
			return string(data[:n]), nil
		}
	}
}

func getUser(uid int) string {
	var username string

	if _, ok := usernames[uid]; ok {
		username = usernames[uid]
	} else {
		if info, err := user.LookupId(strconv.Itoa(uid)); err != nil {
			username = "-"
		} else {
			username = info.Username
		}
		usernames[uid] = username
	}

	return username
}

func getDeleted(dirFd int) ([]string, error) {
	maps, err := readFile(dirFd, "maps")
	if err != nil {
		if errors.Is(err, unix.EACCES) {
			err = nil
		}
		return nil, err
	}

	var files []string
	for _, str := range strings.Split(string(maps), "\n") {
		file := regexDeleted.FindString(str)
		if file != "" && regexExecMap.MatchString(str) && !regexIgnored.MatchString(str) {
			files = append(files, quoteString(strings.TrimSuffix(file, " (deleted)")))
		}
	}
	sort.Strings(files)

	return files, nil
}

func getService(dirFd int) string {
	cgroup, err := readFile(dirFd, "cgroup")
	if err != nil {
		return "-"
	}

	var match []string
	if pid1 == "systemd" {
		if opts.user {
			match = regexUserService.FindStringSubmatch(strings.TrimSpace(string(cgroup)))
		} else {
			match = regexSystemService.FindStringSubmatch(strings.TrimSpace(string(cgroup)))
		}
	} else if pid1 == "openrc" {
		match = regexOpenRC.FindStringSubmatch(strings.TrimSpace(string(cgroup)))
	}

	if len(match) > 1 {
		return match[1]
	}
	return "-"
}

func getInfo(pid int) (*proc, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid))
	dirFd, err := unix.Open(path, unix.O_DIRECTORY|unix.O_PATH, unix.O_RDONLY)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(dirFd)

	files, err := getDeleted(dirFd)
	if err != nil {
		return nil, err
	} else if len(files) == 0 {
		return nil, nil
	}

	data, err := readFile(dirFd, "status")
	if err != nil {
		return nil, err
	}
	status := string(data)

	uid, _ := strconv.Atoi(regexRuid.FindStringSubmatch(status)[1])

	data, err = readFile(dirFd, "cmdline")
	if err != nil {
		return nil, err
	}

	cmdline := []string{}
	if bytes.HasSuffix(data, []byte("\x00")) {
		cmdline = strings.Split(string(data), "\x00")
		cmdline = cmdline[:len(cmdline)-1]
	} else {
		cmdline = append(cmdline, string(data))
	}

	command := ""
	if opts.verbose {
		// Use full path

		// cmdline is empty if zombie, but zombies have void proc.maps
		exe, err := readLink(dirFd, "exe")
		if err != nil {
			exe = ""
		}
		exe = strings.TrimSuffix(exe, " (deleted)")

		if len(cmdline) > 0 && !strings.HasPrefix(cmdline[0], "/") && exe != "" && filepath.Base(cmdline[0]) == filepath.Base(exe) {
			command = exe + " " + strings.Join(cmdline[1:], " ")
		} else {
			command = strings.Join(cmdline, " ")
		}
	} else {
		command = regexName.FindStringSubmatch(status)[1]
		// The command may be truncated to 15 chars in /proc/<pid>/status
		// Also, kernel usermode helpers use "none"
		if len(cmdline) > 0 && cmdline[0] != "" && (len(command) == 15 || command == "none") {
			command = cmdline[0]
		}
		if strings.HasPrefix(command, "/") {
			command = filepath.Base(command)
		} else {
			command = strings.Split(command, " ")[0]
		}
	}

	return &proc{
		command: quoteString(command),
		deleted: files,
		ppid:    regexPpid.FindStringSubmatch(status)[1],
		uid:     uid,
		service: getService(dirFd),
	}, nil
}

func init() {
	log.SetPrefix("ERROR: ")
	log.SetFlags(0)

	flag.CountVarP(&opts.short, "short", "s", "Create a short table not showing the deleted files. Given twice, show only processes which are associated with a system service. Given three times, list the associated system service names only.")
	flag.BoolVarP(&opts.user, "user", "u", false, "show user services instead of system services")
	flag.BoolVarP(&opts.verbose, "verbose", "v", false, "verbose output")
	flag.BoolVarP(&opts.version, "version", "V", false, "show version and exit")
	flag.Parse()

	if opts.version {
		fmt.Printf("v%s %v %s/%s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}
}

func main() {
	usernames = make(map[int]string)

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "WARN: Run this program as root")
	}

	if data, err := os.ReadFile("/proc/1/comm"); err != nil {
		log.Fatal(err)
	} else {
		pid1 = strings.TrimSpace(string(data))
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Fatal(err)
	}

	var pids []int
	for _, entry := range entries {
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)

	services := make(map[string]bool)

	if opts.short < 3 {
		fmt.Printf("%s\t%s\t%s\t%-20s\t%20s\t%s\n", "PID", "PPID", "UID", "User", "Service", "Command")
	}

	channel := make(map[int]chan *proc, len(pids))
	for _, pid := range pids {
		channel[pid] = make(chan *proc)
	}

	go func() {
		for _, pid := range pids {
			go func(pid int) {
				if info, err := getInfo(pid); info != nil && err == nil {
					channel[pid] <- info
				} else {
					if err != nil {
						log.Print(err)
					}
					close(channel[pid])
				}
			}(pid)
		}
	}()

	for _, pid := range pids {
		proc := <-channel[pid]
		if proc == nil {
			continue
		}
		//close(channel[pid])
		if opts.short < 3 {
			fmt.Printf("%d\t%s\t%d\t%-20s\t%20s\t%s\n", pid, proc.ppid, proc.uid, getUser(proc.uid), proc.service, proc.command)
		} else if proc.service != "-" {
			services[proc.service] = true
		}
		if opts.short == 0 {
			for _, deleted := range proc.deleted {
				fmt.Printf("\t%s\n", deleted)
			}
		}
	}

	if opts.short == 3 && len(services) > 0 {
		// Print services in sorted mode
		ss := make([]string, 0, len(services))
		for s := range services {
			ss = append(ss, s)
		}
		sort.Strings(ss)
		for _, service := range ss {
			fmt.Println(service)
		}
	}
}
