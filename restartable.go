//go:build linux

package main

import (
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

type proc struct {
	command string
	deleted []string
	ppid    string
	uid     int
	service string
}

const version string = "v1.0"

var usernames map[int]string

var opts struct {
	proc    string
	quote   bool
	short   int
	verbose bool
	version bool
}

var pid1 string

var regex = struct {
	script, deleted, ignored, execmap, name, ppid, ruid, systemd, openrc *regexp.Regexp
}{
	regexp.MustCompile(`((perl|python|(ruby\.)?ruby)(\d?(\.\d)?)|(a|ba|c|da|fi|k|pdk|tc|z)?sh)$`),
	regexp.MustCompile(`/.* \(deleted\)$`),
	regexp.MustCompile(`[^/]*/(dev|memfd:|run| )`),
	regexp.MustCompile(`^[0-9a-f]+-[0-9a-f]+ r(w|-)x`),
	regexp.MustCompile(`(?m)^Name:\t(.*)$`),
	regexp.MustCompile(`(?m)^PPid:\t(.*)$`),
	regexp.MustCompile(`(?m)^Uid:\t([0-9]+)\t`),
	regexp.MustCompile(`\d+:(?:name=systemd)?:/system\.slice/(?:.*/)?(.*)\.service$`),
	regexp.MustCompile(`\d+:name=openrc:/(.*)$`),
}

var logger *log.Logger

func quoteString(str string) string {
	if opts.quote {
		return strconv.Quote(str)
	} else {
		return str
	}
}

func isFile(path string) bool {
	if info, err := os.Stat(path); err == nil {
		return info.Mode().IsRegular()
	}
	return false
}

func readFile(dirFd int, path string) ([]byte, error) {
	fd, err := unix.Openat(dirFd, path, unix.O_NOFOLLOW, unix.O_RDONLY)
	if err != nil {
		return []byte{}, err
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
			return data, err
		}
	}
}

func readLink(dirFd int, path string) (string, error) {
	for size := unix.PathMax; ; size *= 2 {
		data := make([]byte, unix.PathMax)
		if n, err := unix.Readlinkat(dirFd, path, data); err != nil {
			return "", err
		} else if n != size {
			return quoteString(string(data[:n])), err
		}
	}
}

func getUser(uid int) (username string) {
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

func getDeleted(dirFd int, pid string) (files []string) {
	maps, err := readFile(dirFd, filepath.Join(opts.proc, pid, "maps"))
	if err != nil {
		return
	}

	for _, str := range strings.Split(string(maps), "\n") {
		file := regex.deleted.FindString(str)
		if file != "" && regex.execmap.MatchString(str) && !regex.ignored.MatchString(str) {
			files = append(files, quoteString(strings.TrimSuffix(file, " (deleted)")))
		}
	}
	sort.Sort(sort.StringSlice(files))

	return
}

func getService(dirFd int, pid string) (service string) {
	cgroup, err := readFile(dirFd, filepath.Join(opts.proc, pid, "cgroup"))
	if err != nil {
		return "-"
	}

	var match []string
	if pid1 == "systemd" {
		match = regex.systemd.FindStringSubmatch(strings.TrimSpace(string(cgroup)))
	} else if pid1 == "openrc" {
		match = regex.openrc.FindStringSubmatch(strings.TrimSpace(string(cgroup)))
	}

	if len(match) > 1 {
		return match[1]
	} else {
		return "-"
	}
}

func getInfo(pidInt int) (info *proc, err error) {
	pid := strconv.Itoa(pidInt)
	dirFd, err := unix.Open(filepath.Join(opts.proc, pid), unix.O_DIRECTORY|unix.O_PATH|unix.O_NOATIME, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFd)

	files := getDeleted(dirFd, pid)
	if len(files) == 0 {
		return
	}

	data, err := readFile(dirFd, filepath.Join(opts.proc, pid, "status"))
	if err != nil {
		return nil, err
	}
	status := string(data)

	uid, _ := strconv.Atoi(regex.ruid.FindStringSubmatch(status)[1])

	data, err = readFile(dirFd, filepath.Join(opts.proc, pid, "cmdline"))
	if err != nil {
		return nil, err
	}
	cmdline := strings.Split(string(data), "\x00")
	cmdline = cmdline[:len(cmdline)-1]

	command := ""
	if opts.verbose {
		// Use full path

		// cmdline is empty if zombie, but zombies have void proc.maps
		exe, err := readLink(dirFd, filepath.Join(opts.proc, pid, "exe"))
		if err != nil {
			exe = ""
		}
		exe = strings.TrimSuffix(exe, " (deleted)")

		if len(cmdline) > 0 && cmdline[0] != "/" && exe != "" && filepath.Base(cmdline[0]) == filepath.Base(exe) {
			command = exe + strings.Join(cmdline[1:], " ")
		} else {
			command = strings.Join(cmdline, " ")
		}
	} else {
		command = regex.name.FindStringSubmatch(status)[1]
		// The command may be truncated to 15 chars in /proc/<pid>/status
		// Also, kernel usermode helpers use "none"
		if len(cmdline) > 0 && cmdline[0] != "" && (len(command) == 15 || command == "none") {
			command = cmdline[0]
		}
		// If running a script, get the path of the script instead of the interpreter
		if len(cmdline) > 1 && regex.script.MatchString(filepath.Base(strings.Split(command, " ")[0])) {
			// Skip options and assume the first path is the script
			for _, arg := range cmdline[1:] {
				if isFile(arg) {
					command = arg
					break
				}
			}
		}
		if command == "/" {
			command = filepath.Base(command)
		} else {
			command = strings.Split(command, " ")[0]
		}
	}

	return &proc{
		command: quoteString(command),
		deleted: files,
		ppid:    regex.ppid.FindStringSubmatch(status)[1],
		uid:     uid,
		service: getService(dirFd, pid),
	}, nil
}

func printInfoAll(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var pids []int
	for _, entry := range entries {
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	sort.Sort(sort.IntSlice(pids))

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
						fmt.Println("ERROR: ", err)
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
		sort.Sort(sort.StringSlice(ss))
		for _, service := range ss {
			fmt.Println(service)
		}
	}

	return nil
}

func init() {
	logger = log.New(os.Stderr, "ERROR: ", 0)

	flag.StringVarP(&opts.proc, "proc", "P", "/proc", "proc directory")
	flag.BoolVarP(&opts.quote, "quote", "Q", false, "quote filenames")
	flag.CountVarP(&opts.short, "short", "s", "Create a short table not showing the deleted files. Given twice, show only processes which are associated with a system service. Given three times, list the associated system service names only.")
	flag.BoolVarP(&opts.verbose, "verbose", "v", false, "verbose output")
	flag.BoolVarP(&opts.version, "version", "V", false, "show version and exit")
	flag.Parse()

	if opts.version {
		fmt.Printf("%s\t%v\n", version, runtime.Version())
		os.Exit(0)
	}

	// NOTE: This is no longer needed on Go 1.19+ but runtime.Version() sucks
	var limits unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limits); err != nil && limits.Cur != limits.Max {
		limits.Cur = limits.Max
		if err = unix.Setrlimit(unix.RLIMIT_NOFILE, &limits); err != nil {
			logger.Print(err)
		}
	}
}

func main() {
	usernames = make(map[int]string)

	if data, err := os.ReadFile("/proc/1/comm"); err == nil {
		pid1 = strings.TrimSpace(string(data))
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "WARN: Run this program as root")
	}

	if err := printInfoAll(opts.proc); err != nil {
		logger.Fatal(err)
	}
	os.Exit(0)
}
