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
	"sync"
)

import flag "github.com/spf13/pflag"

const version string = "2.3.0"

type Info struct {
	command string
	deleted []string
	pid     int
	ppid    string
	uid     int
	service string
}

// ProcPidFS abstracts access to a /proc/<pid> directory
type ProcPidFS struct {
	dirFd int
	pid   int
}

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

// OpenProc opens a /proc/<pid> directory and returns a ProcPidFS instance
func OpenProcPid(pid int) (*ProcPidFS, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid))
	dirFd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_PATH, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return &ProcPidFS{dirFd: dirFd, pid: pid}, nil
}

// Close releases the file descriptor
func (p *ProcPidFS) Close() error {
	err := unix.Close(p.dirFd)
	if err != nil {
		return &os.PathError{Op: "close", Path: "/proc", Err: err}
	}
	return nil
}

// ReadFile reads a file inside /proc/<pid>
func (p *ProcPidFS) ReadFile(path string) ([]byte, error) {
	fd, err := unix.Openat(p.dirFd, path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
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

// ReadLink reads a symbolic link inside /proc/<pid>
func (p *ProcPidFS) ReadLink(path string) (string, error) {
	for size := unix.PathMax; ; size *= 2 {
		data := make([]byte, unix.PathMax)
		if n, err := unix.Readlinkat(p.dirFd, path, data); err != nil {
			return "", &os.PathError{Op: "readlinkat", Path: path, Err: err}
		} else if n != size {
			return string(data[:n]), nil
		}
	}
}

// GetDeleted retrieves deleted file mappings for a process
func (p *ProcPidFS) GetDeleted() ([]string, error) {
	maps, err := p.ReadFile("maps")
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

// GetService retrieves the service name
func (p *ProcPidFS) GetService(pid1 string, isUser bool) string {
	cgroup, err := p.ReadFile("cgroup")
	if err != nil {
		return "-"
	}

	var match []string
	if pid1 == "systemd" {
		if isUser {
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

func getInfo(pid int) (*Info, error) {
	p, err := OpenProcPid(pid)
	if err != nil {
		return nil, err
	}
	defer p.Close()

	deleted, err := p.GetDeleted()
	if err != nil {
		return nil, err
	} else if len(deleted) == 0 {
		return nil, nil
	}

	data, err := p.ReadFile("status")
	if err != nil {
		return nil, err
	}
	status := string(data)

	uid, _ := strconv.Atoi(regexRuid.FindStringSubmatch(status)[1])

	data, err = p.ReadFile("cmdline")
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

		// cmdline is empty if zombie, but zombies have void maps
		exe, err := p.ReadLink("exe")
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

	return &Info{
		command: quoteString(command),
		deleted: deleted,
		pid:     pid,
		ppid:    regexPpid.FindStringSubmatch(status)[1],
		uid:     uid,
		service: p.GetService(pid1, opts.user),
	}, nil
}

// Quote special characters
func quoteString(str string) string {
	if len(str) > 0 {
		str = strconv.Quote(str)
		return str[1 : len(str)-1]
	}
	return ""
}

// Get username from UID
func getUser(uid int) string {
	if info, err := user.LookupId(strconv.Itoa(uid)); err != nil {
		return "-"
	} else {
		return info.Username
	}
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

	infoCh := make(chan *Info)
	var wg sync.WaitGroup

	for _, pid := range pids {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			if info, err := getInfo(pid); err != nil {
				log.Print(err)
			} else if info != nil {
				infoCh <- info
			}
		}(pid)
	}

	go func() {
		defer close(infoCh)
		wg.Wait()
	}()

	for proc := range infoCh {
		if opts.short < 3 {
			fmt.Printf("%d\t%s\t%d\t%-20s\t%20s\t%s\n", proc.pid, proc.ppid, proc.uid, getUser(proc.uid), proc.service, proc.command)
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
