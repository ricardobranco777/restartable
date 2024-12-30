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

// ProcPidFS defines an interface for /proc/<pid> filesystem access
type ProcPidFS interface {
	ReadFile(path string) ([]byte, error)
	ReadLink(path string) (string, error)
	Close() error
}

// RealProcPidFS implements ProcPidFS for real /proc/<pid> filesystem
type RealProcPidFS struct {
	dirFd int
	pid   int
}

var (
	regexDeleted = regexp.MustCompile(`/.* \(deleted\)$`)
	regexIgnored = regexp.MustCompile(`[^/]*/(dev|memfd:|run| )`)
	regexExecMap = regexp.MustCompile(`^[0-9a-f]+-[0-9a-f]+ r(w|-)x`)
	regexName    = regexp.MustCompile(`(?m)^Name:\t(.*)$`)
	regexPpid    = regexp.MustCompile(`(?m)^PPid:\t(.*)$`)
	regexRuid    = regexp.MustCompile(`(?m)^Uid:\t([0-9]+)\t`)
)

// OpenProc opens a /proc/<pid> directory and returns a ProcPidFS instance
func OpenProcPid(pid int) (*RealProcPidFS, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid))
	dirFd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_PATH, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: fmt.Sprintf("/proc/%d", pid), Err: err}
	}
	return &RealProcPidFS{dirFd: dirFd, pid: pid}, nil
}

// Close releases the file descriptor
func (p *RealProcPidFS) Close() error {
	err := unix.Close(p.dirFd)
	if err != nil {
		return &os.PathError{Op: "close", Path: "/proc", Err: err}
	}
	return nil
}

// ReadFile reads a file inside /proc/<pid>
func (p *RealProcPidFS) ReadFile(path string) ([]byte, error) {
	fd, err := unix.Openat(p.dirFd, path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: fmt.Sprintf("/proc/%d/%s", p.pid, path), Err: err}
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
				err = &os.PathError{Op: "read", Path: fmt.Sprintf("/proc/%d/%s", p.pid, path), Err: err}
			}
			return data, err
		}
	}
}

// ReadLink reads a symbolic link inside /proc/<pid>
func (p *RealProcPidFS) ReadLink(path string) (string, error) {
	for size := unix.PathMax; ; size *= 2 {
		data := make([]byte, unix.PathMax)
		if n, err := unix.Readlinkat(p.dirFd, path, data); err != nil {
			return "", &os.PathError{Op: "readlinkat", Path: fmt.Sprintf("/proc/%d/%s", p.pid, path), Err: err}
		} else if n != size {
			return string(data[:n]), nil
		}
	}
}

// ProcessInfo holds process information
type ProcessInfo struct {
	Command string
	Deleted []string
	Ppid    string
	Uid     int
	Service string
}

// GetDeleted retrieves deleted file mappings for a process
func GetDeleted(fs ProcPidFS) ([]string, error) {
	maps, err := fs.ReadFile("maps")
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
			files = append(files, QuoteString(strings.TrimSuffix(file, " (deleted)")))
		}
	}
	sort.Strings(files)

	return files, nil
}

// GetService retrieves the service name
func GetService(fs ProcPidFS, userService bool) string {
	data, err := fs.ReadFile("cgroup")
	if err != nil {
		return "-"
	}
	cgroup := strings.TrimSpace(string(data))

	if strings.HasSuffix(cgroup, ".service") {
		// Systemd
		if userService && strings.Contains(cgroup, "/user.slice/") || !userService && strings.Contains(cgroup, "/system.slice/") {
			return strings.TrimSuffix(cgroup[strings.LastIndex(cgroup, "/")+1:], ".service")
		}
	} else if strings.Contains(cgroup, ":name=openrc:/") {
		// OpenRC
		return cgroup[strings.LastIndex(cgroup, "/")+1:]
	}
	return "-"
}

// GetCommand retrieves the command
func GetCommand(fs ProcPidFS, fullPath bool, statusName string) (string, error) {
	data, err := fs.ReadFile("cmdline")
	if err != nil {
		return "", err
	}

	cmdline := []string{}
	if bytes.HasSuffix(data, []byte("\x00")) {
		cmdline = strings.Split(string(data), "\x00")
		cmdline = cmdline[:len(cmdline)-1]
	} else {
		cmdline = append(cmdline, string(data))
	}

	var command string
	if fullPath {
		// Use full path

		// cmdline is empty if zombie, but zombies have void maps
		exe, err := fs.ReadLink("exe")
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
		command = statusName
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
	return command, nil
}

// GetProcessInfo gets process information
func GetProcessInfo(fs ProcPidFS, fullPath bool, userService bool) (*ProcessInfo, error) {
	deleted, err := GetDeleted(fs)
	if err != nil {
		return nil, err
	} else if len(deleted) == 0 {
		return nil, nil
	}

	data, err := fs.ReadFile("status")
	if err != nil {
		return nil, err
	}
	status := string(data)

	command, err := GetCommand(fs, fullPath, regexName.FindStringSubmatch(status)[1])
	if err != nil {
		return nil, err
	}

	uid, _ := strconv.Atoi(regexRuid.FindStringSubmatch(status)[1])

	return &ProcessInfo{
		Command: QuoteString(command),
		Deleted: deleted,
		Ppid:    regexPpid.FindStringSubmatch(status)[1],
		Uid:     uid,
		Service: GetService(fs, userService),
	}, nil
}

// Quote special characters
func QuoteString(str string) string {
	if len(str) > 0 {
		str = strconv.Quote(str)
		return str[1 : len(str)-1]
	}
	return ""
}

// Get username from UID
func GetUser(uid int) string {
	if info, err := user.LookupId(strconv.Itoa(uid)); err != nil {
		return "-"
	} else {
		return info.Username
	}
}

type ProcessLister interface {
	ListProcesses() ([]int, error)
}

type DefaultProcessLister struct{}

func (d DefaultProcessLister) ListProcesses() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var pids []int
	for _, entry := range entries {
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

type Opts struct {
	short   int
	user    bool
	verbose bool
	version bool
}

func RunProcessMonitor(lister ProcessLister, opts Opts, openProc func(int) (ProcPidFS, error)) {
	pids, err := lister.ListProcesses()
	if err != nil {
		log.Fatal(err)
	}
	if opts.short < 3 {
		fmt.Printf("%s\t%s\t%s\t%-20s\t%20s\t%s\n", "PID", "PPID", "UID", "User", "Service", "Command")
	}

	channel := make(map[int]chan *ProcessInfo, len(pids))
	for _, pid := range pids {
		channel[pid] = make(chan *ProcessInfo)
	}

	go func() {
		for _, pid := range pids {
			go func(pid int) {
				fs, err := openProc(pid)
				if err != nil {
					if !errors.Is(err, unix.ENOENT) {
						log.Print(err)
					}
					return
				}
				defer fs.Close()
				info, err := GetProcessInfo(fs, opts.verbose, opts.user)
				if err != nil {
					log.Print(err)
				}
				channel[pid] <- info
			}(pid)
		}
	}()

	services := make(map[string]bool)
	for _, pid := range pids {
		proc := <-channel[pid]
		if proc == nil {
			continue
		}
		close(channel[pid])
		if opts.short < 3 {
			fmt.Printf("%d\t%s\t%d\t%-20s\t%20s\t%s\n", pid, proc.Ppid, proc.Uid, GetUser(proc.Uid), proc.Service, proc.Command)
		} else if proc.Service != "-" {
			services[proc.Service] = true
		}
		if opts.short == 0 {
			for _, deleted := range proc.Deleted {
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

func main() {
	log.SetPrefix("ERROR: ")
	log.SetFlags(0)

	var opts Opts

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

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "WARN: Run this program as root")
	}

	RunProcessMonitor(DefaultProcessLister{}, opts, func(pid int) (ProcPidFS, error) {
		return OpenProcPid(pid)
	})
}
