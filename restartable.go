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

const version string = "2.3.1"

// ProcFS defines an interface for /proc/ filesystem access
type ProcFS interface {
	ReadFile(path string) ([]byte, error)
	ReadLink(path string) (string, error)
	Close() error
}

// ProcPidFS defines an interface for /proc/<pid> filesystem access
type ProcPidFS interface {
	ProcFS
	PID() int
}

// RealProcPidFS implements ProcPidFS for real /proc/<pid> filesystem
type RealProcPidFS struct {
	ProcPidFS
	dirFd int
	pid   int
}

// OpenProc opens a /proc/<pid> directory and returns a ProcPidFS instance
func OpenProcPid(procDir string, pid int) (*RealProcPidFS, error) {
	if procDir == "" {
		procDir = "/proc"
	}
	path := filepath.Join(procDir, strconv.Itoa(pid))
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

	data := make([]byte, 0, 8192)
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

// PID returns the process ID
func (p *RealProcPidFS) PID() int {
	return p.pid
}

var (
	regexDeleted = regexp.MustCompile(`/.* \(deleted\)$`)
	regexIgnored = regexp.MustCompile(`^/(dev|memfd:|run| )`)
	regexExecMap = regexp.MustCompile(`^[0-9a-f]+-[0-9a-f]+ r(w|-)x`)
)

// getDeleted retrieves deleted file mappings for a process
func getDeleted(maps string) []string {
	var files []string
	for _, line := range strings.Split(maps, "\n") {
		file := regexDeleted.FindString(line)
		if file != "" && regexExecMap.MatchString(line) && !regexIgnored.MatchString(file) {
			files = append(files, quoteString(strings.TrimSuffix(file, " (deleted)")))
		}
	}
	sort.Strings(files)

	return files
}

// getService retrieves the service name
func getService(cgroup string, userService bool) string {
	cgroup = strings.TrimSpace(cgroup)

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

// getCommand retrieves the command
func getCommand(cmdline []string, exe string, fullPath bool) string {
	var command string

	if fullPath {
		exe = strings.TrimSuffix(exe, " (deleted)")
		if exe != "" && !strings.HasPrefix(cmdline[0], "/") && filepath.Base(cmdline[0]) == filepath.Base(exe) {
			cmdline[0] = exe
		}
		command = strings.Join(cmdline, " ")
	} else if cmdline[0] != "" {
		command = filepath.Base(cmdline[0])
	}
	if command == "" {
		command = "-"
	}
	return command
}

// parseStatusField extracts a field value from the status file given a key
func parseStatusField(data, key string) string {
	if key != "Name" {
		key = "\n" + key
	}
	key = key + ":\t"

	start := strings.Index(data, key)
	if start == -1 {
		return ""
	}

	start += len(key)
	end := strings.IndexByte(data[start:], '\n')
	if end == -1 {
		end = len(data[start:])
	}

	return data[start : start+end]
}

// ProcessInfo holds process information
type ProcessInfo struct {
	Command string
	Deleted []string
	Pid     int
	Ppid    int
	Uid     int
	Service string
}

// getProcessInfo gets process information
func getProcessInfo(fs ProcPidFS, fullPath bool, userService bool) (*ProcessInfo, error) {
	maps, err := fs.ReadFile("maps")
	if err != nil {
		if errors.Is(err, unix.EACCES) {
			err = nil
		}
		return nil, err
	}
	deleted := getDeleted(string(maps))
	if len(deleted) == 0 {
		return nil, nil
	}

	data, err := fs.ReadFile("status")
	if err != nil {
		return nil, err
	}
	status := string(data)

	ppid, _ := strconv.Atoi(parseStatusField(status, "PPid"))
	uid, _ := strconv.Atoi(strings.Fields(parseStatusField(status, "Uid"))[0])

	var cmdline []string
	if data, err = fs.ReadFile("cmdline"); err != nil {
		return nil, err
	} else {
		data = bytes.TrimSuffix(data, []byte("\x00"))
		cmdline = strings.Split(string(data), "\x00")
	}
	exe, _ := fs.ReadLink("exe")
	command := getCommand(cmdline, exe, fullPath)

	cgroup, err := fs.ReadFile("cgroup")
	if err != nil {
		cgroup = []byte("")
	}
	service := getService(string(cgroup), userService)

	return &ProcessInfo{
		Command: quoteString(command),
		Deleted: deleted,
		Pid:     fs.PID(),
		Ppid:    ppid,
		Uid:     uid,
		Service: service,
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

func runProcessMonitor(lister ProcessLister, opts Opts, openProc func(int) (ProcPidFS, error)) {
	pids, err := lister.ListProcesses()
	if err != nil {
		log.Fatal(err)
	}
	if opts.short < 3 {
		fmt.Printf("%s\t%s\t%s\t%-20s\t%20s\t%s\n", "PID", "PPID", "UID", "User", "Service", "Command")
	}

	channel := make(map[int]chan *ProcessInfo, len(pids))
	for _, pid := range pids {
		channel[pid] = make(chan *ProcessInfo, 1)
	}

	for _, pid := range pids {
		go func(pid int) {
			defer close(channel[pid])
			fs, err := openProc(pid)
			if err != nil {
				if !errors.Is(err, unix.ENOENT) {
					log.Print(err)
				}
				return
			}
			defer fs.Close()
			info, err := getProcessInfo(fs, opts.verbose, opts.user)
			if err != nil {
				log.Print(err)
			}
			channel[pid] <- info
		}(pid)
	}

	services := make(map[string]bool)
	for _, pid := range pids {
		proc := <-channel[pid]
		if proc == nil {
			continue
		}
		if opts.short < 2 || proc.Service != "-" {
			fmt.Printf("%d\t%d\t%d\t%-20s\t%20s\t%s\n", proc.Pid, proc.Ppid, proc.Uid, getUser(proc.Uid), proc.Service, proc.Command)
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

	runProcessMonitor(DefaultProcessLister{}, opts, func(pid int) (ProcPidFS, error) {
		return OpenProcPid("/proc", pid)
	})
}
