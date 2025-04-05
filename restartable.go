//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io/fs"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unsafe"
)

import flag "github.com/spf13/pflag"

const version = "2.3.9"

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

// ProcPid implements ProcPidFS for real /proc/<pid> filesystem
type ProcPid struct {
	ProcPidFS
	*os.Root
	fd  int
	pid int
}

// ProcPid satisfies ProcPidFS interface
var _ ProcPidFS = &ProcPid{}

// getFD returns the fd from *os.Root
func (p *ProcPid) getFD() int {
	if p.fd < 0 {
		// Reflect into *os.Root -> .root -> .fd
		rootVal := reflect.ValueOf(p.Root).Elem().FieldByName("root")
		rootPtr := reflect.NewAt(rootVal.Type(), unsafe.Pointer(rootVal.UnsafeAddr())).Elem()

		fdField := rootPtr.Elem().FieldByName("fd")
		fdVal := reflect.NewAt(fdField.Type(), unsafe.Pointer(fdField.UnsafeAddr())).Elem()

		p.fd = int(fdVal.Int())
	}
	return p.fd
}

// OpenProc opens a /proc/<pid> directory and returns a ProcPidFS instance
func OpenProcPid(pid int) (*ProcPid, error) {
	root, err := os.OpenRoot(filepath.Join("/proc", strconv.Itoa(pid)))
	if err != nil {
		return nil, err
	}
	return &ProcPid{Root: root, fd: -1, pid: pid}, nil
}

// Close releases the file descriptor
func (p *ProcPid) Close() error {
	return p.Root.Close()
}

// ReadFile reads a file inside /proc/<pid>
func (p *ProcPid) ReadFile(path string) ([]byte, error) {
	rfs, ok := p.Root.FS().(fs.ReadFileFS)
	if !ok {
		panic("ProcPid.Root does not implement ReadFileFS")
	}
	return rfs.ReadFile(path)
}

// ReadLink reads a symbolic link inside /proc/<pid>
func (p *ProcPid) ReadLink(path string) (string, error) {
	data := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(p.getFD(), path, data)
	if err != nil {
		return "", &os.PathError{Op: "readlinkat", Path: fmt.Sprintf("/proc/%d/%s", p.pid, path), Err: err}
	}
	return string(data[:n]), nil
}

// PID returns the process ID
func (p *ProcPid) PID() int {
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
func getCommand(data []byte, exe string, fullPath bool, statusName string) string {
	data = bytes.TrimSuffix(data, []byte("\x00"))
	cmdline := strings.Split(string(data), "\x00")

	var command string
	if fullPath {
		// Use full path

		// cmdline is empty if zombie, but zombies have void maps
		exe = strings.TrimSuffix(exe, " (deleted)")
		if exe != "" && !strings.HasPrefix(cmdline[0], "/") && filepath.Base(cmdline[0]) == filepath.Base(exe) {
			cmdline[0] = exe
		}
		command = strings.Join(cmdline, " ")
	} else {
		command = statusName
		// The command may be truncated to 15 chars in /proc/<pid>/status
		// Also, kernel usermode helpers use "none"
		if (len(command) == 15 || command == "none") && len(cmdline) > 0 && cmdline[0] != "" {
			command = cmdline[0]
		}
		if strings.HasPrefix(command, "/") {
			command = filepath.Base(command)
		} else {
			command = strings.Split(command, " ")[0]
		}
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
func getProcessInfo(p ProcPidFS, fullPath bool, userService bool) (*ProcessInfo, error) {
	maps, err := p.ReadFile("maps")
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

	data, err := p.ReadFile("status")
	if err != nil {
		return nil, err
	}
	status := string(data)

	ppid, _ := strconv.Atoi(parseStatusField(status, "PPid"))
	uid, _ := strconv.Atoi(strings.Fields(parseStatusField(status, "Uid"))[0])

	cmdline, err := p.ReadFile("cmdline")
	if err != nil {
		return nil, err
	}
	exe, err := p.ReadLink("exe")
	if err != nil {
		exe = ""
	}
	command := getCommand(cmdline, exe, fullPath, parseStatusField(status, "Name"))

	cgroup, err := p.ReadFile("cgroup")
	if err != nil {
		cgroup = []byte("")
	}
	service := getService(string(cgroup), userService)

	return &ProcessInfo{
		Command: quoteString(command),
		Deleted: deleted,
		Pid:     p.PID(),
		Ppid:    ppid,
		Uid:     uid,
		Service: service,
	}, nil
}

// Quote special characters
func quoteString(str string) string {
	quoted := strconv.AppendQuote(nil, str)
	// Strip the surrounding double quotes
	return string(quoted[1 : len(quoted)-1])
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

	if len(pids) == 0 {
		return
	}

	channel := make(map[int]chan *ProcessInfo, len(pids))
	for _, pid := range pids {
		channel[pid] = make(chan *ProcessInfo, 1)
	}

	for _, pid := range pids {
		go func(pid int) {
			defer close(channel[pid])
			p, err := openProc(pid)
			if err != nil {
				if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
					log.Print(err)
				}
				return
			}
			defer p.Close()
			info, err := getProcessInfo(p, opts.verbose, opts.user)
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
		if proc.Service != "-" {
			services[proc.Service] = true
		}
		if opts.short < 3 && proc.Service != "-" || opts.short < 2 {
			fmt.Printf("%d\t%d\t%d\t%-20s\t%20s\t%s\n", proc.Pid, proc.Ppid, proc.Uid, getUser(proc.Uid), proc.Service, proc.Command)
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
		return OpenProcPid(pid)
	})
}
