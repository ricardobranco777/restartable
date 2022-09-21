package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
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

var usernames map[int]string

var opts struct {
	proc    string
	short   int
	verbose bool
}

var pid1 string

func isFile(path string) bool {
	info, err := os.Stat(path)
	if err == nil {
		return info.Mode().IsRegular()
	}
	return false
}

func getUser(uid int) (username string) {
	if _, ok := usernames[uid]; ok {
		username = usernames[uid]
	} else {
		info, err := user.LookupId(strconv.Itoa(uid))
		if err != nil {
			username = "-"
		} else {
			username = info.Username
		}
		usernames[uid] = username
	}
	return username
}

func getDeleted(pid string) (files []string) {
	maps, err := os.ReadFile(filepath.Join("/proc/", pid, "maps"))
	if err != nil {
		return
	}

	deleted := regexp.MustCompile(`/.* \(deleted\)$`)
	ignored := regexp.MustCompile(`[^/]*/(dev|memfd:|run| )`)
	execmap := regexp.MustCompile(`^[0-9a-f]+-[0-9a-f]+ r(w|-)x`)

	for _, str := range strings.Split(string(maps), "\n") {
		file := deleted.FindString(str)
		if file != "" && execmap.MatchString(str) && !ignored.MatchString(str) {
			files = append(files, strings.TrimSuffix(file, " (deleted)"))
		}
	}

	sort.Sort(sort.StringSlice(files))

	return
}

func getService(pid string) (service string) {
	cgroup, err := os.ReadFile(filepath.Join("/proc/", pid, "cgroup"))
	if err != nil {
		return "-"
	}

	var match []string
	if pid1 == "systemd" {
		regex := regexp.MustCompile(`\d+:(?:name=systemd)?:/system\.slice/(?:.*/)?(.*)\.service$`)
		match = regex.FindStringSubmatch(strings.TrimSpace(string(cgroup)))
	} else if pid1 == "openrc" {
		regex := regexp.MustCompile(`\d+:name=openrc:/(.*)$`)
		match = regex.FindStringSubmatch(strings.TrimSpace(string(cgroup)))
	}

	if len(match) > 1 {
		return match[1]
	} else {
		return "-"
	}
}

func getInfo(pidInt int) (info *proc, err error) {
	pid := strconv.Itoa(pidInt)

	files := getDeleted(pid)
	if len(files) == 0 {
		return
	}

	data, err := os.ReadFile(filepath.Join("/proc/", pid, "status"))
	if err != nil {
		return nil, err
	}
	status := string(data)

	name := regexp.MustCompile(`(?m)^Name:\t(.*)$`)
	ppid := regexp.MustCompile(`(?m)^PPid:\t(.*)$`)
	ruid := regexp.MustCompile(`(?m)^Uid:\t([0-9]+)\t`)
	uid, _ := strconv.Atoi(ruid.FindStringSubmatch(status)[1])

	data, err = os.ReadFile(filepath.Join("/proc/", pid, "cmdline"))
	if err != nil {
		return nil, err
	}
	cmdline := strings.Split(string(data), "\x00")
	cmdline = cmdline[:len(cmdline)-1]

	command := ""
	if opts.verbose {
		// Use full path

		// cmdline is empty if zombie, but zombies have void proc.maps
		exe, err := os.Readlink(filepath.Join("/proc", pid, "exe"))
		if err != nil {
			exe = ""
		}
		exe = strings.TrimSuffix(exe, " (deleted)")

		if len(cmdline) > 0 && !strings.HasPrefix(cmdline[0], "/") && exe != "" && filepath.Base(cmdline[0]) == filepath.Base(exe) {
			command = exe + strings.Join(cmdline[1:], " ")
		} else {
			command = strings.Join(cmdline, " ")
		}
	} else {
		command = name.FindStringSubmatch(status)[1]
		// The command may be truncated to 15 chars in /proc/<pid>/status
		// Also, kernel usermode helpers use "none"
		if cmdline[0] != "" && (len(command) == 15 || command == "none") {
			command = cmdline[0]
		}
		// If running a script, get the path of the script instead of the interpreter
		script_regex := regexp.MustCompile(`((perl|python|(ruby\.)?ruby)(\d?(\.\d)?)|(a|ba|c|da|fi|k|pdk|tc|z)?sh)$`)
		if script_regex.MatchString(filepath.Base(strings.Split(command, " ")[0])) {
			// Skip options and assume the first path is the script
			for _, arg := range cmdline[1:] {
				if isFile(arg) {
					command = arg
					break
				}
			}
		}
		if strings.HasPrefix(command, "/") {
			command = filepath.Base(command)
		} else {
			command = strings.Split(command, " ")[0]
		}
	}

	return &proc{
		command: command,
		deleted: files,
		ppid:    ppid.FindStringSubmatch(status)[1],
		uid:     uid,
		service: getService(pid),
	}, nil
}

func printInfoAll(proc string) error {
	entries, err := os.ReadDir(proc)
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
	for _, pid := range pids {
		proc, err := getInfo(pid)
		if proc == nil || err != nil {
			continue
		}
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
	flag.BoolVarP(&opts.verbose, "verbose", "v", false, "verbose output")
	flag.StringVarP(&opts.proc, "proc", "P", "/proc", "proc directory")
	flag.CountVarP(&opts.short, "short", "s", "Create a short table not showing the deleted files. Given twice, show only processes which are associated with a system service. Given three times, list the associated system service names only.")
	flag.Parse()
}

func main() {
	usernames = make(map[int]string)

	data, err := os.ReadFile("/proc/1/comm")
	if err == nil {
		pid1 = strings.TrimSpace(string(data))
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "WARN: Run this program as root")
	}

	err = printInfoAll(opts.proc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
