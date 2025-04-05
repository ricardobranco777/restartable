package main

import (
	"fmt"
	"io/fs"
	"os"
	"slices"
	"testing"
	"testing/fstest"
)

// Test using real /proc files
func TestRealProcPid(t *testing.T) {
	pid := os.Getpid()

	p, err := OpenProcPid(pid)
	if err != nil {
		t.Fatalf("OpenProcPid: %v", err)
	}
	defer p.Close()

	// Test PID method
	t.Run("PID", func(t *testing.T) {
		got := p.PID()
		if got != pid {
			t.Errorf("PID() = %d, want %d", got, pid)
		}
	})

	// Test ReadFile with real data and compare to os.ReadFile
	filesToTest := []string{"cmdline"}

	for _, file := range filesToTest {
		t.Run(file, func(t *testing.T) {
			// Custom ReadFile method
			data, err := p.ReadFile(file)
			if err != nil {
				t.Errorf("failed to read /proc/%d/%s: %v", pid, file, err)
			}

			// Real ReadFile method (os.ReadFile)
			realData, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, file))
			if err != nil {
				t.Errorf("failed to read /proc/%d/%s using os.ReadFile: %v", pid, file, err)
			}

			// Compare the data returned by both methods
			if string(data) != string(realData) {
				t.Errorf("ReadFile data mismatch for %s: expected %s, got %s", file, string(realData), string(data))
			}
		})
	}

	// Test ReadLink with real data and compare to os.ReadLink
	t.Run("exe", func(t *testing.T) {
		link, err := p.ReadLink("exe")
		if err != nil {
			t.Errorf("failed to read /proc/%d/exe: %v", pid, err)
		}

		realLink, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			t.Errorf("failed to read /proc/%d/exe using os.Readlink: %v", pid, err)
		}

		if link != realLink {
			t.Errorf("ReadLink data mismatch for exe: expected %s, got %s", realLink, link)
		}
	})
}

// Test getDeleted
func TestGetDeleted(t *testing.T) {
	tests := []struct {
		name     string
		maps     string
		expected []string
	}{
		{
			name:     "Test with deleted file",
			maps:     "00400000-0040b000 r-xp 00000000 08:01 1234 /path/to/executable (deleted)\n",
			expected: []string{"/path/to/executable"},
		},
		{
			name:     "Test with no deleted files",
			maps:     "00400000-0040b000 r-xp 00000000 08:01 1234 /path/to/executable\n",
			expected: []string{},
		},
		{
			name:     "Test with permission error",
			maps:     "",
			expected: []string{},
		},
		{
			name:     "Test with invalid mapping",
			maps:     "00400000-0040b000 r-xp 00000000 08:01 1234 /path/to/someotherfile (deleted)\n",
			expected: []string{"/path/to/someotherfile"},
		},
		{
			name: "Test with multiple deleted files",
			maps: "00400000-0040b000 r-xp 00000000 08:01 1234 /path/to/executable1 (deleted)\n" +
				"00410000-0041b000 r-xp 00000000 08:01 1234 /path/to/executable2 (deleted)\n",
			expected: []string{"/path/to/executable1", "/path/to/executable2"},
		},
		{
			name:     "Test with ignored files",
			maps:     "00400000-0040b000 r-xp 00000000 08:01 1234 /memfd:shm (deleted)\n",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := getDeleted(tt.maps)

			if !slices.Equal(files, tt.expected) {
				t.Errorf("expected files: %v, got: %v", tt.expected, files)
			}
		})
	}
}

// Test getService
func TestGetService(t *testing.T) {
	tests := []struct {
		name        string
		userService bool
		cgroup      string
		expected    string
	}{
		{
			name:        "Test Systemd User Slice",
			userService: true,
			cgroup:      "/user.slice/my.service",
			expected:    "my",
		},
		{
			name:        "Test Systemd System Slice",
			userService: false,
			cgroup:      "/system.slice/my.service",
			expected:    "my",
		},
		{
			name:        "Test OpenRC Service",
			userService: false,
			cgroup:      ":name=openrc:/myservice",
			expected:    "myservice",
		},
		{
			name:        "Test Invalid Cgroup Format",
			userService: false,
			cgroup:      "/invalid/format",
			expected:    "-",
		},
		{
			name:        "Test No Service in Cgroup",
			userService: false,
			cgroup:      "/system.slice/",
			expected:    "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := getService(tt.cgroup, tt.userService)

			if cmd != tt.expected {
				t.Errorf("expected command: %v, got: %v", tt.expected, cmd)
			}
		})
	}
}

// Test getCommand
func TestGetCommand(t *testing.T) {
	tests := []struct {
		name       string
		fullPath   bool
		statusName string
		cmdline    string
		exe        string
		expected   string
	}{
		{
			name:       "Test Full Path with Non-Zombie Process",
			fullPath:   true,
			statusName: "cmdline data",
			cmdline:    "cmd --flag=\"value\"",
			exe:        "/path/to/executable",
			expected:   "cmd --flag=\"value\"",
		},
		{
			name:       "Test Full Path with Zombie Process",
			fullPath:   true,
			statusName: "cmdline data",
			cmdline:    "cmd --flag=\"value\"",
			exe:        "",
			expected:   "cmd --flag=\"value\"",
		},
		{
			name:       "Test Short Path (cmdline exists)",
			fullPath:   false,
			statusName: "cmdline data",
			cmdline:    "cmdline",
			exe:        "",
			expected:   "cmdline",
		},
		{
			name:       "Test Command Truncated in Status",
			fullPath:   false,
			statusName: "cmdline data",
			cmdline:    "cmdline",
			exe:        "",
			expected:   "cmdline",
		},
		{
			name:       "Test Command 'none' for Kernel Helper",
			fullPath:   false,
			statusName: "none",
			cmdline:    "cmdline",
			exe:        "",
			expected:   "cmdline",
		},
		{
			name:       "Test Empty Command",
			fullPath:   false,
			statusName: "",
			cmdline:    "",
			exe:        "",
			expected:   "-",
		},
		{
			name:       "Test Non-Zombie Process with Matching Executable Path",
			fullPath:   true,
			statusName: "cmdline data",
			cmdline:    "cmd --flag=\"value\"",
			exe:        "/path/to/executable",
			expected:   "cmd --flag=\"value\"",
		},
		{
			name:       "Test Non-Zombie Process with Mismatched Executable Path",
			fullPath:   true,
			statusName: "cmdline data",
			cmdline:    "cmd --flag=\"value\"",
			exe:        "/different/path/to/executable",
			expected:   "cmd --flag=\"value\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := getCommand([]byte(tt.cmdline), tt.exe, tt.fullPath, tt.statusName)

			if cmd != tt.expected {
				t.Errorf("expected command: %v, got: %v", tt.expected, cmd)
			}
		})
	}
}

// Test parseStatusField
func TestParseStatusField(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		field    string
		expected string
	}{
		{"Valid Uid Field", "Name:\tbash\nUid:\t1000\t1001\n", "Uid", "1000\t1001"},
		{"Valid Name Field", "Name:\tbash\nUid:\t1000\n", "Name", "bash"},
		{"Missing Field", "Name:\tbash\nUid:\t1000\n", "Gid", ""},
		{"Empty Data", "", "Uid", ""},
		{"Malformed Data", "Name\nUid:\t1000\n", "Uid", "1000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			field := parseStatusField(tt.data, tt.field)
			if field != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, field)
			}
		})
	}
}

type MockProcPid struct {
	fs  fs.FS
	pid int
}

func (p *MockProcPid) ReadFile(path string) ([]byte, error) {
	return fs.ReadFile(p.fs, path)
}

// Workaround for https://github.com/golang/go/issues/49580
func (p *MockProcPid) ReadLink(path string) (string, error) {
	file, err := p.fs.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open path: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat path: %w", err)
	}

	if stat.Mode()&fs.ModeSymlink == 0 {
		return "", fmt.Errorf("not a symlink")
	}

	if mapFile, ok := p.fs.(fstest.MapFS)[path]; ok {
		return string(mapFile.Data), nil
	}
	return "", fmt.Errorf("symlink target not found")
}

func (p *MockProcPid) PID() int {
	return p.pid
}

func (p *MockProcPid) Close() error {
	return nil
}

func mockProcFS(pid int, files map[string]string, symlinks map[string]string) *MockProcPid {
	mockFS := fstest.MapFS{}

	for path, content := range files {
		mockFS[path] = &fstest.MapFile{Data: []byte(content)}
	}

	for path, target := range symlinks {
		mockFS[path] = &fstest.MapFile{
			Mode: fs.ModeSymlink,
			Data: []byte(target),
		}
	}

	return &MockProcPid{fs: mockFS, pid: pid}
}

// Test getProcessInfo
func TestGetProcessInfo(t *testing.T) {
	procFS := mockProcFS(1234, map[string]string{
		"cgroup":  "/proc/777/cgroup:0::/system.slice/sshd.service\n",
		"cmdline": "/bin/bash\x00--version\x00",
		"maps":    "00400000-00452000 r-xp 00000000 fd:00 12345 /bin/bash (deleted)\n",
		"status":  "Name:\tbash\nPPid:\t1\nUid:\t1000\n",
	}, nil)

	info, err := getProcessInfo(procFS, true, false)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if info.Pid != 1234 {
		t.Errorf("Expected PID 1234, got %d", info.Pid)
	}
	if info.Ppid != 1 {
		t.Errorf("Expected PPID 1, got %d", info.Ppid)
	}
	if info.Uid != 1000 {
		t.Errorf("Expected UID 1000, got %d", info.Uid)
	}
	if info.Command != "/bin/bash --version" {
		t.Errorf("Expected command '/bin/bash --version', got '%s'", info.Command)
	}
	if len(info.Deleted) != 1 || info.Deleted[0] != "/bin/bash" {
		t.Errorf("Expected Deleted ['/bin/bash'], got %v", info.Deleted)
	}
}

// Test getUser
func TestGetUser(t *testing.T) {
	if getUser(0) != "root" {
		t.Errorf("Expected 'root', got '%s'", getUser(0))
	}
	if getUser(99999) != "-" {
		t.Errorf("Expected '-', got '%s'", getUser(99999))
	}
}

// Test quoteString
func TestQuoteString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Empty String", "", ""},
		{"No Special Characters", "hello", "hello"},
		{"String With Spaces", "hello world", "hello world"},
		{"String With Special Characters", "hello\tworld", "hello\\tworld"},
		{"String With Quotes", `cmd --flag="value"`, `cmd --flag=\"value\"`},
		{"String With Newline", "hello\nworld", "hello\\nworld"},
		{"String With Mixed Characters", "cmd --flag=\"value\"\nnext line", `cmd --flag=\"value\"\nnext line`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := quoteString(tt.input)
			if result != tt.expected {
				t.Errorf("For input '%s': expected '%s', got '%s'", tt.input, tt.expected, result)
			}
		})
	}
}
