package main

import (
	"fmt"
	"io/fs"
	"slices"
	"testing"
	"testing/fstest"
)

type MockProcPidFS struct {
	fs  fs.FS
	pid int
}

func (p *MockProcPidFS) ReadFile(path string) ([]byte, error) {
	return fs.ReadFile(p.fs, path)
}

// Workaround for https://github.com/golang/go/issues/49580
func (p *MockProcPidFS) ReadLink(path string) (string, error) {
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

func (p *MockProcPidFS) PID() int {
	return p.pid
}

func (p *MockProcPidFS) Close() error {
	return nil
}

func mockProcFS(pid int, files map[string]string, symlinks map[string]string) *MockProcPidFS {
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

	return &MockProcPidFS{fs: mockFS, pid: pid}
}

// Test getDeleted
func TestGetDeleted(t *testing.T) {
	tests := []struct {
		name        string
		files       map[string]string
		expectedCmd []string
		expectedErr bool
	}{
		{
			name: "Test with deleted file",
			files: map[string]string{
				"maps": "00400000-0040b000 r-xp 00000000 08:01 1234 /path/to/executable (deleted)\n",
			},
			expectedCmd: []string{"/path/to/executable"},
			expectedErr: false,
		},
		{
			name: "Test with no deleted files",
			files: map[string]string{
				"maps": "00400000-0040b000 r-xp 00000000 08:01 1234 /path/to/executable\n",
			},
			expectedCmd: []string{},
			expectedErr: false,
		},
		{
			name: "Test with permission error",
			files: map[string]string{
				"maps": "",
			},
			expectedCmd: []string{},
			expectedErr: false, // EACCES is handled, so no error should propagate
		},
		{
			name:        "Test with missing maps file",
			files:       map[string]string{},
			expectedCmd: []string{},
			expectedErr: true, // Should return error as "maps" is missing
		},
		{
			name: "Test with invalid mapping",
			files: map[string]string{
				"maps": "00400000-0040b000 r-xp 00000000 08:01 1234 /path/to/someotherfile (deleted)\n",
			},
			expectedCmd: []string{"/path/to/someotherfile"},
			expectedErr: false,
		},
		{
			name: "Test with multiple deleted files",
			files: map[string]string{
				"maps": "00400000-0040b000 r-xp 00000000 08:01 1234 /path/to/executable1 (deleted)\n" +
					"00410000-0041b000 r-xp 00000000 08:01 1234 /path/to/executable2 (deleted)\n",
			},
			expectedCmd: []string{"/path/to/executable1", "/path/to/executable2"},
			expectedErr: false,
		},
		{
			name: "Test with ignored files",
			files: map[string]string{
				"maps": "00400000-0040b000 r-xp 00000000 08:01 1234 /memfd:shm (deleted)\n",
			},
			expectedCmd: []string{},
			expectedErr: false, // Should not include library.so as it is ignored
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFS := mockProcFS(1234, tt.files, nil)
			files, err := getDeleted(mockFS)

			if tt.expectedErr && err == nil {
				t.Errorf("expected error but got none")
			} else if !tt.expectedErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check if the expected files match the actual result
			if !slices.Equal(files, tt.expectedCmd) {
				t.Errorf("expected files: %v, got: %v", tt.expectedCmd, files)
			}
		})
	}
}

// Test getService
func TestGetService(t *testing.T) {
	tests := []struct {
		name        string
		userService bool
		files       map[string]string
		expectedCmd string
		expectedErr bool
	}{
		{
			name:        "Test Systemd User Slice",
			userService: true,
			files:       map[string]string{"cgroup": "/user.slice/my.service"},
			expectedCmd: "my",
			expectedErr: false,
		},
		{
			name:        "Test Systemd System Slice",
			userService: false,
			files:       map[string]string{"cgroup": "/system.slice/my.service"},
			expectedCmd: "my",
			expectedErr: false,
		},
		{
			name:        "Test OpenRC Service",
			userService: false,
			files:       map[string]string{"cgroup": ":name=openrc:/myservice"},
			expectedCmd: "myservice",
			expectedErr: false,
		},
		{
			name:        "Test Missing Cgroup File",
			userService: true,
			files:       map[string]string{},
			expectedCmd: "-",
			expectedErr: true,
		},
		{
			name:        "Test Invalid Cgroup Format",
			userService: false,
			files:       map[string]string{"cgroup": "/invalid/format"},
			expectedCmd: "-",
			expectedErr: false,
		},
		{
			name:        "Test No Service in Cgroup",
			userService: false,
			files:       map[string]string{"cgroup": "/system.slice/"},
			expectedCmd: "-",
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFS := mockProcFS(1234, tt.files, nil)
			cmd := getService(mockFS, tt.userService)

			if tt.expectedErr && cmd != "-" {
				t.Errorf("expected error or '-' but got: %v", cmd)
			}
			if !tt.expectedErr && cmd != tt.expectedCmd {
				t.Errorf("expected command: %v, got: %v", tt.expectedCmd, cmd)
			}
		})
	}
}

// Test getCommand
func TestGetCommand(t *testing.T) {
	tests := []struct {
		name        string
		fullPath    bool
		statusName  string
		files       map[string]string
		symlinks    map[string]string
		expectedCmd string
		expectedErr bool
	}{
		{
			name:        "Test Full Path with Non-Zombie Process",
			fullPath:    true,
			statusName:  "cmdline data",
			files:       map[string]string{"cmdline": "cmd --flag=\"value\""},
			symlinks:    map[string]string{"exe": "/path/to/executable"},
			expectedCmd: "cmd --flag=\"value\"",
			expectedErr: false,
		},
		{
			name:        "Test Full Path with Zombie Process",
			fullPath:    true,
			statusName:  "cmdline data",
			files:       map[string]string{"cmdline": "cmd --flag=\"value\""},
			symlinks:    map[string]string{"exe": ""},
			expectedCmd: "cmd --flag=\"value\"",
			expectedErr: false,
		},
		{
			name:        "Test Short Path (cmdline exists)",
			fullPath:    false,
			statusName:  "cmdline data",
			files:       map[string]string{"cmdline": "cmdline"},
			symlinks:    map[string]string{},
			expectedCmd: "cmdline",
			expectedErr: false,
		},
		{
			name:        "Test Command Truncated in Status",
			fullPath:    false,
			statusName:  "cmdline data",
			files:       map[string]string{"cmdline": "cmdline"},
			symlinks:    map[string]string{},
			expectedCmd: "cmdline",
			expectedErr: false,
		},
		{
			name:        "Test Command 'none' for Kernel Helper",
			fullPath:    false,
			statusName:  "none",
			files:       map[string]string{"cmdline": "cmdline"},
			symlinks:    map[string]string{},
			expectedCmd: "cmdline",
			expectedErr: false,
		},
		{
			name:        "Test Empty Command",
			fullPath:    false,
			statusName:  "",
			files:       map[string]string{"cmdline": ""},
			symlinks:    map[string]string{},
			expectedCmd: "-",
			expectedErr: false,
		},
		{
			name:        "Test Non-Zombie Process with Matching Executable Path",
			fullPath:    true,
			statusName:  "cmdline data",
			files:       map[string]string{"cmdline": "cmd --flag=\"value\""},
			symlinks:    map[string]string{"exe": "/path/to/executable"},
			expectedCmd: "cmd --flag=\"value\"",
			expectedErr: false,
		},
		{
			name:        "Test Non-Zombie Process with Mismatched Executable Path",
			fullPath:    true,
			statusName:  "cmdline data",
			files:       map[string]string{"cmdline": "cmd --flag=\"value\""},
			symlinks:    map[string]string{"exe": "/different/path/to/executable"},
			expectedCmd: "cmd --flag=\"value\"",
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFS := mockProcFS(1234, tt.files, tt.symlinks)
			cmd, err := getCommand(mockFS, tt.fullPath, tt.statusName)

			if tt.expectedErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if cmd != tt.expectedCmd {
				t.Errorf("expected command: %v, got: %v", tt.expectedCmd, cmd)
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
