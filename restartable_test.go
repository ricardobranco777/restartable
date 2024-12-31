package main

import (
	"fmt"
	"io/fs"
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
	procFS := mockProcFS(1234, map[string]string{
		"maps": "00400000-00452000 r-xp 00000000 fd:00 12345 /bin/bash (deleted)\n",
	}, nil)

	files, err := getDeleted(procFS)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(files) != 1 || files[0] != "/bin/bash" {
		t.Errorf("Expected ['/bin/bash'], got %v", files)
	}
}

// Test getService
func TestGetService(t *testing.T) {
	procFS := mockProcFS(1234, map[string]string{
		"cgroup": "/proc/777/cgroup:0::/system.slice/sshd.service\n",
	}, nil)

	service := getService(procFS, false)
	if service != "sshd" {
		t.Errorf("Expected 'sshd', got '%s'", service)
	}
}

// Test getCommand
func TestGetCommand(t *testing.T) {
	procFS := mockProcFS(1234, map[string]string{
		"cmdline": "/bin/bash\x00--version\x00",
	}, nil)

	command, err := getCommand(procFS, true, "bash")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	expected := "/bin/bash --version"
	if command != expected {
		t.Errorf("Expected '%s', got '%s'", expected, command)
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
