package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSwitchMissingNoDeadlock(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "ssb")
	build := exec.Command("go", "build", "-race", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "switch", "missing")
	cmd.Env = append(os.Environ(), "HOME="+home, "GOMAXPROCS=1")
	cmd.Stdin = strings.NewReader("\n\n\n")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("switch should fail, output:\n%s", buf.String())
		}
		if strings.Contains(buf.String(), "deadlock") {
			t.Fatalf("deadlock:\n%s", buf.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("deadlock:\n%s", buf.String())
	}
}
