package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentRequiresHumanTask(t *testing.T) {
	if err := agentCommand([]string{"-room", "test"}); err == nil {
		t.Fatal("expected task validation")
	}
}
func TestAgentUsesLocalClaude(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-claude")
	out := filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + out + "'\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := agentCommand([]string{"-data", dir, "-room", "physics", "-task", "Find gaps", "-claude-bin", bin}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "HUMAN-APPROVED TASK") || !strings.Contains(string(b), "Find gaps") {
		t.Fatal("missing task")
	}
}
