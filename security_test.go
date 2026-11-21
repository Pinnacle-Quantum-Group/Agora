package main

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestOperatorAuthorization(t *testing.T) {
	t.Setenv("AGORA_ADMIN_TOKEN", "testing-secret")
	r := httptest.NewRequest("POST", "http://localhost/api/events", nil)
	if authorized(r) {
		t.Fatal("unauthenticated request accepted")
	}
	r.Header.Set("Authorization", "Bearer testing-secret")
	if !authorized(r) {
		t.Fatal("valid token rejected")
	}
	r.Header.Set("Authorization", "Bearer wrong")
	if authorized(r) {
		t.Fatal("wrong token accepted")
	}
}
func TestBindSafety(t *testing.T) {
	os.Unsetenv("AGORA_ALLOW_PUBLIC_BIND")
	if err := secureBind("0.0.0.0:8080"); err == nil {
		t.Fatal("public bind accepted")
	}
	if err := secureBind("127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
}
func TestAgentEnv(t *testing.T) {
	out := filteredAgentEnv([]string{"HOME=/tmp", "AGORA_ADMIN_TOKEN=secret", "GH_TOKEN=secret"})
	if len(out) != 1 || !strings.HasPrefix(out[0], "HOME=") {
		t.Fatalf("unexpected environment: %v", out)
	}
}
