package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Local operator token is deliberately distinct from the node's signing key.
func operatorToken() string { return strings.TrimSpace(os.Getenv("AGORA_ADMIN_TOKEN")) }
func authorized(r *http.Request) bool {
	token := operatorToken()
	if token == "" {
		return false
	}
	supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) == 1
}
func requireOperator(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			http.Error(w, "operator authorization required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
func secureBind(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if (ip == nil || !ip.IsLoopback()) && os.Getenv("AGORA_ALLOW_PUBLIC_BIND") != "1" {
		return errors.New("non-loopback listen requires AGORA_ALLOW_PUBLIC_BIND=1 and TLS reverse proxy")
	}
	return nil
}
func decodeStrict(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var trailing any
	if err := d.Decode(&trailing); err == nil {
		return errors.New("multiple JSON objects")
	}
	return nil
}
func server(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
}
