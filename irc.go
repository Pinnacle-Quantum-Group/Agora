package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"time"
)

// IRC is a rendezvous and conversation transport; signed Agora events remain authoritative.
type IRCConfig struct {
	Server, Nick, Channel string
	Enabled               bool
}

var ircSafe = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

func ircChannel(question, part string, max int) string {
	if max < 16 {
		max = 32
	}
	base := "#AGORA_" + ircSafe.ReplaceAllString(question, "_")
	if part != "" {
		base += "_" + ircSafe.ReplaceAllString(part, "_")
	}
	// A stable suffix avoids collisions when names are shortened.
	hash := sha256Short(question + "\x00" + part)
	suffix := "_" + hash
	if len(base)+len(suffix) > max {
		base = base[:max-len(suffix)]
	}
	return base + suffix
}
func sha256Short(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:10]
}
func runIRC(ctx context.Context, cfg IRCConfig) {
	if !cfg.Enabled {
		return
	}
	for ctx.Err() == nil {
		if err := ircSession(ctx, cfg); err != nil && ctx.Err() == nil {
			log.Printf("IRC disconnected: %v", err)
		}
		delay := time.Duration(5+rand.Intn(6)) * time.Second
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}
func ircSession(ctx context.Context, cfg IRCConfig) error {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", cfg.Server, &tls.Config{MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()
	write := func(line string) error { _, e := fmt.Fprintf(conn, "%s\r\n", line); return e }
	nick := ircSafe.ReplaceAllString(cfg.Nick, "_")
	if nick == "" {
		nick = "AgoraNode"
	}
	if len(nick) > 20 {
		nick = nick[:20]
	}
	if err = write("NICK " + nick); err != nil {
		return err
	}
	if err = write("USER agora 0 * :Agora research node"); err != nil {
		return err
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 8192)
	joined := false
	chanlen := 32
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PING ") {
			if err = write("PONG " + strings.TrimPrefix(line, "PING ")); err != nil {
				return err
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "005" {
			for _, f := range fields {
				if strings.HasPrefix(f, "CHANLEN=") {
					var n int
					fmt.Sscanf(f, "CHANLEN=%d", &n)
					if n >= 16 && n <= 256 {
						chanlen = n
					}
				}
			}
		}
		if fields[1] == "001" && !joined {
			channel := cfg.Channel
			if channel == "" {
				channel = ircChannel("Discovery", "", chanlen)
			}
			if !strings.HasPrefix(channel, "#AGORA_") || len(channel) > chanlen || strings.ContainsAny(channel, " ,\r\n\x00") {
				return fmt.Errorf("invalid or overlength IRC channel")
			}
			if err = write("JOIN " + channel); err != nil {
				return err
			}
			joined = true
			log.Printf("IRC joined %s on %s", channel, cfg.Server)
		}
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	return fmt.Errorf("IRC connection closed")
}
