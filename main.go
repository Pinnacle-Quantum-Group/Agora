package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var assets embed.FS

type Event struct {
	ID        string `json:"id"`
	Node      string `json:"node"`
	Room      string `json:"room"`
	Kind      string `json:"kind"`
	Text      string `json:"text"`
	Parent    string `json:"parent,omitempty"`
	Time      int64  `json:"time"`
	Signature string `json:"signature"`
}
type unsigned struct {
	Node   string `json:"node"`
	Room   string `json:"room"`
	Kind   string `json:"kind"`
	Text   string `json:"text"`
	Parent string `json:"parent,omitempty"`
	Time   int64  `json:"time"`
}
type Store struct {
	sync.Mutex
	events map[string]Event
	peers  []string
	path   string
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
}

func payload(e Event) []byte {
	b, _ := json.Marshal(unsigned{e.Node, e.Room, e.Kind, e.Text, e.Parent, e.Time})
	return b
}
func verify(e Event) bool {
	pub, err := base64.RawURLEncoding.DecodeString(e.Node)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(append(payload(e), sig...))
	return e.ID == hex.EncodeToString(sum[:]) && ed25519.Verify(pub, payload(e), sig)
}
func (s *Store) add(e Event) bool {
	if !verify(e) || strings.TrimSpace(e.Room) == "" || strings.TrimSpace(e.Text) == "" || len(e.Text) > 8192 || len(e.Room) > 80 || len(e.Kind) > 40 || len(e.Parent) > 100 || e.Time > time.Now().Add(5*time.Minute).UnixMilli() || e.Time < time.Now().Add(-365*24*time.Hour).UnixMilli() {
		return false
	}
	s.Lock()
	defer s.Unlock()
	if _, ok := s.events[e.ID]; ok {
		return true
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return false
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	if _, err = f.Write(append(b, '\n')); err != nil {
		return false
	}
	s.events[e.ID] = e
	return true
}
func (s *Store) list() []Event {
	s.Lock()
	defer s.Unlock()
	out := make([]Event, 0, len(s.events))
	for _, e := range s.events {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Time == out[j].Time {
			return out[i].ID < out[j].ID
		}
		return out[i].Time < out[j].Time
	})
	return out
}
func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		if err := agentCommand(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	dir := flag.String("data", "./agora-data", "data directory")
	addr := flag.String("listen", "127.0.0.1:8080", "listen address")
	peer := flag.String("peer", "", "comma-separated HTTPS peer base URLs")
	ircServer := flag.String("irc-server", "", "opt-in IRC TLS host:port (only on networks authorizing bots)")
	ircNick := flag.String("irc-nick", "AgoraNode", "IRC nickname")
	ircChannelFlag := flag.String("irc-channel", "", "approved #AGORA_ channel")
	flag.Parse()
	if *ircServer != "" {
		go runIRC(context.Background(), IRCConfig{Server: *ircServer, Nick: *ircNick, Channel: *ircChannelFlag, Enabled: true})
	}
	if err := secureBind(*addr); err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*dir, 0700); err != nil {
		log.Fatal(err)
	}
	keyPath := filepath.Join(*dir, "identity.key")
	key, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		_, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			log.Fatal(e)
		}
		key = priv
		if e = os.WriteFile(keyPath, key, 0600); e != nil {
			log.Fatal(e)
		}
	} else if err != nil {
		log.Fatal(err)
	}
	if len(key) != ed25519.PrivateKeySize {
		log.Fatal("bad identity key")
	}
	priv := ed25519.PrivateKey(key)
	s := &Store{events: map[string]Event{}, path: filepath.Join(*dir, "events.jsonl"), priv: priv, pub: priv.Public().(ed25519.PublicKey)}
	if b, e := os.ReadFile(s.path); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			var ev Event
			if json.Unmarshal([]byte(line), &ev) == nil && verify(ev) {
				s.events[ev.ID] = ev
			}
		}
	}
	for _, p := range strings.Split(*peer, ",") {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if strings.HasPrefix(p, "https://") {
			s.peers = append(s.peers, p)
		}
	}
	mux := http.NewServeMux()
	broker := newIdentityBroker()
	broker.routes(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/web/", http.StatusTemporaryRedirect)
			return
		}
		http.FileServer(http.FS(assets)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK); w.Write([]byte("ok")) })
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		jsonOut(w, map[string]any{"node": base64.RawURLEncoding.EncodeToString(s.pub), "peers": s.peers})
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			room := r.URL.Query().Get("room")
			all := s.list()
			limit := 100
			if n, e := strconv.Atoi(r.URL.Query().Get("limit")); e == nil && n > 0 && n <= 500 {
				limit = n
			}
			out := []Event{}
			for _, e := range all {
				if room == "" || e.Room == room {
					out = append(out, e)
				}
			}
			if len(out) > limit {
				out = out[len(out)-limit:]
			}
			jsonOut(w, out)
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		if _, ok := broker.identity(r); !ok && !authorized(r) {
			http.Error(w, "login or operator authorization required", 401)
			return
		}
		var req struct {
			Room   string `json:"room"`
			Kind   string `json:"kind"`
			Text   string `json:"text"`
			Parent string `json:"parent"`
		}
		if decodeStrict(w, r, &req, 12000) != nil || strings.TrimSpace(req.Text) == "" || len(req.Text) > 8192 || len(req.Room) > 80 || req.Room == "" {
			http.Error(w, "invalid", 400)
			return
		}
		switch req.Kind {
		case "message", "claim", "hypothesis", "experiment", "outcome", "objection":
		default:
			http.Error(w, "kind", 400)
			return
		}
		ev := Event{Node: base64.RawURLEncoding.EncodeToString(s.pub), Room: req.Room, Kind: req.Kind, Text: req.Text, Parent: req.Parent, Time: time.Now().UnixMilli()}
		sig := ed25519.Sign(s.priv, payload(ev))
		ev.Signature = base64.RawURLEncoding.EncodeToString(sig)
		sum := sha256.Sum256(append(payload(ev), sig...))
		ev.ID = hex.EncodeToString(sum[:])
		if !s.add(ev) {
			http.Error(w, "storage", 500)
			return
		}
		jsonOut(w, ev)
	})
	mux.HandleFunc("/api/federation/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method", 405)
			return
		}
		if !authorized(r) {
			http.Error(w, "federation requires operator token in MVP", 401)
			return
		}
		all := s.list()
		if len(all) > 500 {
			all = all[len(all)-500:]
		}
		jsonOut(w, all)
	})
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		if !authorized(r) {
			http.Error(w, "operator authorization required", 401)
			return
		}
		client := &http.Client{Timeout: 12 * time.Second}
		added := 0
		for _, p := range s.peers {
			req, e := http.NewRequest("GET", p+"/api/federation/events", nil)
			if e != nil {
				continue
			}
			req.Header.Set("Authorization", r.Header.Get("Authorization"))
			resp, e := client.Do(req)
			if e != nil {
				continue
			}
			body, e := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
			resp.Body.Close()
			if e != nil || resp.StatusCode != 200 {
				continue
			}
			var events []Event
			if json.Unmarshal(body, &events) != nil {
				continue
			}
			for _, ev := range events {
				s.Lock()
				_, exists := s.events[ev.ID]
				s.Unlock()
				if !exists && s.add(ev) {
					added++
				}
			}
		}
		jsonOut(w, map[string]int{"accepted": added})
	})
	log.Printf("Agora node %s listening on %s", base64.RawURLEncoding.EncodeToString(s.pub), *addr)
	log.Fatal(server(*addr, securityHeaders(mux)).ListenAndServe())
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'")
		if r.Method == "POST" {
			origin := r.Header.Get("Origin")
			if origin != "" && !strings.EqualFold(origin, "http://"+r.Host) && !strings.EqualFold(origin, "https://"+r.Host) {
				http.Error(w, "origin", 403)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
