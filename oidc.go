package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type oidcProvider struct{ name, clientID, clientSecret, authURL, tokenURL, jwksURL, issuer string }
type oidcIdentity struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
	Email    string `json:"email,omitempty"`
}
type authState struct {
	provider, verifier string
	expires            time.Time
}
type sessionRecord struct {
	identity oidcIdentity
	expires  time.Time
}
type identityBroker struct {
	sync.Mutex
	base      string
	providers map[string]oidcProvider
	states    map[string]authState
	sessions  map[string]sessionRecord
	client    *http.Client
}

func randomURL(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func newIdentityBroker() *identityBroker {
	b := &identityBroker{base: strings.TrimRight(os.Getenv("AGORA_PUBLIC_URL"), "/"), providers: map[string]oidcProvider{}, states: map[string]authState{}, sessions: map[string]sessionRecord{}, client: &http.Client{Timeout: 8 * time.Second}}
	if id := os.Getenv("AGORA_GOOGLE_CLIENT_ID"); id != "" && b.base != "" {
		b.providers["google"] = oidcProvider{"google", id, os.Getenv("AGORA_GOOGLE_CLIENT_SECRET"), "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "https://www.googleapis.com/oauth2/v3/certs", "https://accounts.google.com"}
	}
	if id := os.Getenv("AGORA_APPLE_CLIENT_ID"); id != "" && strings.HasPrefix(b.base, "https://") {
		b.providers["apple"] = oidcProvider{"apple", id, "", "https://appleid.apple.com/auth/authorize", "https://appleid.apple.com/auth/token", "https://appleid.apple.com/auth/keys", "https://appleid.apple.com"}
	}
	return b
}
func (b *identityBroker) routes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/providers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method", 405)
			return
		}
		names := []string{}
		for k := range b.providers {
			names = append(names, k)
		}
		jsonOut(w, names)
	})
	mux.HandleFunc("/auth/login/", func(w http.ResponseWriter, r *http.Request) {
		p, ok := b.providers[strings.TrimPrefix(r.URL.Path, "/auth/login/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		state, verifier := randomURL(32), randomURL(32)
		challenge := sha256.Sum256([]byte(verifier))
		b.Lock()
		b.states[state] = authState{p.name, verifier, time.Now().Add(5 * time.Minute)}
		b.pruneLocked()
		b.Unlock()
		sameSite := http.SameSiteLaxMode
		if p.name == "apple" {
			sameSite = http.SameSiteNoneMode
		}
		http.SetCookie(w, &http.Cookie{Name: "agora_oauth", Value: state, Path: "/auth/callback/", HttpOnly: true, Secure: strings.HasPrefix(b.base, "https://"), SameSite: sameSite, MaxAge: 300})
		q := url.Values{"client_id": {p.clientID}, "redirect_uri": {b.base + "/auth/callback/" + p.name}, "response_type": {"code"}, "scope": {"openid email"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
		if p.name == "apple" {
			q.Set("response_mode", "form_post")
		}
		http.Redirect(w, r, p.authURL+"?"+q.Encode(), http.StatusFound)
	})
	mux.HandleFunc("/auth/callback/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/auth/callback/")
		p, ok := b.providers[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.Method != "GET" && r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		if r.Method == "POST" {
			r.Body = http.MaxBytesReader(w, r.Body, 8192)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid", 400)
				return
			}
		}
		state := r.FormValue("state")
		cookie, err := r.Cookie("agora_oauth")
		if err != nil || cookie.Value != state || state == "" {
			http.Error(w, "state mismatch", 403)
			return
		}
		b.Lock()
		st, found := b.states[state]
		delete(b.states, state)
		b.Unlock()
		if !found || st.provider != name || time.Now().After(st.expires) {
			http.Error(w, "expired login", 403)
			return
		}
		if r.FormValue("error") != "" || r.FormValue("code") == "" {
			http.Error(w, "login rejected", 401)
			return
		}
		secret := p.clientSecret
		if name == "apple" {
			secret, err = appleClientSecret(p.clientID)
			if err != nil {
				http.Error(w, "apple configuration", 500)
				return
			}
		}
		form := url.Values{"grant_type": {"authorization_code"}, "code": {r.FormValue("code")}, "redirect_uri": {b.base + "/auth/callback/" + name}, "client_id": {p.clientID}, "code_verifier": {st.verifier}}
		if secret != "" {
			form.Set("client_secret", secret)
		}
		req, err := http.NewRequestWithContext(r.Context(), "POST", p.tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			http.Error(w, "token request", 502)
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := b.client.Do(req)
		if err != nil {
			http.Error(w, "identity provider unavailable", 502)
			return
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		if err != nil || resp.StatusCode != 200 {
			http.Error(w, "token exchange failed", 401)
			return
		}
		var token struct {
			IDToken string `json:"id_token"`
		}
		if json.Unmarshal(data, &token) != nil || token.IDToken == "" {
			http.Error(w, "missing identity token", 401)
			return
		}
		claims, err := b.validateJWT(r.Context(), p, token.IDToken)
		if err != nil {
			http.Error(w, "invalid identity token", 401)
			return
		}
		sub, _ := claims["sub"].(string)
		email, _ := claims["email"].(string)
		if sub == "" {
			http.Error(w, "missing subject", 401)
			return
		}
		sid := randomURL(32)
		b.Lock()
		b.sessions[sid] = sessionRecord{oidcIdentity{name, sub, email}, time.Now().Add(12 * time.Hour)}
		b.pruneLocked()
		b.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "agora_session", Value: sid, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(b.base, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: 43200})
		http.SetCookie(w, &http.Cookie{Name: "agora_oauth", Value: "", Path: "/auth/callback/", HttpOnly: true, MaxAge: -1})
		http.Redirect(w, r, "/web/", http.StatusSeeOther)
	})
	mux.HandleFunc("/auth/me", func(w http.ResponseWriter, r *http.Request) {
		if id, ok := b.identity(r); ok {
			jsonOut(w, id)
			return
		}
		http.Error(w, "not authenticated", 401)
	})
	mux.HandleFunc("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		if c, e := r.Cookie("agora_session"); e == nil {
			b.Lock()
			delete(b.sessions, c.Value)
			b.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "agora_session", Path: "/", MaxAge: -1, HttpOnly: true})
		w.WriteHeader(204)
	})
}
func (b *identityBroker) pruneLocked() {
	now := time.Now()
	for k, v := range b.states {
		if now.After(v.expires) {
			delete(b.states, k)
		}
	}
	for k, v := range b.sessions {
		if now.After(v.expires) {
			delete(b.sessions, k)
		}
	}
}
func (b *identityBroker) identity(r *http.Request) (oidcIdentity, bool) {
	c, e := r.Cookie("agora_session")
	if e != nil {
		return oidcIdentity{}, false
	}
	b.Lock()
	defer b.Unlock()
	s, ok := b.sessions[c.Value]
	return s.identity, ok && time.Now().Before(s.expires)
}
func (b *identityBroker) validateJWT(ctx context.Context, p oidcProvider, jwt string) (map[string]any, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt segments")
	}
	decode := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
	headerBytes, e := decode(parts[0])
	if e != nil {
		return nil, e
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Alg != "RS256" || header.Kid == "" {
		return nil, errors.New("unsupported jwt")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", p.jwksURL, nil)
	if e != nil {
		return nil, e
	}
	resp, e := b.client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("jwks unavailable")
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if e != nil {
		return nil, e
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if json.Unmarshal(body, &jwks) != nil {
		return nil, errors.New("invalid jwks")
	}
	sig, e := decode(parts[2])
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	valid := false
	for _, key := range jwks.Keys {
		if key.Kid != header.Kid || key.Kty != "RSA" || (key.Alg != "" && key.Alg != "RS256") {
			continue
		}
		n, e1 := decode(key.N)
		ex, e2 := decode(key.E)
		if e1 != nil || e2 != nil || len(ex) > 4 {
			continue
		}
		exp := 0
		for _, v := range ex {
			exp = exp<<8 | int(v)
		}
		if exp < 3 {
			continue
		}
		pub := rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
		if rsa.VerifyPKCS1v15(&pub, crypto.SHA256, digest[:], sig) == nil {
			valid = true
			break
		}
	}
	if !valid {
		return nil, errors.New("bad jwt signature")
	}
	claimsBytes, e := decode(parts[1])
	if e != nil {
		return nil, e
	}
	var claims map[string]any
	if json.Unmarshal(claimsBytes, &claims) != nil {
		return nil, errors.New("claims")
	}
	iss, _ := claims["iss"].(string)
	if iss != p.issuer && !(p.name == "google" && iss == "accounts.google.com") {
		return nil, errors.New("issuer")
	}
	audOK := false
	switch aud := claims["aud"].(type) {
	case string:
		audOK = aud == p.clientID
	case []any:
		for _, v := range aud {
			if v == p.clientID {
				audOK = true
			}
		}
		if len(aud) > 1 {
			if azp, _ := claims["azp"].(string); azp != p.clientID {
				return nil, errors.New("azp")
			}
		}
	}
	if !audOK {
		return nil, errors.New("audience")
	}
	now := float64(time.Now().Unix())
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= now {
		return nil, errors.New("expired")
	}
	iat, ok := claims["iat"].(float64)
	if !ok || iat > now+120 {
		return nil, errors.New("issued in future")
	}
	return claims, nil
}
func appleClientSecret(clientID string) (string, error) {
	team := os.Getenv("AGORA_APPLE_TEAM_ID")
	keyID := os.Getenv("AGORA_APPLE_KEY_ID")
	path := os.Getenv("AGORA_APPLE_PRIVATE_KEY_FILE")
	if team == "" || keyID == "" || path == "" {
		return "", errors.New("missing apple signing settings")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", errors.New("pem")
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return "", e
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New("not ec key")
	}
	now := time.Now().Unix()
	head, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": keyID})
	body, _ := json.Marshal(map[string]any{"iss": team, "iat": now, "exp": now + 3600, "aud": "https://appleid.apple.com", "sub": clientID})
	input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(body)
	hash := sha256.Sum256([]byte(input))
	sig, e := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if e != nil {
		return "", e
	}
	return appleJWTSignature(input, sig)
}
func appleJWTSignature(input string, der []byte) (string, error) {
	var pair struct{ R, S *big.Int }
	rest, e := asn1.Unmarshal(der, &pair)
	if e != nil || len(rest) != 0 {
		return "", errors.New("ecdsa signature")
	}
	rb := pair.R.FillBytes(make([]byte, 32))
	sb := pair.S.FillBytes(make([]byte, 32))
	return input + "." + base64.RawURLEncoding.EncodeToString(append(rb, sb...)), nil
}
