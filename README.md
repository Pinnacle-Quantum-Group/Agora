# AGORA — Questions into outcomes

Ubuntu-first Go MVP for evidence-centered research rooms with an optional local Claude Code assistant. **Prototype/controlled alpha; not ready for open public Internet deployment.**

## Run locally (Ubuntu)

Requires Go 1.22+ and optionally an authenticated Claude Code CLI. No third-party Go dependencies.

```bash
git clone YOUR_REPO_URL agora
cd agora
go test ./...
go build -o agora .
export AGORA_ADMIN_TOKEN="$(openssl rand -hex 32)"
./agora -listen 127.0.0.1:8080 -data ./agora-data
```

Open `http://127.0.0.1:8080/web/`. The UI requests the operator token when posting or synchronizing. Keep the token private. It is not persisted by the browser.

```bash
./agora agent -data ./agora-data -room general -task 'Find testable hypotheses and unresolved objections'
```

The agent runs locally, with Claude Code tools disabled. This **is not an OS sandbox**. Use a separate low-privilege account without credentials or sensitive files; do not run Claude as root. Agent results print to stdout and are not automatically published.

## Included

- Embedded static web interface and problem rooms
- Append-only JSONL signed event log with Ed25519 node identity
- Event kinds: message, claim, hypothesis, experiment, objection, outcome
- Local operator token for writes and synchronization; GET events are public
- HTTP timeouts, strict JSON parsing, response-size caps, loopback-only default
- Local Claude Code wrapper with bounded history and timeout
- Opt-in static HTTPS peers (experimental; shared operator token required)
- systemd example, Caddy example, CI, tests, and software-factory backlog

## Explicit limitations

- Google/Apple OIDC login is available when configured; events remain signed by the **node**, not individual users. Sessions are in memory and reset on restart. No per-user author signatures or room ACLs yet.
- JSONL has no transactional recovery, pagination, or indexed queries.
- Peer synchronization is experimental, retrieves up to 500 events, and is not a reliable full-history protocol. Peer URLs are configured by the operator, not discovered dynamically.
- **No DALnet/IRC transport, DDNS integration, NAT traversal, RSS discovery, or production federation.**
- No WebSocket; browser polls. No user moderation, private rooms, backups, automated upgrades, or formal audit.
- Admin token shared across any manually configured peers; do not reuse it across untrusted operators.
- This is suitable for local evaluation and a controlled engineering alpha, **not** unrestricted public exposure.

## Deployment

`deploy/agora.service` is a template. Create a dedicated `agora` Linux user and `/var/lib/agora` owned by it; put `AGORA_ADMIN_TOKEN=...` in `/etc/agora/agora.env` with root-only permissions; install the binary at `/usr/local/bin/agora`. Use the sample Caddyfile only after DNS is configured and the host is secured. Do not expose the application directly on `0.0.0.0`.

## Repository roadmap

See `FACTORY_BACKLOG.md` for independently gated engineering stages. A release candidate requires verified identity, storage durability, Claude isolation, trusted incremental federation, abuse controls, and multi-node integration testing.

## License

MIT. See LICENSE.

## IRC-first transport (experimental)

Agora can join an **authorized** IRC network over TLS for rendezvous and channel presence:

```bash
./agora -irc-server irc.example.org:6697 -irc-nick AgoraNode -irc-channel '#AGORA_Discovery'
```

This is a real IRC TLS client with registration, PING/PONG, ISUPPORT CHANLEN parsing, JOIN, and reconnect. It does **not** yet bridge room chat, announce signed peers, implement SASL/NickServ, or replicate data over IRC. It must not be pointed at DALnet without permission from the relevant server/network operators. The signed Agora event log remains authoritative. MIT license applies (see LICENSE).

## Google / Apple login (optional)

Register OAuth clients with these **exact** callback URLs (replace host):

- Google: `https://agora.example.org/auth/callback/google` (for localhost development: `http://localhost:8080/auth/callback/google`)
- Apple Services ID: `https://agora.example.org/auth/callback/apple` (HTTPS public domain required).

Set variables before launching:

```bash
export AGORA_PUBLIC_URL=https://agora.example.org
export AGORA_GOOGLE_CLIENT_ID=your-google-client-id
export AGORA_GOOGLE_CLIENT_SECRET=your-google-secret
# Optional Apple Sign in with Apple configuration:
export AGORA_APPLE_CLIENT_ID=your-services-id
export AGORA_APPLE_TEAM_ID=your-team-id
export AGORA_APPLE_KEY_ID=your-key-id
export AGORA_APPLE_PRIVATE_KEY_FILE=/etc/agora/apple-auth-key.p8
```

OAuth authorization-code flow uses PKCE, CSRF state cookie, provider JWKS signature validation, issuer/audience/expiry checks, and HttpOnly session cookies. Apple client secrets are signed on demand. Google works on localhost over HTTP for development; Apple requires an HTTPS public callback. Set `AGORA_PUBLIC_URL` to the exact browser origin (behind TLS reverse proxy in production).

**Security boundary:** OAuth login grants basic event-posting permission only. Administrative synchronization still requires `AGORA_ADMIN_TOKEN`. Google/Apple login is account authentication, **not KYC**, proof of export authorization, or a user-signed contribution. There is no private-channel access enforcement yet. Do not expose to untrusted public users until the factory implements persistent sessions, authorization, audit, and anti-abuse controls.

## Software factory start

Use `FACTORY_BACKLOG.md` as the engineering queue. First gates: persist sessions and identities, enforce per-room ACLs (including private rooms), bind each contribution to an authenticated identity, and implement IRC room messaging and federation tests.
