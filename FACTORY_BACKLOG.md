# AGORA — AI Software Factory Backlog

## Working rules

- Never claim a capability is complete without an executable acceptance test.
- Implement in small PRs; include threat model, migration/rollback, tests, and operational notes.
- Preserve the signed event format or introduce explicit versioned migrations.
- Make IRC/IRCv3 the first-class conversation and rendezvous transport; keep signed Agora events as the authoritative durable record.
- Never allow remotely sourced room text to become privileged Claude instructions.
- No autonomous publication or unrestricted shell access from agent jobs.

## P0 — controlled alpha hardening

1. **Identity:** per-user Ed25519 authorship, account/session lifecycle, room ACLs, revocation. Gate: anonymous write rejected; forged authorship rejected; private room unreadable to unauthorized users.
2. **Storage:** SQLite WAL, transactional migrations, event ID uniqueness, durable queue, paginated queries, backup/restore. Gate: kill -9 during writes; restore all acknowledged events; replay is idempotent.
3. **Agent supervisor:** dedicated Linux user, sandbox via systemd transient units or namespaces, explicit allowlisted tools, resource quotas, cancellation, audit logs, bounded output. Gate: adversarial prompts cannot read host secrets or execute forbidden tools.
4. **HTTP:** TLS proxy deployment, auth and CSRF review, rate limiting, request caps, security tests, abuse policy. Gate: unauthenticated mutations and SSRF probes fail.

## P1 — federated beta

5. **IRC transport:** complete IRCv3 negotiation, safe user/channel identity mapping, channel chat bridge, authorized peer advertisements, TLS and SASL, flood controls, reconnect. DALnet requires operator authorization. RSS/Atom signed manifest bootstrap and DDNS optional. Gate: discovery outage does not lose events.
6. **Federation:** mutual peer authorization, signed manifests, incremental cursor/anti-entropy, hash-chain validation, bounded downloads, privacy scopes. Gate: three-node offline/rejoin converges under duplicates and malicious peers.
7. **Product:** search, question/subpart graph, claim/evidence links, accessibility, responsive layout, moderation and appeals. Gate: complete question-to-outcome journey passes browser E2E.

## P2 — release candidate

8. **Ops:** metrics, audit events, backups, restore drills, resource budgets, 72h soak, upgrade rollback.
9. **Supply chain:** pinned CI, SBOM, dependency scanning, signed amd64/arm64 binaries, documented reproducible builds.
10. **Governance:** contribution attribution with independent verification; anti-gaming, appeal, evidence retention and deletion policy.

## PR template

Problem / threat model / design / changed files / tests / failure modes / migration / rollback / evidence / open questions.
