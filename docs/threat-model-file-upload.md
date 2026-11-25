# Threat model — new feature: ticket file upload

Applied as a pre-merge review gate for the proposed "attach a file to a ticket" feature.
Method: STRIDE over the feature's data flow. The feature is **not** implemented in this
lab; this document is the security review that must pass before it would be.

## Feature summary
Users upload a file (image or PDF) to a ticket. Files are stored on disk and served back
from `/tickets/{id}/files/{name}`. The mock agent can be asked to "summarise attachments".

## Data flow / trust boundaries
1. Browser → `POST /api/tickets/{id}/files` (untrusted bytes + filename + content-type)
2. API → filesystem (write) and DB (metadata)
3. Browser → `GET /tickets/{id}/files/{name}` (serve)
4. Agent → reads attachment bytes (new injection sink)

## STRIDE

| Category | Threat | Mitigation (required before merge) |
|---|---|---|
| Spoofing | Unauthenticated upload | Require auth; bind upload to the ticket owner. |
| Tampering | Path traversal via `filename` (`../../etc`) | Generate server-side names; never trust the client name. |
| Repudiation | No record of who uploaded what | Store uploader id + timestamp; audit log. |
| Information disclosure | IDOR on file retrieval (cf. F01) | Enforce ownership on the serve route. |
| Information disclosure | Serve with `Content-Type: text/html` → stored XSS | Force `Content-Disposition: attachment` + `nosniff`; allow-list MIME. |
| Denial of service | Huge/zip-bomb uploads (cf. F05) | Max size, count, and per-user rate limit. |
| Elevation of privilege | Agent follows instructions hidden in a PDF (cf. F09) | Treat attachment text as data; never let it drive tool calls. |
| Tampering | Malicious SVG/script, polyglot files | Validate magic bytes; re-encode images; reject on mismatch. |

## Residual risk & decision
Merge only when every "required before merge" control is implemented and covered by a
re-test in the harness (same vuln/fixed pattern). Owner sign-off required. This lab marks
the feature **blocked** until those tests exist.
