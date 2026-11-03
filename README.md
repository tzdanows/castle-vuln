# castle-vuln

Castle's second test target: a small axum service whose flaws are deliberate, so that
Castle's three security sources each have something to pick up and fix.

Run it: `cargo run`, then `curl localhost:3000/healthz`. Tests: `cargo test`.

## Deliberate flaws

In the code (filed as issues, one run each):

| Endpoint | Flaw |
|---|---|
| `GET /files/{name}` | Path traversal: the name is joined to `data/` unchecked, so `..%2F` escapes the directory. |
| `GET /ping?host=` | Command injection: the host goes into `sh -c` unquoted. |
| `POST /users`, `POST /login` | Passwords are stored as unsalted MD5. |
| `POST /users` | Account takeover: registering an existing name silently replaces its password. |
| `DELETE /users/{name}` | No authentication: anyone can delete any user. |

In the dependencies (Dependabot alerts and the Trivy workflow):

| Crate | Advisory |
|---|---|
| `time 0.1.43` | RUSTSEC-2020-0071, segfault from `localtime_r` |

In the Dockerfile (Trivy misconfiguration): runs as root, no healthcheck.

Nothing here is a real secret and the service listens on nothing by default.
