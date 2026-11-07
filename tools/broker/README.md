# tools/broker — nsh-auth reference token broker

A tiny server the **app owner** runs. Some providers need a client secret at
the token endpoint even for public-client flows — GitHub's web flow is the
canonical case (`client_id` + `client_secret` + `code`). The secret must never
live inside an app bundle, so the app sends its authorization code here and the
broker swaps it for tokens.

The broker has exactly one route and no storage. It holds the client secret in
an environment variable and **refuses to start without it**. It binds
`127.0.0.1` only and never contacts anything except the configured provider
token endpoint. Its logs contain no tokens, no codes and no secrets — only
`POST /token -> <status> <latency>` lines.

## Run

```sh
export GITHUB_CLIENT_SECRET=…   # required; the broker exits without it
node tools/broker/main.mjs --port 0
```

```
BROKER_URL=http://127.0.0.1:54123
```

| Env var | Default | Meaning |
| --- | --- | --- |
| `GITHUB_CLIENT_SECRET` | — (required) | the provider client secret; never logged, never written anywhere |
| `BROKER_TOKEN_URL` | `http://127.0.0.1:8755/github/login/oauth/access_token` | provider token endpoint to forward to |
| `BROKER_CLIENT_ID` | `nsh-auth-sandbox-client-id` | the client id sent alongside the secret |

`--port 0` (or omitting `--port`) picks an ephemeral port; the default port is
`8756`. From the Android emulator the broker is reachable as
`http://10.0.2.2:<port>`.

## Endpoint

`POST /token` with a JSON body:

```json
{ "code": "…", "code_verifier": "…", "redirect_uri": "nsh-auth-sandbox://callback" }
```

- `code` is required; `code_verifier` and `redirect_uri` are forwarded when
  present (PKCE still binds end to end, since the code was issued against the
  challenge).
- The broker forwards the fields plus `client_id` and `client_secret` as an
  `application/x-www-form-urlencoded` request with `Accept: application/json`
  (GitHub answers form-encoded without that header).
- The provider's status code and body are returned verbatim — including
  GitHub's quirk of reporting `bad_verification_code` in-band with HTTP 200.

Anything else answers `404`. Malformed requests answer `400 invalid_request`
without contacting the provider. A provider that cannot be reached answers
`502 provider_unavailable`.

## Tests

```sh
cd tools/broker && bun test
```

The suite spawns the mock (`tools/mock-oauth`) on an ephemeral port, points a
real broker process at it, and runs the whole GitHub leg: authorize → broker
exchange → the returned access token authenticates at the mock's user
endpoint. It also proves the broker exits non-zero without
`GITHUB_CLIENT_SECRET` and that logs never contain the secret or tokens.
