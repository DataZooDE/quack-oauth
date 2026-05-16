# quack-oauth live demo

A small, self-contained example application that exercises every
moving part of `quack-oauth` end-to-end:

- **Server**: one Python process boots an in-process DuckDB, loads
  `quack` + `quack_oauth`, configures the **GitHub** provider preset,
  caches the **NYC TLC yellow-taxi parquet** (~50 MB, one month) into
  `main.trips_enriched`, and starts the quack listener with policy +
  audit wired in.
- **Browser client**: a static page running **DuckDB-Wasm** that
  obtains a GitHub OAuth token (Web Flow, callback proxied by the
  same Python process), `ATTACH`es to the server over the quack
  protocol, pulls a sample into an **Apache Arrow** table, and
  hands it to a **Perspective** `<perspective-viewer>` for an
  interactive pivot — with **zero-copy Arrow IPC** between the
  DuckDB-Wasm and Perspective WASM heaps when the browser is in a
  cross-origin-isolated context.

```
        +-----------------------+              +---------------------------+
        |  browser              |              |  python process           |
        |                       |              |                           |
        |  +-----------------+  | http :8000   |  +---------------------+  |
        |  | static HTML +   |<-+--------------+->| aiohttp:            |  |
        |  | DuckDB-Wasm     |  |              |  |  GET  /             |  |
        |  | + Perspective   |  |              |  |  GET  /oauth/login  |  |
        |  +--------+--------+  |              |  |  GET  /oauth/cb     |  |
        |           |           |              |  |  POST /quack proxy  |  |
        |     ATTACH 'quack:    |              |  +-----+---------------+  |
        |     localhost:8000'   |              |        |                  |
        |     (token 'gho_..')  |              |        v 127.0.0.1:<rnd>  |
        |                       |              |  +---------------------+  |
        |                       |              |  | duckdb              |  |
        |                       |              |  |  quack_serve()      |  |
        |                       |              |  |  quack_oauth_*      |  |
        |                       |              |  |  main.trips_enriched|  |
        |                       |              |  +---------------------+  |
        +-----------------------+              +---------------------------+
                  |
                  v GitHub OAuth Web Flow (sign-in + /user)
        +-----------------------+
        |  github.com           |
        +-----------------------+
```

## Prerequisites

- `uv` ([install](https://github.com/astral-sh/uv))
- A **GitHub OAuth App** you own (NOT a GitHub App — the
  `github_check` validation endpoint
  `POST /applications/{client_id}/token` is OAuth-App-only).

## Set up the OAuth App

1. github.com → **Settings → Developer settings → OAuth Apps → New OAuth App**.
2. **Application name**: anything you like.
   **Homepage URL**: `http://localhost:8000/`.
   **Authorization callback URL**: `http://localhost:8000/oauth/callback`.
3. Note the **Client ID** (starts with `Iv1.` or `Ov23li…`).
4. **Generate a new client secret** — copy the value once; GitHub
   shows it exactly one time.

## Configure the demo

```bash
cd example
cp .env.demo.example .env.demo
# edit .env.demo: paste GITHUB_DEMO_CLIENT_ID and GITHUB_DEMO_CLIENT_SECRET
```

## Run

```bash
cd example
uv run quack-oauth-demo
```

First boot downloads `yellow_tripdata_2024-01.parquet` (~50 MB) and
the zone lookup into `example/cache/`. Subsequent boots reuse the
cache.

You should see:

```
[boot] opening DuckDB + loading quack + quack_oauth
[boot] loading NYC taxi data
[taxi_data] main.trips_enriched ready (2,964,624 rows)
[boot] wiring github auth + policy + audit
[boot] starting quack listener on quack:127.0.0.1:54321
[boot] frontend listening on http://localhost:8000  (quack proxy -> quack:127.0.0.1:54321)
[boot] open http://localhost:8000 in your browser
```

Open <http://localhost:8000>, click **sign in with GitHub**, approve
the App on github.com, land back on the demo page. A few seconds
later the pivot renders with rows = pickup borough, cols = dropoff
borough, measures = avg fare / miles / tip. Drag dimensions inside
the viewer to re-pivot in place (Perspective handles those locally —
no extra queries to the server).

## What the demo verifies

| Layer | Showcased by |
|---|---|
| `quack_oauth_check_token` against live GitHub | every ATTACH; audit row `token_accepted` with subject `gh:<your-id>` |
| `quack_oauth_check_authorization` policy table | server logs print `authz_allow Scan rule allow` |
| GitHub provider preset (R-S-13) | server SECRET omits `introspect_client_id`, fixed in commit `d5d5cb5` |
| github_check decision cache | repeated queries: only the first hits `api.github.com` |
| Quack wire protocol over HTTP | wireshark / browser devtools: `POST /quack` per query |
| DuckDB-Wasm + custom extension repo | first page load: 200 from `get.erpl.io/v1.5.2/wasm_eh/quack_oauth.duckdb_extension.wasm` |
| Arrow zero-copy handoff | `window.crossOriginIsolated === true` (footer green); pivot drag is instantaneous |

## Inspect the server side

The server prints audit rows after each query the browser issues.
You can also peek live by attaching a second DuckDB shell to the
running process via the same quack URI (with your own gho_ token):

```sql
INSTALL quack; LOAD quack;
ATTACH 'quack:127.0.0.1:8000' AS srv (TYPE quack, token 'gho_…');
SELECT * FROM srv.main.audit ORDER BY timestamp_unix_s DESC LIMIT 10;
```

## Troubleshooting

- **"crossOriginIsolated: false" in the footer**: jsdelivr is meant
  to serve `Cross-Origin-Resource-Policy: cross-origin` headers. If
  your network injects something between you and jsdelivr that
  strips them, the Arrow handoff falls back to a single memcpy —
  still fast, just not headline-zero-copy.
- **`Authentication failed` on ATTACH**: your GitHub OAuth App
  credentials in `.env.demo` are wrong, or the App is mis-typed (it
  must be an **OAuth App**, not a **GitHub App**).
- **`get.erpl.io ... 404`** during INSTALL: probably you're on a
  DuckDB build that isn't `v1.5.2`. The extension is only published
  for that version.
- **First boot is slow**: ~50 MB parquet download. Cached after.

## Reset

```bash
rm -rf example/cache
```

Re-download on next boot.

## Why this lives under `example/`

The repo's `e2e/` Python harness is a test suite (pytest + Keycloak
fixture). This is a hands-on demo. They share patterns (in-process
DuckDB, `quack_serve()` from a Python connection, policy + audit
seeding) but not test machinery, so I kept them separate.
