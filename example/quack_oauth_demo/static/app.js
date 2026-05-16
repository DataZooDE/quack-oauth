// quack-oauth demo client.
//
// Flow:
//   1. Read sessionStorage.gh_token (set by /oauth/callback). If absent, show
//      the sign-in pane and stop.
//   2. Bootstrap DuckDB-Wasm with custom_extension_repository = get.erpl.io.
//   3. INSTALL/LOAD quack and quack_oauth.
//   4. ATTACH 'quack:localhost:<page-port>' AS srv (token '<gho_*>').
//      The wasm client posts to /quack on this same origin -- aiohttp
//      reverse-proxies that to the in-process quack listener.
//   5. SELECT into an Arrow table, hand the IPC bytes to a Perspective
//      Worker. When the browser is in a cross-origin-isolated context
//      (the aiohttp COOP/COEP headers achieve this), the handoff uses
//      SharedArrayBuffer and is true zero-copy.
//   6. Render <perspective-viewer> with a default pivot. The user
//      drags row/col/measure inside Perspective -- those re-pivots
//      run entirely in Perspective's WASM, no extra queries.

import * as duckdb from "https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@1.33.1-dev53.0/+esm";
import perspective from "https://cdn.jsdelivr.net/npm/@finos/perspective@3/dist/cdn/perspective.js";
import "https://cdn.jsdelivr.net/npm/@finos/perspective-viewer@3/dist/cdn/perspective-viewer.js";
import "https://cdn.jsdelivr.net/npm/@finos/perspective-viewer-datagrid@3/dist/cdn/perspective-viewer-datagrid.js";
import "https://cdn.jsdelivr.net/npm/@finos/perspective-viewer-d3fc@3/dist/cdn/perspective-viewer-d3fc.js";

const QUACK_URI = `quack:${location.hostname}:${location.port || "80"}`;
const $log = document.getElementById("boot-log");

function log(msg, cls = "") {
  const line = document.createElement("div");
  if (cls) line.className = cls;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  $log.appendChild(line);
  $log.scrollTop = $log.scrollHeight;
  console.log(msg);
}

function showSignedOut() {
  document.getElementById("signin-pane").hidden = false;
  document.getElementById("app").hidden = true;
}

function showSignedIn(login) {
  document.getElementById("signin-pane").hidden = true;
  document.getElementById("app").hidden = false;
  document.getElementById("principal").textContent = login;
  const out = document.getElementById("sign-out");
  out.hidden = false;
  out.onclick = () => {
    sessionStorage.removeItem("gh_token");
    location.reload();
  };
}

function reportIsolation() {
  const el = document.getElementById("isolation-state");
  if (window.crossOriginIsolated) {
    el.textContent = "crossOriginIsolated: zero-copy Arrow handoff enabled";
    el.className = "good";
  } else {
    el.textContent = "crossOriginIsolated=false (Arrow IPC falls back to memcpy)";
    el.className = "bad";
  }
}

async function fetchGithubUser(token) {
  const r = await fetch("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" },
  });
  if (!r.ok) throw new Error(`github /user returned ${r.status}`);
  return r.json(); // {login, id, ...}
}

async function bootDuckDB() {
  // Standard recipe: pick the right bundle for this browser, instantiate.
  // jsdelivr serves with CORP: cross-origin so the worker + wasm pass COEP.
  const JSDELIVR_BUNDLES = duckdb.getJsDelivrBundles();
  const bundle = await duckdb.selectBundle(JSDELIVR_BUNDLES);
  const workerUrl = URL.createObjectURL(
    new Blob([`importScripts("${bundle.mainWorker}");`], { type: "text/javascript" })
  );
  const worker = new Worker(workerUrl);
  const logger = new duckdb.ConsoleLogger();
  const db = new duckdb.AsyncDuckDB(logger, worker);
  await db.instantiate(bundle.mainModule, bundle.pthreadWorker);
  URL.revokeObjectURL(workerUrl);
  await db.open({
    allowUnsignedExtensions: true,
    query: { customExtensionRepository: "http://get.erpl.io" },
  });
  const conn = await db.connect();
  return { db, conn };
}

async function loadExtensions(conn) {
  log("INSTALL quack; LOAD quack;");
  await conn.query("INSTALL quack;");
  await conn.query("LOAD quack;");
  // The aiohttp /ext-repo/* route is a same-origin pass-through to
  // get.erpl.io that injects the CORS headers the bucket doesn't
  // emit. Without it, the XHR-backed `INSTALL ... FROM <url>` would
  // fail with "Failed to execute 'send' on 'XMLHttpRequest'".
  const extRepo = `${location.origin}/ext-repo`;
  log(`INSTALL quack_oauth FROM '${extRepo}';`);
  await conn.query(`INSTALL quack_oauth FROM '${extRepo}';`);
  await conn.query("LOAD quack_oauth;");
}

async function attachAndQuery(conn, token) {
  // SQL-injection note: the token is a GitHub OAuth user-to-server token
  // (regex `^gho_[A-Za-z0-9_]+$`). It is server-validated by quack_oauth_check_token
  // immediately on ATTACH, so an injected token simply gets rejected --
  // BUT we still pass it via a prepared parameter where possible. The
  // ATTACH ... TYPE quack form doesn't accept parameter binding for
  // option values, so we inline after asserting the shape.
  if (!/^gh[oprsu]_[A-Za-z0-9_]+$/.test(token)) {
    throw new Error("token does not look like a GitHub OAuth token (gho_*/ghu_*/ghs_*)");
  }
  log(`ATTACH '${QUACK_URI}' AS srv (TYPE quack, token '<gh_...>')`);
  await conn.query(
    `ATTACH '${QUACK_URI}' AS srv (TYPE quack, token '${token}')`
  );

  log("SELECT * FROM srv.main.trips_enriched LIMIT 200000 ...");
  const t0 = performance.now();
  const tbl = await conn.query(`
    SELECT pickup_borough, dropoff_borough,
           hour_of_day, day_of_week, payment,
           passengers, trip_miles, fare_usd, tip_usd, total_usd
    FROM srv.main.trips_enriched
    USING SAMPLE 200000 ROWS;
  `);
  const dt = performance.now() - t0;
  log(`  ${tbl.numRows.toLocaleString()} rows in ${dt.toFixed(0)} ms`, "ok");
  return tbl;
}

async function renderPivot(arrowTable) {
  log("init Perspective worker");
  const psp = await perspective.worker();
  // Arrow IPC stream bytes. Perspective accepts ArrayBuffer or Uint8Array.
  // tableToIPC() is the supported entry point in modern @apache-arrow.
  // duckdb-wasm re-exports `arrow`, so we use it directly.
  const { tableToIPC } = await import(
    "https://cdn.jsdelivr.net/npm/apache-arrow@17/+esm"
  );
  const ipc = tableToIPC(arrowTable, "stream");
  log(`Arrow IPC bytes: ${(ipc.byteLength / (1024 * 1024)).toFixed(1)} MB -> Perspective`);

  const pTable = await psp.table(ipc.buffer);
  const viewer = document.getElementById("viewer");
  await viewer.load(pTable);
  await viewer.restore({
    plugin: "Datagrid",
    group_by: ["pickup_borough"],
    split_by: ["dropoff_borough"],
    columns: ["fare_usd", "trip_miles", "tip_usd"],
    aggregates: { fare_usd: "avg", trip_miles: "avg", tip_usd: "avg" },
    theme: "Pro Dark",
  });
  log("pivot rendered. drag dimensions in the viewer to re-pivot in-place.", "ok");
}

async function main() {
  reportIsolation();
  const token = sessionStorage.getItem("gh_token");
  if (!token) {
    showSignedOut();
    return;
  }
  try {
    const user = await fetchGithubUser(token);
    showSignedIn(`${user.login}`);
  } catch (e) {
    log(`github /user failed: ${e.message} -- token expired? sign in again.`, "err");
    sessionStorage.removeItem("gh_token");
    showSignedOut();
    return;
  }

  log("booting DuckDB-Wasm ...");
  const { conn } = await bootDuckDB();
  log("DuckDB-Wasm ready");

  try {
    await loadExtensions(conn);
    const arrow = await attachAndQuery(conn, token);
    await renderPivot(arrow);
  } catch (e) {
    log(`failure: ${e.message}`, "err");
    console.error(e);
  }
}

main().catch((e) => log(`fatal: ${e.message}`, "err"));
