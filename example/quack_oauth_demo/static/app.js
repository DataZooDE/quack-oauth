// quack-oauth demo client.
//
// Flow:
//   1. Read sessionStorage.oauth_token (set by /oauth/callback). If absent,
//      show the sign-in pane and stop.
//   2. Bootstrap DuckDB-Wasm with custom_extension_repository = get.erpl.io.
//   3. INSTALL/LOAD quack and quack_oauth.
//   4. ATTACH 'quack:localhost:<page-port>' AS srv (token '<ya29.*>').
//      The wasm client posts to /quack on this same origin -- aiohttp
//      reverse-proxies that to the in-process quack listener. The server
//      validates the token via Google's tokeninfo endpoint.
//   5. SELECT into an Arrow table, hand the IPC bytes to a Perspective
//      Worker. When the browser is in a cross-origin-isolated context
//      (the aiohttp COOP/COEP headers achieve this), the handoff uses
//      SharedArrayBuffer and is true zero-copy.
//   6. Render <perspective-viewer> with a default pivot. The user
//      drags row/col/measure inside Perspective -- those re-pivots
//      run entirely in Perspective's WASM, no extra queries.

import * as duckdb from "https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@1.33.1-dev53.0/+esm";
import perspective from "https://cdn.jsdelivr.net/npm/@finos/perspective@3/dist/cdn/perspective.js";

// Perspective + plugin custom-element registrations happen via the
// `<script type="module">` tags in index.html. Those load
// asynchronously, so we wait for the viewer custom element to be
// defined before touching it.
async function waitForViewerCE() {
  await customElements.whenDefined("perspective-viewer");
}

const QUACK_URI = `quack:${location.hostname}:${location.port || "80"}`;
const $log = document.getElementById("boot-log");

function log(msg, cls = "") {
  // Defend against giant messages -- Perspective + DuckDB-Wasm errors
  // sometimes embed the entire offending payload, which blows up the
  // narrow log pane. Full message still goes to the JS console.
  const text = String(msg);
  const shown = text.length > 240 ? text.slice(0, 240) + ` ... (+${text.length - 240} chars; see console)` : text;
  const line = document.createElement("div");
  if (cls) line.className = cls;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${shown}`;
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
    sessionStorage.removeItem("oauth_token");
    location.reload();
  };
}

// Persist + restore the log pane's width. The drag handle lives
// between the log and the viewer (see index.html); on mousedown we
// track the pointer and resize the log until release.
function wireResizeHandle() {
  const handle = document.getElementById("resize-handle");
  const logEl = document.getElementById("boot-log");
  if (!handle || !logEl) return;

  const stored = parseInt(localStorage.getItem("logPaneWidthPx") || "0", 10);
  if (stored > 120 && stored < 1200) {
    logEl.style.width = `${stored}px`;
  }

  let startX = 0;
  let startW = 0;

  function onMove(ev) {
    const dx = ev.clientX - startX;
    const next = Math.max(180, Math.min(1200, startW + dx));
    logEl.style.width = `${next}px`;
  }
  function onUp() {
    document.removeEventListener("mousemove", onMove);
    document.removeEventListener("mouseup", onUp);
    document.body.classList.remove("is-resizing");
    handle.classList.remove("dragging");
    localStorage.setItem("logPaneWidthPx", parseInt(logEl.offsetWidth, 10));
  }
  handle.addEventListener("mousedown", (ev) => {
    startX = ev.clientX;
    startW = logEl.offsetWidth;
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
    document.body.classList.add("is-resizing");
    handle.classList.add("dragging");
    ev.preventDefault();
  });
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

async function fetchGoogleUser(token) {
  // Google's OpenID Connect UserInfo. Returns {sub, name, email, picture, ...}.
  // sub is the stable numeric Google account id (also what tokeninfo
  // returns; the server-side audit row's `subject` will match).
  const r = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error(`google userinfo returned ${r.status}`);
  return r.json();
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

async function attachServer(conn, token) {
  // SQL-injection note: the token is a Google OAuth access token
  // (regex `^ya29\.[\w\-.]+$`). The ATTACH ... TYPE quack form
  // doesn't accept parameter binding for option values, so we
  // pre-validate the shape and inline.
  if (!/^ya29\.[A-Za-z0-9_\-.]+$/.test(token)) {
    throw new Error("token does not look like a Google OAuth access token (ya29.*)");
  }
  log(`ATTACH '${QUACK_URI}' AS srv (TYPE quack, token '<ya29...>')`);
  await conn.query(
    `ATTACH '${QUACK_URI}' AS srv (TYPE quack, token '${token}')`
  );
}

// Fetch only the column types of trips_enriched. Zero data rows.
async function fetchSchema(conn) {
  log("fetching schema (LIMIT 0) ...");
  const t0 = performance.now();
  const tbl = await conn.query(
    "SELECT * FROM srv.main.trips_enriched LIMIT 0"
  );
  log(`  ${tbl.schema.fields.length} columns in ${(performance.now() - t0).toFixed(0)} ms`, "ok");
  return tbl;
}

// Map an Apache Arrow type to a Perspective schema type literal.
// Perspective recognises: "string" | "integer" | "float" | "boolean"
// | "date" | "datetime". We collapse Arrow's many numeric variants
// into integer/float and the rest into string by default.
function arrowToPspType(dataType) {
  const s = String(dataType);
  if (s === "Bool") return "boolean";
  if (s.startsWith("Int") || s.startsWith("Uint")) return "integer";
  if (s.startsWith("Float") || s === "Decimal" || s.startsWith("Decimal"))
    return "float";
  if (s === "Date") return "date";
  if (s.startsWith("Timestamp")) return "datetime";
  return "string"; // Utf8, LargeUtf8, Binary, …
}

// Perspective aggregate -> DuckDB SQL aggregate. Falls back to "sum"
// for anything we haven't taught.
const AGG_MAP = {
  sum: "SUM", avg: "AVG", mean: "AVG", count: "COUNT",
  min: "MIN", max: "MAX", median: "MEDIAN",
  any: "ANY_VALUE", dominant: "MODE",
  distinct_count: "COUNT(DISTINCT {0})", // sentinel; handled below
  unique: "COUNT(DISTINCT {0})",
};

function sqlAggExpr(perspectiveAgg, column) {
  const ident = `"${column.replace(/"/g, '""')}"`;
  const fn = AGG_MAP[perspectiveAgg];
  if (!fn) return `SUM(${ident})`;
  if (fn.includes("{0}")) return fn.replace("{0}", ident);
  return `${fn}(${ident})`;
}

function ident(col) {
  return `"${col.replace(/"/g, '""')}"`;
}

// Build the SQL we send to the server given the viewer's current config.
function buildSql(config) {
  const groupBy = config.group_by || [];
  const splitBy = config.split_by || [];
  const columns = (config.columns || []).filter(Boolean);
  const aggregates = config.aggregates || {};

  // No grouping at all -> single-row totals over the entire dataset.
  if (groupBy.length === 0 && splitBy.length === 0) {
    if (columns.length === 0) {
      return "SELECT COUNT(*) AS row_count FROM srv.main.trips_enriched";
    }
    const exprs = columns.map(
      (c) => `${sqlAggExpr(aggregates[c], c)} AS ${ident(c)}`
    );
    return `SELECT ${exprs.join(", ")} FROM srv.main.trips_enriched`;
  }

  // group_by + split_by all become GROUP BY dimensions on the server.
  // Perspective will then pivot the split_by columns client-side over
  // the already-aggregated result -- a fully-correct rendering with
  // tiny data over the wire.
  const dims = [...groupBy, ...splitBy].map(ident);

  const measureExprs = columns.length
    ? columns.map((c) => `${sqlAggExpr(aggregates[c], c)} AS ${ident(c)}`)
    : ["COUNT(*) AS row_count"];

  const orderBy = dims.length ? `ORDER BY ${dims.join(", ")}` : "";

  return `
    SELECT ${dims.join(", ")}, ${measureExprs.join(", ")}
    FROM srv.main.trips_enriched
    GROUP BY ${dims.join(", ")}
    ${orderBy}
  `.trim().replace(/\s+/g, " ");
}

async function setupPivot(conn, schemaTable) {
  const psp = await perspective.worker();

  // Build the Perspective schema from the FULL source schema so the
  // viewer's "All Columns" shelf always exposes every dim and
  // measure available on the server -- regardless of which subset
  // the current SQL result happens to carry. This is the key to
  // keeping the pivot UI useful: the user drags ANY of the 26
  // source columns into Group By / Split By / Columns and we
  // re-query the server accordingly.
  const sourceFieldNames = schemaTable.schema.fields.map((f) => f.name);
  const pspSchema = {};
  for (const f of schemaTable.schema.fields) {
    pspSchema[f.name] = arrowToPspType(f.type);
  }
  const pTable = await psp.table(pspSchema);

  const viewer = document.getElementById("viewer");
  await viewer.load(pTable);

  // Default plugin = Datagrid (always registered). The d3fc plugins
  // are loaded asynchronously via index.html <script> tags, so by
  // the time you click the plugin dropdown they'll be there: X Bar,
  // Y Bar, X/Y Line, X/Y Area, X/Y Scatter, Heatmap, Treemap,
  // Sunburst, Candlestick, OHLC. We default to Datagrid because
  // restoring a plugin that hasn't finished registering yet hangs
  // the viewer.
  const initialColumns = ["fare_usd", "tip_usd", "total_usd", "trip_minutes", "tip_pct"];
  const initialConfig = {
    plugin: "Datagrid",
    group_by: ["pickup_borough", "rate_code"],
    split_by: ["vendor"],
    columns: initialColumns,
    aggregates: Object.fromEntries(initialColumns.map((c) => [c, "avg"])),
    theme: "Pro Dark",
  };
  await viewer.restore(initialConfig);

  // Refetch coordinator. The pTable's schema NEVER changes (it
  // mirrors the source's 26 columns), so we always go through
  // `pTable.replace(rows)`. That avoids viewer.load() entirely,
  // which means no feedback loop AND the "All Columns" shelf never
  // shrinks.
  //
  //   1. Only one query in flight at a time; coalesce overlaps.
  //   2. We still suppress events while replace() runs because
  //      Perspective's internal view recomputes can race with
  //      pending config-update events.
  let inFlight = false;
  let queued = false;
  let suppressUpdates = 0;

  async function refetch(reason) {
    if (inFlight) { queued = true; return; }
    inFlight = true;
    try {
      const config = await viewer.save();
      const sql = buildSql(config);
      log(`[${reason}] ${sql}`);

      const t0 = performance.now();
      const result = await conn.query(sql);
      const dt = performance.now() - t0;

      // Extract result columns into plain arrays (cross the
      // apache-arrow-module-instance boundary as bare data -- see
      // the long comment in the previous render path for why this
      // matters).
      const resultCols = {};
      for (const f of result.schema.fields) {
        resultCols[f.name] = result.getChild(f.name).toArray();
      }

      // Build row-form JSON spanning the FULL source schema. Each
      // row has all 26 keys; columns the SQL didn't touch are null.
      // Perspective accepts row JSON and reconciles values against
      // the pTable's already-declared schema (no class identity
      // issues, no type inference surprises).
      const rows = new Array(result.numRows);
      for (let i = 0; i < result.numRows; i++) {
        const row = {};
        for (const name of sourceFieldNames) {
          const col = resultCols[name];
          row[name] = col !== undefined ? col[i] : null;
        }
        rows[i] = row;
      }

      suppressUpdates++;
      try {
        await pTableRef.replace(rows);
        // Flush so any pending config-update events from internal
        // view recomputes land while we're still suppressing.
        await new Promise((r) => setTimeout(r, 0));
      } finally {
        suppressUpdates--;
      }

      log(`  ${result.numRows.toLocaleString()} rows in ${dt.toFixed(0)} ms`, "ok");
    } catch (e) {
      log(`refetch failed: ${e.message}`, "err");
      console.error(e);
    } finally {
      inFlight = false;
      if (queued) { queued = false; refetch("queued"); }
    }
  }

  // Single, stable Perspective table reference (same one for the
  // life of the page); `replace(rows)` is the only path to update
  // its data.
  const pTableRef = pTable;

  // Debounce drag operations: the viewer fires one config-update per
  // chip move; we want one SQL query per user-perceived gesture.
  let debounce;
  viewer.addEventListener("perspective-config-update", () => {
    if (suppressUpdates > 0) return; // our own load/restore -- not a user action
    clearTimeout(debounce);
    debounce = setTimeout(() => refetch("config-update"), 200);
  });

  // Initial fetch. The first refetch will go through the
  // "schema changed" branch and replace the empty schema-only table.
  await refetch("initial");

  log("pivot ready. drag dimensions in the viewer to re-pivot via SQL.", "ok");
}

async function main() {
  reportIsolation();
  wireResizeHandle();
  const token = sessionStorage.getItem("oauth_token");
  if (!token) {
    showSignedOut();
    return;
  }
  try {
    const user = await fetchGoogleUser(token);
    showSignedIn(user.email || user.name || user.sub);
  } catch (e) {
    log(`google userinfo failed: ${e.message} -- token expired? sign in again.`, "err");
    sessionStorage.removeItem("oauth_token");
    showSignedOut();
    return;
  }

  log("waiting for <perspective-viewer> to register ...");
  await waitForViewerCE();
  log("  registered", "ok");

  log("booting DuckDB-Wasm ...");
  const { conn } = await bootDuckDB();
  log("DuckDB-Wasm ready");

  try {
    await loadExtensions(conn);
    await attachServer(conn, token);
    const schemaTable = await fetchSchema(conn);
    await setupPivot(conn, schemaTable);
  } catch (e) {
    log(`failure: ${e.message}`, "err");
    console.error(e);
  }
}

main().catch((e) => log(`fatal: ${e.message}`, "err"));
