"""NYC TLC yellow-taxi loader.

Downloads one month of trip data + the zone lookup once into
`example/cache/` and exposes a flat enriched view that the wasm
client pivots over.

Public sources (TLC CloudFront, no auth needed):
  - yellow_tripdata_2024-01.parquet  ~ 50 MB,  ~3 M rows
  - taxi_zone_lookup.csv             ~  5 KB,    265 rows
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

import duckdb

CACHE_DIR = Path(__file__).resolve().parents[1] / "cache"

TRIPS_URL = "https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2024-01.parquet"
ZONES_URL = "https://d37ci6vzurychx.cloudfront.net/misc/taxi_zone_lookup.csv"

TRIPS_FILE = CACHE_DIR / "yellow_tripdata_2024-01.parquet"
ZONES_FILE = CACHE_DIR / "taxi_zone_lookup.csv"


def _download_once(url: str, target: Path) -> None:
    if target.exists() and target.stat().st_size > 0:
        return
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"  downloading {url} -> {target} ...", flush=True)
    tmp = target.with_suffix(target.suffix + ".part")
    urllib.request.urlretrieve(url, tmp)
    tmp.rename(target)
    print(f"  cached: {target.stat().st_size // (1024 * 1024)} MB", flush=True)


def ensure_loaded(conn: duckdb.DuckDBPyConnection) -> None:
    """Cache the parquet + CSV locally, materialise demo tables and a
    flat `trips_enriched` view the client SELECTs over.

    Materialised (not view) because the client's `SELECT * FROM srv.main.trips_enriched`
    pulls the enriched columns over the wire -- a real table lets the
    quack scan use a single columnar fetch instead of evaluating the
    view per query.
    """
    print("[taxi_data] ensuring cache + tables ...", flush=True)
    try:
        _download_once(TRIPS_URL, TRIPS_FILE)
        _download_once(ZONES_URL, ZONES_FILE)
    except Exception as e:
        print(f"  FAIL: {e}", file=sys.stderr)
        raise

    conn.execute(
        f"CREATE OR REPLACE TABLE main.zones AS "
        f"SELECT LocationID, Borough, Zone, service_zone "
        f"FROM read_csv('{ZONES_FILE.as_posix()}', header=true, AUTO_DETECT=true)"
    )

    # Project to the columns the pivot UI needs. Filter obviously-bad rows
    # so the pivot's default aggregates aren't dominated by outliers.
    conn.execute(
        f"""
        CREATE OR REPLACE TABLE main.trips_enriched AS
        SELECT
            t.tpep_pickup_datetime                              AS pickup_ts,
            EXTRACT(HOUR FROM t.tpep_pickup_datetime)::INTEGER  AS hour_of_day,
            DAYNAME(t.tpep_pickup_datetime)                     AS day_of_week,
            t.passenger_count::INTEGER                          AS passengers,
            t.trip_distance::DOUBLE                             AS trip_miles,
            t.fare_amount::DOUBLE                               AS fare_usd,
            t.tip_amount::DOUBLE                                AS tip_usd,
            t.total_amount::DOUBLE                              AS total_usd,
            CASE t.payment_type
                WHEN 1 THEN 'credit_card'
                WHEN 2 THEN 'cash'
                WHEN 3 THEN 'no_charge'
                WHEN 4 THEN 'dispute'
                ELSE 'other'
            END                                                  AS payment,
            pu.Borough                                           AS pickup_borough,
            pu.Zone                                              AS pickup_zone,
            dz.Borough                                           AS dropoff_borough,
            dz.Zone                                              AS dropoff_zone
        FROM read_parquet('{TRIPS_FILE.as_posix()}') t
        JOIN main.zones pu ON t.PULocationID = pu.LocationID
        JOIN main.zones dz ON t.DOLocationID = dz.LocationID
        WHERE t.trip_distance BETWEEN 0.1 AND 50
          AND t.fare_amount  BETWEEN 0   AND 200
          AND t.total_amount BETWEEN 0   AND 500
          AND t.passenger_count BETWEEN 1 AND 6
        """
    )

    n = conn.execute("SELECT count(*) FROM main.trips_enriched").fetchone()[0]
    print(f"[taxi_data] main.trips_enriched ready ({n:,} rows)", flush=True)
