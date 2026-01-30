# PLC Replica Service

The `replica` command implements a `did:plc` read-replica service that syncs operations from an upstream PLC directory service, and exposes the standard HTTP APIs for resolving and auditing DID documents.

It performs full cryptographic validation of all inbound PLC operations, including enforcing constraints around operation nullification.

```
NAME:
   replica - PLC directory replica server

USAGE:
   replica [global options]

GLOBAL OPTIONS:
   --postgres-url string            PostgreSQL connection string (if set, uses Postgres instead of SQLite) [$POSTGRES_URL]
   --sqlite-path string             SQLite database file path (used when --postgres-url is not set) (default: "replica.db") [$SQLITE_PATH]
   --http-addr string               HTTP server listen address (default: ":8080") [$HTTP_ADDR]
   --metrics-addr string            Metrics HTTP server listen address (default: ":9464") [$METRICS_ADDR]
   --no-ingest                      Disable ingestion from upstream directory (default: false) [$NO_INGEST]
   --upstream-directory-url string  Upstream PLC directory base URL (default: "https://plc.directory") [$UPSTREAM_DIRECTORY_URL]
   --cursor-override int            Starting cursor (sequence number) for ingestion (default: -1) [$CURSOR_OVERRIDE]
   --num-workers int                Number of validation worker threads (0 = auto) (default: 0) [$NUM_WORKERS]
   --log-level string               Log level (debug, info, warn, error) (default: "info") [$LOG_LEVEL]
   --log-json                       Output logs in JSON format (default: false) [$LOG_JSON]
   --help, -h                       show help
```

## HTTP API

It exposes the following endpoints, as described in the `did:plc` [spec](https://web.plc.directory/spec/v0.1/did-plc)

- `GET /{did}` (see Format Differences below)
- `GET /{did}/data`
- `GET /{did}/log`
- `GET /{did}/log/audit`
- `GET /{did}/log/last`

Actually, some of these aren't mentioned in the spec, but they are in the [API docs](https://web.plc.directory/api/redoc) and implemented by the [reference implementation](https://github.com/did-method-plc/did-method-plc/tree/main/packages/server).

It does not support POSTing DID updates to `/{did}` - it only discovers new operations by importing from the upstream instance.

It does not currently implement the `/export` and `/export/stream` endpoints, although it may in the future.

### DID Document Format Differences

The reference implementation returns DID documents in `application/did+ld+json` format, whereas this replica returns them in `application/did+json` format. Both are described in the [DID specification](https://www.w3.org/TR/did-1.0/), but in practical terms the difference is that the `@context` field is missing.

Secondarily, service identifiers include the DID ([relevant issue](https://github.com/did-method-plc/did-method-plc/issues/90))

Although these differences are spec-compliant, some PLC client libraries may have trouble with these differences.


## Databases

The service supports either PostgreSQL or SQLite. Postgres has more horizontal scaling headroom on the read path, but SQLite performs better when backfilling.

## Backfilling

When the service is started for the first time, it has to "backfill" the entire PLC operation history from the upstream instance. Until it "catches up", it will not provide up-to-date responses to queries. Depending on your hardware, it should take less than 24h to complete a backfill (at time of writing). Backfilling tends to be bottlenecked by database throughput.
