-- SLIP-106: managed services framework (Part 1/3 -- persistence foundation).
--
-- Three STRICT tables with explicit boundaries:
--   slip_metadata  -- persistent installation ID (key/value).
--   services       -- exportable desired state (maps 1:1 to [services.<name>]).
--   service_state  -- internal control/observed state (never exported).
--
-- Secret values are NEVER stored in SQLite -- only an opaque `secret_ref` in
-- `service_state`. The filesystem secrets store owns the value.
--
-- `service_state` intentionally has NO cascade FK to `services`: a normal
-- removal deletes the desired row but retains the control row (phase
-- 'retained') so the data instance can be safely recognized and reattached.
--
-- CHECK constraints mirror the Rust validators using SQLite GLOB negation
-- (`[^...]`): closed enums, exact identifier formats (hex, length), bounded
-- lengths, version grammar, canonical secret-ref format, and closed failure
-- codes. Corrupt or tampered rows are rejected at the SQLite level. The
-- Rust row mappers validate cross-field consistency again on read.

CREATE TABLE slip_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE services (
    name        TEXT PRIMARY KEY
        CHECK (length(name) >= 1 AND length(name) <= 63
               AND name NOT GLOB '*[^a-z0-9-]*'
               AND name NOT GLOB '*__*'
               AND name NOT GLOB '*--*'
               AND name NOT GLOB '-*'
               AND name NOT GLOB '*-'),
    provider    TEXT NOT NULL CHECK (provider IN ('postgres')),
    version     TEXT NOT NULL
        CHECK (length(version) >= 3 AND length(version) <= 32
               AND version GLOB '[0-9]*.[0-9]*'
               AND version NOT GLOB '*[^0-9.]*'
               AND version NOT GLOB '*..*'
               AND version NOT GLOB '..*'
               AND version NOT GLOB '*..'),
    config_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(config_json)
               AND json_type(config_json) = 'object'
               AND length(config_json) <= 4096),
    created_at  TEXT NOT NULL CHECK (length(created_at) >= 20 AND length(created_at) <= 64),
    updated_at  TEXT NOT NULL CHECK (length(updated_at) >= 20 AND length(updated_at) <= 64)
) STRICT;

CREATE TABLE service_state (
    service_name      TEXT PRIMARY KEY
        CHECK (length(service_name) >= 1 AND length(service_name) <= 63
               AND service_name NOT GLOB '*[^a-z0-9-]*'
               AND service_name NOT GLOB '*__*'
               AND service_name NOT GLOB '*--*'
               AND service_name NOT GLOB '-*'
               AND service_name NOT GLOB '*-'),
    provider          TEXT NOT NULL CHECK (provider IN ('postgres')),
    data_major        INTEGER NOT NULL CHECK (data_major > 0 AND data_major < 100000),
    version           TEXT NOT NULL
        CHECK (length(version) >= 3 AND length(version) <= 32
               AND version GLOB '[0-9]*.[0-9]*'
               AND version NOT GLOB '*[^0-9.]*'
               AND version NOT GLOB '*..*'
               AND version NOT GLOB '..*'
               AND version NOT GLOB '*..'),
    instance_id       TEXT NOT NULL UNIQUE
        CHECK (length(instance_id) = 32
               AND instance_id NOT GLOB '*[^0-9a-f]*'),
    generation        INTEGER NOT NULL CHECK (generation > 0),
    phase             TEXT NOT NULL CHECK (phase IN
        ('provisioning','ready','deleting','retained','blocked','error')),
    container_id      TEXT
        CHECK (container_id IS NULL OR
               (length(container_id) = 64
                AND container_id NOT GLOB '*[^0-9a-f]*')),
    resolved_image    TEXT NOT NULL CHECK (length(resolved_image) >= 1 AND length(resolved_image) <= 512),
    applied_spec_hash TEXT
        CHECK (applied_spec_hash IS NULL OR
               (length(applied_spec_hash) = 64
                AND applied_spec_hash NOT GLOB '*[^0-9a-f]*')),
    secret_ref        TEXT NOT NULL
        CHECK (length(secret_ref) >= 10 AND length(secret_ref) <= 256
               AND secret_ref GLOB 'service/[0-9a-f]*/[a-z_]*'
               AND secret_ref NOT GLOB '*[^0-9a-f/a-z_-]*'
               AND secret_ref NOT GLOB '*..*'
               AND secret_ref NOT GLOB '* *'),
    health            TEXT
        CHECK (health IS NULL OR health IN ('healthy','unhealthy','starting','unknown')),
    last_error        TEXT
        CHECK (last_error IS NULL OR last_error IN
            ('provision_failed','health_timeout','ownership_mismatch',
             'filesystem_check','image_pull_failed','readiness_failed','internal')),
    last_checked_at   TEXT CHECK (last_checked_at IS NULL OR (length(last_checked_at) >= 20 AND length(last_checked_at) <= 64)),
    updated_at        TEXT NOT NULL CHECK (length(updated_at) >= 20 AND length(updated_at) <= 64)
) STRICT;