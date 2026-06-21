CREATE TABLE deploys (
    id                TEXT PRIMARY KEY,
    app               TEXT NOT NULL,
    image             TEXT NOT NULL,
    tag               TEXT NOT NULL,
    status            TEXT NOT NULL,
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    error             TEXT,
    triggered_by      TEXT NOT NULL,
    new_container_id  TEXT,
    new_port          INTEGER,
    new_pod_name      TEXT,
    new_manifest_path TEXT
) STRICT;
