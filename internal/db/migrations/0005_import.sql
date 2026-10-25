CREATE TABLE import_runs (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    source TEXT NOT NULL,
    report TEXT NOT NULL
);
CREATE INDEX import_runs_finished_idx ON import_runs(finished_at);
