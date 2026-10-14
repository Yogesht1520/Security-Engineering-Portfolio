-- Threat Intelligence IP Blacklisting Engine — SQLite Schema
-- ==============================================================

CREATE TABLE IF NOT EXISTS scored_ips (
    ip              TEXT    PRIMARY KEY,
    combined_score  REAL    NOT NULL,
    sources         TEXT    NOT NULL,   -- JSON array: ["abuseipdb","spamhaus"]
    category        TEXT    NOT NULL,
    first_seen      TEXT    NOT NULL,   -- ISO-8601 UTC string: First time IP was observed
    last_seen       TEXT,               -- ISO-8601 UTC string: Most recent appearance
    last_confirmed  TEXT,               -- ISO-8601 UTC string: Most recent corroboration
    last_updated    TEXT    NOT NULL,   -- ISO-8601 UTC string
    expires_at      TEXT    NOT NULL,   -- ISO-8601 UTC string
    source_count    INTEGER NOT NULL DEFAULT 1,
    status          TEXT    NOT NULL DEFAULT 'blocked', -- 'candidate' | 'blocked' | 'expired' | 'revoked'
    reason          TEXT    NOT NULL DEFAULT '',
    evidence_json   TEXT    NOT NULL DEFAULT '[]',
    enforced        INTEGER NOT NULL DEFAULT 0  -- 1 = currently in enforcement point
);

CREATE INDEX IF NOT EXISTS idx_expires_at ON scored_ips(expires_at);
CREATE INDEX IF NOT EXISTS idx_enforced   ON scored_ips(enforced);

CREATE TABLE IF NOT EXISTS feed_health (
    feed_name           TEXT    PRIMARY KEY,
    status              TEXT    NOT NULL,   -- 'Healthy' | 'Degraded' | 'Failed'
    last_sync_utc       TEXT    NOT NULL,
    duration_ms         REAL    NOT NULL,
    indicators_received INTEGER NOT NULL,
    rejected_count      INTEGER NOT NULL DEFAULT 0,
    error_message       TEXT
);
