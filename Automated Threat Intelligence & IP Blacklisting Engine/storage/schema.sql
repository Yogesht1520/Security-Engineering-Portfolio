-- Threat Intelligence IP Blacklisting Engine — SQLite Schema
-- ==============================================================

CREATE TABLE IF NOT EXISTS scored_ips (
    ip              TEXT    PRIMARY KEY,
    combined_score  REAL    NOT NULL,
    sources         TEXT    NOT NULL,   -- JSON array: ["abuseipdb","spamhaus"]
    category        TEXT    NOT NULL,
    first_seen      TEXT    NOT NULL,   -- ISO-8601 UTC string
    last_updated    TEXT    NOT NULL,   -- ISO-8601 UTC string
    expires_at      TEXT    NOT NULL,   -- ISO-8601 UTC string
    enforced        INTEGER NOT NULL DEFAULT 0  -- 1 = currently in enforcement point
);

CREATE INDEX IF NOT EXISTS idx_expires_at ON scored_ips(expires_at);
CREATE INDEX IF NOT EXISTS idx_enforced   ON scored_ips(enforced);
