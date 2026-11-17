-- Latest diagnostics reported by each agent with its check-in.
CREATE TABLE agent_diagnostics (
    device_id   TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    received_at INTEGER NOT NULL,
    data        TEXT NOT NULL
);
