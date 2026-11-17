CREATE TABLE users (
    id                   INTEGER PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash        TEXT,
    oidc_subject         TEXT UNIQUE,
    email                TEXT,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    disabled             INTEGER NOT NULL DEFAULT 0,
    created_at           INTEGER NOT NULL,
    last_login_at        INTEGER
);

CREATE TABLE sessions (
    id_hash    TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip         TEXT,
    user_agent TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE enrollment_tokens (
    id           INTEGER PRIMARY KEY,
    token        TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    last_used_at INTEGER,
    use_count    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE devices (
    id                  TEXT PRIMARY KEY,
    hostname            TEXT NOT NULL,
    display_name        TEXT,
    os                  TEXT NOT NULL,
    arch                TEXT NOT NULL,
    hardware_id         TEXT,
    machine_id          TEXT,
    credential_hash     TEXT NOT NULL,
    enrollment_token_id INTEGER,
    enrolled_at         INTEGER NOT NULL,
    last_seen_at        INTEGER,
    last_ip             TEXT,
    agent_version       TEXT,
    boot_time           INTEGER,
    clock_skew_sec      INTEGER,
    os_name             TEXT,
    ring                TEXT NOT NULL DEFAULT 'stable',
    pinned_version      TEXT,
    update_now_version  TEXT,
    update_target       TEXT,
    update_state        TEXT,
    update_error        TEXT,
    update_changed_at   INTEGER,
    collect_now         TEXT,
    offline_alert_hours INTEGER,
    alerts_muted        INTEGER NOT NULL DEFAULT 0,
    notes               TEXT,
    revoked_at          INTEGER
);
CREATE INDEX devices_hw ON devices(hardware_id);
CREATE INDEX devices_machine ON devices(machine_id);

CREATE TABLE snapshots (
    device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    collector    TEXT NOT NULL,
    collected_at INTEGER NOT NULL,
    received_at  INTEGER NOT NULL,
    duration_ms  INTEGER,
    error        TEXT,
    warnings     TEXT,
    data         TEXT,
    PRIMARY KEY (device_id, collector)
);

CREATE TABLE smart_history (
    device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    serial          TEXT NOT NULL,
    day             TEXT NOT NULL,
    ts              INTEGER NOT NULL,
    health_passed   INTEGER,
    temperature     INTEGER,
    power_on_hours  INTEGER,
    reallocated     INTEGER,
    pending         INTEGER,
    uncorrectable   INTEGER,
    crc_errors      INTEGER,
    percent_used    INTEGER,
    available_spare INTEGER,
    media_errors    INTEGER,
    PRIMARY KEY (device_id, serial, day)
);

CREATE TABLE software_changes (
    id          INTEGER PRIMARY KEY,
    device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts          INTEGER NOT NULL,
    change      TEXT NOT NULL,
    name        TEXT NOT NULL,
    source      TEXT,
    scope       TEXT,
    version_old TEXT,
    version_new TEXT
);
CREATE INDEX software_changes_device ON software_changes(device_id, ts);

CREATE TABLE events (
    device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    kind        TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    source      TEXT,
    event_id    INTEGER,
    disk        TEXT,
    message     TEXT,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, key)
);
CREATE INDEX events_device_ts ON events(device_id, ts);

CREATE TABLE alerts (
    id               INTEGER PRIMARY KEY,
    device_id        TEXT REFERENCES devices(id) ON DELETE CASCADE,
    rule             TEXT NOT NULL,
    subject          TEXT NOT NULL DEFAULT '',
    severity         TEXT NOT NULL,
    state            TEXT NOT NULL,
    message          TEXT NOT NULL,
    opened_at        INTEGER NOT NULL,
    last_seen_at     INTEGER NOT NULL,
    resolved_at      INTEGER,
    last_notified_at INTEGER,
    notify_count     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX alerts_state ON alerts(state);
CREATE UNIQUE INDEX alerts_open_unique ON alerts(device_id, rule, subject) WHERE state = 'open';

CREATE TABLE agent_update_log (
    id           INTEGER PRIMARY KEY,
    device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts           INTEGER NOT NULL,
    from_version TEXT,
    to_version   TEXT,
    success      INTEGER NOT NULL,
    error        TEXT
);

CREATE TABLE audit_log (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    username TEXT,
    action   TEXT NOT NULL,
    details  TEXT
);

-- Tracks since when a condition holds (e.g. reboot pending since).
CREATE TABLE device_flags (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    flag      TEXT NOT NULL,
    since     INTEGER NOT NULL,
    PRIMARY KEY (device_id, flag)
);
