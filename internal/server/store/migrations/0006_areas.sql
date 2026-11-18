-- Areas: devices, enrollment tokens and users belong to areas. Superadmins
-- see everything; other users only the areas they are a member of.
CREATE TABLE areas (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    oidc_group TEXT,                       -- members of this OIDC group belong to the area
    recipients TEXT NOT NULL DEFAULT '',   -- comma separated alert mail recipients
    created_at INTEGER NOT NULL
);
INSERT INTO areas(id, name, created_at) VALUES (1, 'Default', CAST(strftime('%s', 'now') AS INTEGER));

-- source: 'manual' (assigned in the UI) or 'oidc' (from the OIDC group,
-- synchronised at every login). Both can exist for the same area.
CREATE TABLE user_areas (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    area_id INTEGER NOT NULL REFERENCES areas(id) ON DELETE CASCADE,
    source  TEXT NOT NULL,
    PRIMARY KEY (user_id, area_id, source)
);
CREATE INDEX user_areas_area ON user_areas(area_id);

-- Every existing user could do everything so far.
ALTER TABLE users ADD COLUMN superadmin INTEGER NOT NULL DEFAULT 0;
UPDATE users SET superadmin = 1;

ALTER TABLE devices ADD COLUMN area_id INTEGER NOT NULL DEFAULT 1;
CREATE INDEX devices_area ON devices(area_id);
ALTER TABLE enrollment_tokens ADD COLUMN area_id INTEGER NOT NULL DEFAULT 1;
-- NULL: global entry (only visible to superadmins).
ALTER TABLE audit_log ADD COLUMN area_id INTEGER;
