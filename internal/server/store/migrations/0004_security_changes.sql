-- Rules disabled for a single device (comma separated rule IDs).
ALTER TABLE devices ADD COLUMN disabled_rules TEXT;

-- Items ever seen on a device (local administrators, autostart entries,
-- Defender exclusions) to detect new ones. The empty item marks that a
-- baseline exists for the kind.
CREATE TABLE seen_items (
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    item       TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    PRIMARY KEY (device_id, kind, item)
);
