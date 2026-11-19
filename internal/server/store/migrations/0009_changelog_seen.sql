-- When a user last dismissed the "What's new" notice (NULL: not yet; shows
-- the changes of the current release).
ALTER TABLE users ADD COLUMN changelog_seen_at INTEGER;
