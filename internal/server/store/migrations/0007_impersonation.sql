-- Support sessions: a superadmin signed in as another user. The session
-- belongs to the impersonated user; impersonator_id is the superadmin.
ALTER TABLE sessions ADD COLUMN impersonator_id INTEGER REFERENCES users(id) ON DELETE CASCADE;

-- "My tokens" are the tokens of the areas a user is a member of. Existing
-- superadmins become members of the first area (usually "Default"), which
-- holds all devices and tokens from before areas existed.
INSERT OR IGNORE INTO user_areas(user_id, area_id, source)
SELECT u.id, (SELECT MIN(id) FROM areas), 'manual' FROM users u
WHERE u.superadmin = 1 AND EXISTS (SELECT 1 FROM areas);
