-- Events on USB/removable disks are flagged so alert rules can ignore them.
ALTER TABLE events ADD COLUMN external INTEGER NOT NULL DEFAULT 0;
