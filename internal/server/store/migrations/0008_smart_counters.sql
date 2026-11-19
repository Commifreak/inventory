-- Further SMART counters for "increasing" alert rules.
ALTER TABLE smart_history ADD COLUMN unsafe_shutdowns INTEGER;
ALTER TABLE smart_history ADD COLUMN reported_uncorrect INTEGER;
ALTER TABLE smart_history ADD COLUMN command_timeout INTEGER;
ALTER TABLE smart_history ADD COLUMN spin_retry INTEGER;
