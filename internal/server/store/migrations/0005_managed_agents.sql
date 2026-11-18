-- Agents updated by something else than this server ("home-assistant").
ALTER TABLE devices ADD COLUMN managed TEXT;
