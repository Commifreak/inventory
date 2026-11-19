-- Value of a step-notified alert (e.g. SSD wear in percent) at its last
-- notification; the next mail is sent when the value reaches the next step.
ALTER TABLE alerts ADD COLUMN notified_value REAL;
