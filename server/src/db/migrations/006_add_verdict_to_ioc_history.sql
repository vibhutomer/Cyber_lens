-- adding verdict to ioc_history

ALTER TABLE ioc_history
ADD COLUMN verdict TEXT;
