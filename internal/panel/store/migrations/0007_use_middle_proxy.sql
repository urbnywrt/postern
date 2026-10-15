-- Whether the engine of a proxy uses the middle proxies of Telegram (slice 4).
-- 'auto' is what every proxy did until now: on when the proxy has an ad tag, off
-- when it has none. 'on' and 'off' are for a proxy that says so itself, such as
-- one imported from a stack that had the setting per proxy. The conventions are
-- those of 0001_init.sql.
ALTER TABLE proxies ADD COLUMN use_middle_proxy TEXT NOT NULL DEFAULT 'auto' CHECK (use_middle_proxy IN ('auto', 'on', 'off'));
