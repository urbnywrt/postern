-- The import of a node of the legacy mtproto-node stack (slice 4, Task 5; spec
-- section 10). 0011 belongs to slice 6.
--
-- nodes.standby marks a node whose proxies were imported from the legacy
-- stack that still serves them on the same host: the node runs everything on
-- loopback and binds none of the public listeners until the takeover (Task 6
-- sends it as NodeSettings.standby). 1 from the import until the takeover.
--
-- proxies.web_public_addr is the public IPv4 address of a WEB proxy as the
-- legacy stack baked it into public_addr (webPublicIp, else WEB_BIND_IP, else
-- PUBLIC_IP); the state carries it as WebSettings.public_addr. "" leaves the
-- choice to the node.

ALTER TABLE nodes ADD COLUMN standby INTEGER NOT NULL DEFAULT 0 CHECK (standby IN (0, 1));

ALTER TABLE proxies ADD COLUMN web_public_addr TEXT NOT NULL DEFAULT '';
