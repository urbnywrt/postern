-- Psiphon egresses run on Psiphon's own client, the component psiphon-core,
-- instead of warp-plus (whose Psiphon mode no longer passes traffic). Its
-- channels start at the built-in version. The rows of warp-plus stay: no
-- component reads them any more, and a panel that is rolled back finds them.

INSERT OR IGNORE INTO engine_channels VALUES
  ('psiphon-core', 'stable', '20261005-c4a09096ab', 0),
  ('psiphon-core', 'latest', '20261005-c4a09096ab', 0);
