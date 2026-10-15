-- Where a node gets the engine and provider binaries (slice 5, R5-1): 'panel'
-- uploads them (UploadArtifact), 'direct' has the node download them from
-- their release itself (ArtifactRef.url), with the panel uploading what the
-- node still lacks at its next resync.

ALTER TABLE nodes ADD COLUMN artifact_source TEXT NOT NULL DEFAULT 'panel'
  CHECK (artifact_source IN ('panel', 'direct'));
