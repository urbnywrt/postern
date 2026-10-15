-- Why a node does not run the state that the panel wants it to (the final
-- review of slices 0 and 1, I1(b)): two texts that the panel shows with the
-- node, both empty while all is well.
--
--   last_error       why the last reconcile pass of the node failed, as its
--                    state report says (StateReport.last_error): Docker not
--                    answering, the edge refusing its configuration. It is
--                    cleared by the first report of a pass that went through.
--   state_rejection  why the node refused the desired state that the panel
--                    sent it (ApplyStateResponse.reason). It is cleared when
--                    the node has the desired generation of the panel.

ALTER TABLE nodes ADD COLUMN last_error TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN state_rejection TEXT NOT NULL DEFAULT '';
