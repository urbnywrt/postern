package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/reconcile"
	"github.com/urbnywrt/postern/internal/node/selfupdate"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/version"
)

const (
	// edgeRollTimeout bounds an UpdateEdge: the roll and the new generation's
	// answer.
	edgeRollTimeout = 120 * time.Second

	evEdgeRollFailed  = "edge_roll_failed"
	evEdgeUpdated     = "edge_updated"
	evHandoffUnsafe   = "edge_handoff_unsafe"
	warnHandoffUnsafe = "edge-handoff-unsafe"
)

// UpdateEdge rolls the edge to the agent binary bin/postern-node-<version>
// (capability "update-edge"). An edge that runs the version and answers is not
// rolled. A version older than the edge's is refused (PermissionDenied) unless
// the request is a rollback to the version the edge ran before its last roll.
// The file is verified as UpdateSelf verifies one (selfupdate.VerifyInstalled:
// the release-key signature UpdateSelf kept beside it, or the running agent's
// own file; a static ELF; "<version> (" from its "version"), and the
// reconciler hashes it again right before the edge mounts it. Otherwise the
// reconciler makes a new generation on it beside the running one
// (reconcile.RollEdge, Ruling 44), and the answer is that generation once it
// answers Health with the version, within 120 s. A roll that fails leaves the
// old generation serving and is Aborted with the reason (event
// edge_roll_failed). One call at a time: a second one is Unavailable.
func (s *Service) UpdateEdge(ctx context.Context, req *connect.Request[nodev1.UpdateEdgeRequest]) (*connect.Response[nodev1.UpdateEdgeResponse], error) {
	s.mu.Lock()
	if s.edgeRolling {
		s.mu.Unlock()
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("another UpdateEdge is running"))
	}
	s.edgeRolling = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.edgeRolling = false
		s.mu.Unlock()
	}()

	if s.rollEdge == nil || s.installer == nil || s.home == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this agent cannot roll its edge"))
	}
	v := req.Msg.GetVersion()
	if !release.ValidVersion(v) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid version %.64q", v))
	}
	running, edgeV, rt := s.runningEdge(ctx)
	if running != 0 && edgeV == v {
		s.log.Info("agent: UpdateEdge: the edge runs this version already", "version", v, "edge_generation", running)
		return connect.NewResponse(&nodev1.UpdateEdgeResponse{Generation: running, Version: v}), nil
	}
	if err := checkEdgeDirection(v, edgeV, rt, req.Msg.GetRollback()); err != nil {
		s.log.Warn("agent: UpdateEdge refused", "version", v, "err", err)
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	}
	// Verified as UpdateSelf verifies a binary (selfupdate.VerifyInstalled).
	path, sum, err := s.installer.VerifyInstalled(ctx, v, s.ownBinary, s.edgeExec)
	if err != nil {
		s.log.Warn("agent: UpdateEdge refused", "version", v, "err", err)
		code := connect.CodeFailedPrecondition
		switch {
		case errors.Is(err, selfupdate.ErrInvalid):
			code = connect.CodeInvalidArgument
		case errors.Is(err, selfupdate.ErrSignature):
			code = connect.CodePermissionDenied
		}
		return nil, connect.NewError(code, err)
	}

	timeout := s.edgeRollTimeout
	if timeout <= 0 {
		timeout = edgeRollTimeout
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// The reconciler hashes the file again right before the edge mounts it.
	gen, err := s.rollEdge(rctx, path, sum)
	if errors.Is(err, reconcile.ErrEdgeRollBusy) {
		// A roll that an earlier call gave up on still runs: not a failure.
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("an edge roll still runs; ask again"))
	}
	if err == nil {
		err = s.checkNewEdge(rctx, gen, v)
	}
	if err != nil {
		msg := fmt.Sprintf("edge roll to %s failed: %v", v, err)
		if !errors.Is(err, reconcile.ErrEdgeRollFailed) { // the reconciler recorded that one
			s.event(evEdgeRollFailed, sevError, msg, map[string]string{"version": v})
		}
		s.log.Warn("agent: " + msg)
		return nil, connect.NewError(connect.CodeAborted, errors.New(msg))
	}
	msg := fmt.Sprintf("edge generation %d runs %s", gen, v)
	s.log.Info("agent: "+msg, "event", evEdgeUpdated)
	s.event(evEdgeUpdated, sevInfo, msg, map[string]string{"version": v, "generation": fmt.Sprint(gen)})
	return connect.NewResponse(&nodev1.UpdateEdgeResponse{Generation: gen, Version: v}), nil
}

// checkEdgeDirection refuses a version older than the running edge's (edgeV;
// the agent's when the edge does not say) unless rollback is set, and a
// rollback to another version than the one the edge ran before its last roll
// (rt.EdgePreviousBinary). Versions are told apart by their strings; Compare
// only orders them.
func checkEdgeDirection(v, edgeV string, rt *state.Runtime, rollback bool) error {
	if rollback {
		prev := ""
		if rt != nil && rt.EdgePreviousBinary != "" {
			prev = strings.TrimPrefix(filepath.Base(rt.EdgePreviousBinary), "postern-node-")
		}
		if prev == "" || prev != v {
			return fmt.Errorf("a rollback of the edge goes only to the version it ran before its last roll (%s), not to %s", orNone(prev), v)
		}
		return nil
	}
	if edgeV == "" {
		edgeV = version.Version
	}
	if release.ValidVersion(edgeV) && release.Compare(v, edgeV) < 0 {
		return fmt.Errorf("%s is older than the edge's %s; only a rollback to the edge's previous version goes back", v, edgeV)
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// runningEdge is the current edge generation, the version it answers (""
// when it does not answer) and the runtime record (nil when it cannot be
// read).
func (s *Service) runningEdge(ctx context.Context) (uint64, string, *state.Runtime) {
	rt, err := s.store.LoadRuntime()
	if err != nil {
		return 0, "", nil
	}
	if rt.EdgeGeneration == 0 || s.edge == nil {
		return 0, "", rt
	}
	hctx, cancel := context.WithTimeout(ctx, edgeHealthTimeout)
	defer cancel()
	h, err := s.edge(rt.EdgeGeneration).Health(hctx)
	if err != nil || h.GetGeneration() != rt.EdgeGeneration {
		return 0, "", rt
	}
	return rt.EdgeGeneration, h.GetVersion(), rt
}

// checkNewEdge checks that edge generation gen answers Health with version v.
func (s *Service) checkNewEdge(ctx context.Context, gen uint64, v string) error {
	hctx, cancel := context.WithTimeout(ctx, edgeHealthTimeout)
	defer cancel()
	h, err := s.edge(gen).Health(hctx)
	switch {
	case err != nil:
		return fmt.Errorf("edge generation %d does not answer: %w", gen, err)
	case h.GetGeneration() != gen:
		return fmt.Errorf("edge generation %d answers as generation %d", gen, h.GetGeneration())
	case h.GetVersion() != v:
		return fmt.Errorf("edge generation %d answers version %.64q, not %s", gen, h.GetVersion(), v)
	}
	return nil
}

// tcpMigrateReqFile is net.ipv4.tcp_migrate_req under /proc/sys.
const tcpMigrateReqFile = "net/ipv4/tcp_migrate_req"

// handoffWarnings reads net.ipv4.tcp_migrate_req (finding F2): unless it is 1,
// an edge roll aborts the connections still in the accept queue of the old
// generation's listeners, and the node warns "edge-handoff-unsafe".
// install.sh sets it, and so does the bootstrap of the node image on each
// start of the container (docker restart postern-agent).
func handoffWarnings(procSys string) (warnings []string, why string) {
	data, err := readFileLimited(filepath.Join(procSys, tcpMigrateReqFile), 64)
	switch {
	case err != nil:
		why = "net.ipv4.tcp_migrate_req cannot be read (Linux before 5.14 does not have it)"
	case string(bytes.TrimSpace(data)) != "1":
		why = fmt.Sprintf("net.ipv4.tcp_migrate_req is %.16q, not 1", bytes.TrimSpace(data))
	default:
		return nil, ""
	}
	return []string{warnHandoffUnsafe}, why
}
