package versions

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/rollout"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// SetRollouts gives the service the rollout runner that the rollout
// procedures work with. Without one they answer that they are not
// implemented.
func (s *Service) SetRollouts(r *rollout.Runner) { s.rollouts = r }

var errNoRollouts = connect.NewError(connect.CodeUnimplemented, errors.New("rollouts are not available"))

// rolloutError is the answer to an error of the runner: a conflict names the
// rollout that holds the channel or the node.
func (s *Service) rolloutError(ctx context.Context, err error) error {
	var conflict *store.RolloutConflict
	switch {
	case errors.As(err, &conflict):
		if conflict.NodeID != "" {
			name := conflict.NodeID
			if n, err := s.db.NodeByID(ctx, conflict.NodeID); err == nil {
				name = n.Name
			}
			return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("rollout %s holds node %s", conflict.Holder, name))
		}
		return connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("rollout %s is active for the %s channel of %s", conflict.Holder, conflict.Channel, conflict.Component))
	case errors.Is(err, rollout.ErrInvalid):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, rollout.ErrRefused), errors.Is(err, rollout.ErrState):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, rollout.ErrNoExecutor):
		return connect.NewError(connect.CodeUnimplemented, err)
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, errors.New("no such rollout"))
	}
	return internal(err)
}

// rolloutProto reads a rollout with its steps for an answer.
func (s *Service) rolloutProto(ctx context.Context, id string) (*panelv1.Rollout, error) {
	ro, steps, items, err := s.db.Rollout(ctx, id)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, st := range steps {
		if _, ok := names[st.NodeID]; ok {
			continue
		}
		names[st.NodeID] = st.NodeID
		if n, err := s.db.NodeByID(ctx, st.NodeID); err == nil {
			names[st.NodeID] = n.Name
		}
	}
	out := &panelv1.Rollout{
		Id: ro.ID, Kind: ro.Kind, Component: ro.Component, Channel: ro.Channel,
		FromVersion: ro.FromVersion, ToVersion: ro.ToVersion, ToEngine: ro.ToEngine,
		Mode: ro.Mode, PauseSeconds: ro.PauseSeconds, Status: ro.Status, CurrentStep: ro.CurrentStep, Error: ro.Error,
		CreatedUnix: ro.CreatedAt.Unix(), UpdatedUnix: ro.UpdatedAt.Unix(),
		Agent: ro.Options.Agent, Edge: ro.Options.Edge, SkipOffline: ro.Options.SkipOffline,
	}
	if ro.FinishedAt != nil {
		out.FinishedUnix = ro.FinishedAt.Unix()
	}
	if ro.ResumeAt != nil {
		out.ResumeUnix = ro.ResumeAt.Unix()
	}
	// The diagnostics around the steps: their change names the rollout and
	// the step. Without them the steps are shown all the same.
	runs, err := s.db.DiagnosticRunsByChange(ctx, "rollout "+ro.ID+" step ")
	if err != nil {
		s.log.Warn("could not read the diagnostics of a rollout", "rollout", ro.ID, "err", err)
	}
	for _, st := range steps {
		ps := &panelv1.RolloutStep{
			Index: st.Index, NodeId: st.NodeID, NodeName: names[st.NodeID], ProxyId: st.ProxyID,
			Status: st.Status, Error: st.Error,
		}
		if st.StartedAt != nil {
			ps.StartedUnix = st.StartedAt.Unix()
		}
		if st.FinishedAt != nil {
			ps.FinishedUnix = st.FinishedAt.Unix()
		}
		for _, it := range items {
			if it.StepIndex != st.Index {
				continue
			}
			ps.Items++
			switch it.State {
			case store.ItemApplied:
				if st.Status == store.StepDone {
					ps.ItemsDone++
				}
			case store.ItemDeferred:
				ps.ItemsDeferred++
			}
		}
		stepRuns(ps, runs, store.RolloutStepChange(ro.ID, st.Index), st.NodeID)
		out.Steps = append(out.Steps, ps)
	}
	return out, nil
}

// rolloutAnswer is the rollout of an action, read again after it.
func (s *Service) rolloutAnswer(ctx context.Context, id string) (*panelv1.Rollout, error) {
	out, err := s.rolloutProto(ctx, id)
	if err != nil {
		return nil, s.rolloutError(ctx, err)
	}
	return out, nil
}

// StartRollout starts a rollout; a conflict answers failed precondition,
// naming the rollout that holds the channel or the node.
func (s *Service) StartRollout(ctx context.Context, req *connect.Request[panelv1.StartRolloutRequest]) (*connect.Response[panelv1.StartRolloutResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.rollouts == nil {
		return nil, errNoRollouts
	}
	ro, err := s.rollouts.Start(ctx, admin.ID, req.Msg)
	if err != nil {
		answer := s.rolloutError(ctx, err)
		s.audit(ctx, "versions.rollout.start", "rollout:", failed(answer, map[string]string{
			"kind": req.Msg.GetKind(), "component": req.Msg.GetComponent(), "channel": req.Msg.GetChannel(), "to_version": req.Msg.GetToVersion(),
		}))
		return nil, answer
	}
	s.audit(ctx, "versions.rollout.start", "rollout:"+ro.ID, map[string]string{
		"kind": ro.Kind, "component": ro.Component, "channel": ro.Channel, "to_version": ro.ToVersion, "mode": ro.Mode,
	})
	s.log.Info("rollout started", "rollout", ro.ID, "admin", admin.ID)
	out, err := s.rolloutAnswer(ctx, ro.ID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.StartRolloutResponse{Rollout: out}), nil
}

// GetRollout returns one rollout with its steps.
func (s *Service) GetRollout(ctx context.Context, req *connect.Request[panelv1.GetRolloutRequest]) (*connect.Response[panelv1.GetRolloutResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.rollouts == nil {
		return nil, errNoRollouts
	}
	out, err := s.rolloutAnswer(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.GetRolloutResponse{Rollout: out}), nil
}

// ListRollouts returns rollouts, newest first, with their steps.
func (s *Service) ListRollouts(ctx context.Context, req *connect.Request[panelv1.ListRolloutsRequest]) (*connect.Response[panelv1.ListRolloutsResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.rollouts == nil {
		return nil, errNoRollouts
	}
	list, err := s.db.ListRollouts(ctx, req.Msg.GetActiveOnly(), int(req.Msg.GetLimit()))
	if err != nil {
		return nil, internal(err)
	}
	resp := &panelv1.ListRolloutsResponse{}
	for _, ro := range list {
		out, err := s.rolloutAnswer(ctx, ro.ID)
		if err != nil {
			return nil, err
		}
		resp.Rollouts = append(resp.Rollouts, out)
	}
	return connect.NewResponse(resp), nil
}

// act runs an action of the runner on a rollout, audits it and returns the
// rollout as it is then.
func (s *Service) act(ctx context.Context, action, id string, do func(context.Context, string) error) (*panelv1.Rollout, error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.rollouts == nil {
		return nil, errNoRollouts
	}
	if err := do(ctx, id); err != nil {
		answer := s.rolloutError(ctx, err)
		s.audit(ctx, "versions.rollout."+action, "rollout:"+id, failed(answer, nil))
		return nil, answer
	}
	s.audit(ctx, "versions.rollout."+action, "rollout:"+id, nil)
	s.log.Info("rollout "+action, "rollout", id, "admin", admin.ID)
	return s.rolloutAnswer(ctx, id)
}

// ContinueRollout runs the next step of a paused rollout.
func (s *Service) ContinueRollout(ctx context.Context, req *connect.Request[panelv1.ContinueRolloutRequest]) (*connect.Response[panelv1.ContinueRolloutResponse], error) {
	out, err := s.act(ctx, "continue", req.Msg.GetId(), s.rollouts.Continue)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.ContinueRolloutResponse{Rollout: out}), nil
}

// PauseRollout stops a running rollout after its current step.
func (s *Service) PauseRollout(ctx context.Context, req *connect.Request[panelv1.PauseRolloutRequest]) (*connect.Response[panelv1.PauseRolloutResponse], error) {
	out, err := s.act(ctx, "pause", req.Msg.GetId(), s.rollouts.Pause)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.PauseRolloutResponse{Rollout: out}), nil
}

// RetryRollout runs the step that failed again.
func (s *Service) RetryRollout(ctx context.Context, req *connect.Request[panelv1.RetryRolloutRequest]) (*connect.Response[panelv1.RetryRolloutResponse], error) {
	out, err := s.act(ctx, "retry", req.Msg.GetId(), s.rollouts.Retry)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.RetryRolloutResponse{Rollout: out}), nil
}

// AbortRollout ends a rollout and reverts every step that was applied.
func (s *Service) AbortRollout(ctx context.Context, req *connect.Request[panelv1.AbortRolloutRequest]) (*connect.Response[panelv1.AbortRolloutResponse], error) {
	out, err := s.act(ctx, "abort", req.Msg.GetId(), s.rollouts.Abort)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.AbortRolloutResponse{Rollout: out}), nil
}

// failed is the details of the audit entry of an action that was refused or
// failed: the details given, with the result and what the answer says.
func failed(answer error, details map[string]string) map[string]string {
	out := map[string]string{"result": "failed"}
	for k, v := range details {
		if v != "" {
			out[k] = v
		}
	}
	var ce *connect.Error
	if errors.As(answer, &ce) {
		out["code"], out["error"] = ce.Code().String(), ce.Message()
	}
	return out
}

// stepRuns sets the latest runs before and after a step of its node; runs
// are oldest first.
func stepRuns(ps *panelv1.RolloutStep, runs []*store.DiagnosticRun, change, nodeID string) {
	for _, r := range runs {
		if r.Change != change || r.NodeID != nodeID {
			continue
		}
		switch r.Reason {
		case store.RunBeforeChange:
			ps.BeforeRunId, ps.BeforeRunState = r.ID, r.State
		case store.RunAfterChange:
			ps.AfterRunId, ps.AfterRunState, ps.AfterRegressed = r.ID, r.State, r.Regressed
		}
	}
}
