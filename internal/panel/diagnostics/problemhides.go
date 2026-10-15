package diagnostics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// maxProblemKey bounds the key that HideProblem and UnhideProblem take.
const maxProblemKey = 1024

// problemKey names a problem across refreshes: its source, its node, its
// check id or its kind, and its target. The two problems of the country
// database are one: its check, missing or stale.
func problemKey(p *panelv1.Problem) string {
	switch {
	case p.Kind == KindCheck:
		return "check|" + p.NodeId + "|" + p.CheckId + "|" + p.Target
	case p.NodeId == "":
		return "panel||" + p.CheckId + "|"
	case p.ProxyId != "":
		return "proxy|" + p.NodeId + "|" + p.Kind + "|proxy:" + p.ProxyId
	default:
		return "node|" + p.NodeId + "|" + p.Kind + "|"
	}
}

// problemFingerprint is what a hide compares: the problem's status (its
// severity) and its summary. The kinds whose summary ends with an error text
// that changes from one report to the next (a probe's error, an event's
// message) are compared by their kind and the lead-in of the summary, up to
// its first ": ", so that a new wording of the same failure keeps the hide.
func problemFingerprint(p *panelv1.Problem) string {
	summary := p.Summary
	switch p.Kind {
	case KindProxyDown, KindProxyFailed, KindNodeError, KindNodeLastError, KindNodeStateRejected:
		summary, _, _ = strings.Cut(summary, ": ")
	}
	sum := sha256.Sum256([]byte(p.Severity + "\x00" + p.Kind + "\x00" + summary))
	return hex.EncodeToString(sum[:16])
}

// Visible returns the problems as List does, without those that an admin hid
// (marked hidden instead when includeHidden is set). It deletes the hides of
// the problems that changed and, when it lists the whole fleet, of those that
// cleared.
func (f *Feed) Visible(ctx context.Context, nodeID, proxyID string, includeHidden bool) ([]*panelv1.Problem, error) {
	f.hides.Lock()
	defer f.hides.Unlock()
	ps, err := f.List(ctx, nodeID, proxyID)
	if err != nil {
		return nil, err
	}
	current := make(map[string]string, len(ps))
	for _, p := range ps {
		current[p.Key] = problemFingerprint(p)
	}
	held, err := f.cfg.DB.SettleProblemHides(ctx, current, nodeID == "" && proxyID == "")
	if err != nil {
		return nil, err
	}
	out := ps[:0]
	for _, p := range ps {
		h, hidden := held[p.Key]
		if !hidden {
			out = append(out, p)
			continue
		}
		if includeHidden {
			p.Hidden, p.HiddenAtUnix = true, h.HiddenAt.Unix()
			out = append(out, p)
		}
	}
	return out, nil
}

// Hide hides the problem of a key as it is now, and returns it;
// [store.ErrNotFound] when there is no such problem.
func (f *Feed) Hide(ctx context.Context, key, adminID string) (*panelv1.Problem, error) {
	f.hides.Lock()
	defer f.hides.Unlock()
	ps, err := f.List(ctx, "", "")
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		if p.Key != key {
			continue
		}
		h := &store.ProblemHide{Key: key, Fingerprint: problemFingerprint(p), HiddenAt: f.cfg.Now(), AdminID: adminID}
		if err := f.cfg.DB.HideProblem(ctx, h); err != nil {
			return nil, err
		}
		return p, nil
	}
	return nil, fmt.Errorf("problem: %w", store.ErrNotFound)
}

func problemKeyOf(key string) error {
	switch {
	case key == "":
		return invalid("key is required")
	case len(key) > maxProblemKey:
		return invalid("key is at most 1024 bytes")
	}
	return nil
}

// HideProblem hides a problem until it changes.
func (s *Service) HideProblem(ctx context.Context, req *connect.Request[panelv1.HideProblemRequest]) (*connect.Response[panelv1.HideProblemResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.feed == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("the panel has no problem feed"))
	}
	key := req.Msg.GetKey()
	if err := problemKeyOf(key); err != nil {
		return nil, err
	}
	p, err := s.feed.Hide(ctx, key, admin.ID)
	if err != nil {
		return nil, s.fail("the problem", err)
	}
	if err := s.db.AppendAudit(ctx, &store.AuditEntry{AdminID: admin.ID, Action: "problem.hide", Target: "problem:" + key,
		Details: map[string]string{"kind": p.Kind, "severity": p.Severity}}); err != nil {
		s.log.Error("could not write the audit log", "action", "problem.hide", "err", err)
	}
	return connect.NewResponse(&panelv1.HideProblemResponse{}), nil
}

// UnhideProblem shows a hidden problem again.
func (s *Service) UnhideProblem(ctx context.Context, req *connect.Request[panelv1.UnhideProblemRequest]) (*connect.Response[panelv1.UnhideProblemResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.feed == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("the panel has no problem feed"))
	}
	key := req.Msg.GetKey()
	if err := problemKeyOf(key); err != nil {
		return nil, err
	}
	deleted, err := s.db.UnhideProblem(ctx, key)
	if err != nil {
		return nil, s.fail("could not show the problem", err)
	}
	if deleted {
		if err := s.db.AppendAudit(ctx, &store.AuditEntry{AdminID: admin.ID, Action: "problem.unhide", Target: "problem:" + key}); err != nil {
			s.log.Error("could not write the audit log", "action", "problem.unhide", "err", err)
		}
	}
	return connect.NewResponse(&panelv1.UnhideProblemResponse{}), nil
}
