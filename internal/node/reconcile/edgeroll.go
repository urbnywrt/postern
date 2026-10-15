package reconcile

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// Errors of RollEdge.
var (
	// ErrEdgeRollBusy: another roll request waits or runs.
	ErrEdgeRollBusy = errors.New("an edge roll is already asked for")
	// ErrEdgeRollFailed: the new generation did not come up, or does not bind
	// what the running one binds; it was removed, the running one serves on,
	// and the event edge_roll_failed says so.
	ErrEdgeRollFailed = errors.New("edge roll failed")
)

// edgeRollRequest is UpdateEdge's request for an edge roll to a binary.
type edgeRollRequest struct {
	ctx    context.Context
	binary string
	sum    []byte              // the SHA-256 UpdateEdge verified, checked again before the mount
	done   chan edgeRollResult // buffered: the pass never waits on it
}

type edgeRollResult struct {
	gen uint64
	err error
}

// RollEdge asks for a new edge generation on binary, the host path of an agent
// binary, beside the one that runs (Ruling 44), and waits until a pass made it
// or ctx ends. kick starts a pass. It returns the new generation once it
// answers and took over; ErrEdgeRollFailed (wrapped, with the reason) when it
// did not come up and the running one serves on; ErrEdgeRollBusy while another
// request waits or runs; the pass's error when the pass that held the request
// failed before it came to the edge. A request whose ctx ends before a pass took
// it is withdrawn; one that a pass took runs to its end.
func (r *Reconciler) RollEdge(ctx context.Context, binary string, sum []byte, kick func()) (uint64, error) {
	req := &edgeRollRequest{ctx: ctx, binary: binary, sum: sum, done: make(chan edgeRollResult, 1)}
	r.mu.Lock()
	if r.rollReq != nil || r.rollRunning {
		r.mu.Unlock()
		return 0, ErrEdgeRollBusy
	}
	r.rollReq = req
	r.mu.Unlock()
	kick()
	select {
	case res := <-req.done:
		return res.gen, res.err
	case <-ctx.Done():
		r.mu.Lock()
		if r.rollReq == req {
			r.rollReq = nil
		}
		r.mu.Unlock()
		select {
		case res := <-req.done: // it ended meanwhile
			return res.gen, res.err
		default:
		}
		return 0, ctx.Err()
	}
}

// takeRollRequest takes UpdateEdge's request, if one waits.
func (p *pass) takeRollRequest() *edgeRollRequest {
	r := p.r
	r.mu.Lock()
	defer r.mu.Unlock()
	req := r.rollReq
	if req == nil || req.ctx.Err() != nil {
		return nil
	}
	r.rollReq = nil
	r.rollRunning = true
	p.rollReq = req
	return req
}

// noteRollRequest notes the request that waits as the pass starts, so that a
// pass that fails before it comes to the edge answers it (finishRoll).
func (p *pass) noteRollRequest() {
	p.r.mu.Lock()
	p.rollWaiting = p.r.rollReq
	p.r.mu.Unlock()
}

// rollDone records the outcome of the request the pass took.
func (p *pass) rollDone(gen uint64, err error) {
	p.rollGen, p.rollErr, p.rollEnded = gen, err, true
}

// finishRoll answers the request of the pass, after the runtime record was
// saved: the one it took, with its outcome (or err, when the pass ended before
// it); or the one that waited as the pass started, when the pass failed (err)
// before it came to the edge. interrupted passes start over, and keep it.
func (p *pass) finishRoll(err error, interrupted bool) {
	r := p.r
	if req := p.rollReq; req != nil {
		res := edgeRollResult{gen: p.rollGen, err: p.rollErr}
		if !p.rollEnded {
			res = edgeRollResult{err: fmt.Errorf("the reconcile pass ended before the roll: %w", orErr(err))}
		}
		req.done <- res
		r.mu.Lock()
		r.rollRunning = false
		r.mu.Unlock()
		return
	}
	if err == nil || interrupted || p.rollWaiting == nil {
		return
	}
	r.mu.Lock()
	taken := r.rollReq == p.rollWaiting
	if taken {
		r.rollReq = nil
	}
	r.mu.Unlock()
	if taken {
		p.rollWaiting.done <- edgeRollResult{err: fmt.Errorf("the reconcile pass failed before the roll: %w", err)}
	}
}

func orErr(err error) error {
	if err == nil {
		return errors.New("no roll was made")
	}
	return err
}

// edgeBinaryFor is the binary of a new edge generation that replaces
// generation prev for another reason than a roll to a binary (a crash, other
// capabilities, a start-up): the binary prev mounted, while it is still a
// regular executable file, else the agent's own.
func (p *pass) edgeBinaryFor(prev uint64) string {
	b := p.rt.EdgeBinaries[prev]
	if b == "" || b == p.r.NodeBinaryPath {
		return p.r.NodeBinaryPath
	}
	if err := checkNodeBinary(b); err != nil {
		p.r.log().Warn("the binary of the edge generation that is replaced is gone; the new one runs the agent's",
			"edge_generation", prev, "binary", b, "err", err)
		return p.r.NodeBinaryPath
	}
	return b
}

// recordEdgeBinary notes the binary of an edge generation that was created.
func (p *pass) recordEdgeBinary(gen uint64, binary string) {
	if p.rt.EdgeBinaries == nil {
		p.rt.EdgeBinaries = map[uint64]string{}
	}
	p.rt.EdgeBinaries[gen] = binary
}

// edgeBinaryOf is the binary edge generation gen mounts: the recorded one, or
// the agent's own.
func (p *pass) edgeBinaryOf(gen uint64) string {
	if b := p.rt.EdgeBinaries[gen]; b != "" {
		return b
	}
	return p.r.NodeBinaryPath
}

// edgeLive reports whether the container of edge generation gen is up.
func (p *pass) edgeLive(gen uint64) bool {
	for _, e := range p.edges {
		if e.gen == gen {
			return edgeAlive(e.state)
		}
	}
	return false
}

// settleRoll settles a roll that an agent did not finish: generation old,
// the record's, serves, and the newer generation cur (number high) was made
// beside it. cur takes over only when it is up, answers, and binds every
// listener old binds (checkRollBinds, slice 3); otherwise it is removed
// (abandonEdge) and old goes on serving. It reports whether cur took over.
func (p *pass) settleRoll(old, high uint64, cur *edgeContainer) (took bool, err error) {
	p.r.log().Info("an edge roll was not finished: settling it", "edge_generation", high, "serving", old)
	if edgeAlive(cur.state) {
		err = p.waitEdgeHealthy(high)
		if err == nil {
			err = p.checkRollBinds(old, high)
		}
	} else {
		err = fmt.Errorf("edge g%d is %s", high, cur.state)
	}
	if err == nil {
		p.rt.EdgePreviousBinary = p.edgeBinaryOf(old)
		return true, nil
	}
	if p.ctx.Err() != nil {
		return false, p.ctx.Err()
	}
	p.abandonEdge(high, old, err)
	if p.rt.EdgeNetRaw == high {
		// Which of the two had CAP_NET_RAW is known only of the new one: a
		// generation that needs it is made again if old lacks it.
		p.rt.EdgeNetRaw = 0
	}
	p.edges = slices.DeleteFunc(p.edges, func(e edgeContainer) bool { return e.gen == high })
	return false, nil
}
