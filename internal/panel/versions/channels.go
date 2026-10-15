package versions

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"strconv"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// Proxies is what the channel procedures ask of the proxies service
// (internal/panel/proxies.Service): which proxies of a node a channel would
// change, and the locked write that bumps the nodes it changed.
type Proxies interface {
	// AffectedByChannel returns the proxies of a node whose effective
	// version would change if the node followed channel ("" for the default
	// of the panel).
	AffectedByChannel(ctx context.Context, nodeID, channel string) ([]*panelv1.AffectedProxy, error)
	// WriteVersions runs write under the lock of the node data, then raises
	// the desired generation of every node that write returns and notifies
	// the node manager.
	WriteVersions(ctx context.Context, write func(ctx context.Context) (bump []string, err error)) error
}

// channelsDiffer reports whether two channels give any component another
// version: a node that moves from a to b then runs something else (a proxy
// that follows its channel, or a provider), and needs a new desired state.
func channelsDiffer(versions map[string]map[string]string, a, b string) bool {
	if a == b {
		return false
	}
	for _, byChannel := range versions {
		if byChannel[a] != byChannel[b] {
			return true
		}
	}
	return false
}

// defaultChannelOf is the default channel of the panel, stable when none is
// set.
func (s *Service) defaultChannelOf(ctx context.Context) (string, error) {
	def := store.ChannelStable
	if _, err := s.db.GetSetting(ctx, store.SettingDefaultChannel, &def); err != nil {
		return "", err
	}
	if def == "" {
		def = store.ChannelStable
	}
	return def, nil
}

// SetProxies gives the service the proxies service that SetDefaultChannel and
// SetNodeChannel work with. Without one they answer that they are not
// implemented.
func (s *Service) SetProxies(p Proxies) { s.proxies = p }

// errNoProxies is the answer of the channel procedures of a service that has
// no proxies service.
var errNoProxies = connect.NewError(connect.CodeUnimplemented, errors.New("the proxies service is not available"))

// checkChannel checks a channel name: stable or latest, and "" when empty is
// allowed.
func checkChannel(ch string, emptyOK bool) error {
	switch ch {
	case store.ChannelStable, store.ChannelLatest:
		return nil
	case "":
		if emptyOK {
			return nil
		}
	}
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("channel %.32q is not %s or %s", ch, store.ChannelStable, store.ChannelLatest))
}

// SetDefaultChannel sets the channel that nodes without a channel of their
// own follow. The answer lists the proxies of those nodes whose version the
// change alters; without confirm nothing is changed and applied is false,
// with confirm the setting is written, every node on the default gets a new
// desired generation when the new channel gives any component another
// version (its providers move with it, proxies or not), and applied is true
// (Ruling S5-11). The nodes to bump are decided under the lock of the node
// data, with the write.
func (s *Service) SetDefaultChannel(ctx context.Context, req *connect.Request[panelv1.SetDefaultChannelRequest]) (*connect.Response[panelv1.SetDefaultChannelResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.proxies == nil {
		return nil, errNoProxies
	}
	channel := req.Msg.GetChannel()
	if err := checkChannel(channel, false); err != nil {
		return nil, err
	}
	nodes, err := s.db.ListNodes(ctx)
	if err != nil {
		return nil, internal(err)
	}
	var affected []*panelv1.AffectedProxy
	for _, n := range nodes {
		if n.EngineChannel != "" {
			continue // follows its own channel
		}
		list, err := s.proxies.AffectedByChannel(ctx, n.ID, channel)
		if err != nil {
			return nil, internal(err)
		}
		affected = append(affected, list...)
	}
	resp := &panelv1.SetDefaultChannelResponse{AffectedProxies: affected}
	if !req.Msg.GetConfirm() {
		return connect.NewResponse(resp), nil
	}
	err = s.proxies.WriteVersions(ctx, func(ctx context.Context) ([]string, error) {
		old, err := s.defaultChannelOf(ctx)
		if err != nil {
			return nil, err
		}
		versions, err := s.db.ChannelVersions(ctx)
		if err != nil {
			return nil, err
		}
		if err := s.db.PutSetting(ctx, store.SettingDefaultChannel, channel); err != nil {
			return nil, err
		}
		if !channelsDiffer(versions, old, channel) {
			return nil, nil
		}
		nodes, err := s.db.ListNodes(ctx)
		if err != nil {
			return nil, err
		}
		var bump []string
		for _, n := range nodes {
			if n.EngineChannel == "" {
				bump = append(bump, n.ID)
			}
		}
		return bump, nil
	})
	if err != nil {
		return nil, internal(err)
	}
	resp.Applied = true
	s.audit(ctx, "versions.default_channel", "channel:"+channel,
		map[string]string{"admin": admin.ID, "affected_proxies": strconv.Itoa(len(affected))})
	s.log.Info("default channel set", "channel", channel, "affected_proxies", len(affected), "admin", admin.ID)
	return connect.NewResponse(resp), nil
}

// SetNodeChannel sets the channel of one node, or makes it follow the default
// again (an empty channel), with the same confirm as SetDefaultChannel. The
// node gets a new desired generation when its effective channel changes to
// one that gives any component another version.
func (s *Service) SetNodeChannel(ctx context.Context, req *connect.Request[panelv1.SetNodeChannelRequest]) (*connect.Response[panelv1.SetNodeChannelResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.proxies == nil {
		return nil, errNoProxies
	}
	channel := req.Msg.GetChannel()
	if err := checkChannel(channel, true); err != nil {
		return nil, err
	}
	nodeID := req.Msg.GetNodeId()
	if _, err := s.db.NodeByID(ctx, nodeID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no such node"))
		}
		return nil, internal(err)
	}
	affected, err := s.proxies.AffectedByChannel(ctx, nodeID, channel)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no such node"))
		}
		return nil, internal(err)
	}
	resp := &panelv1.SetNodeChannelResponse{AffectedProxies: affected}
	if !req.Msg.GetConfirm() {
		return connect.NewResponse(resp), nil
	}
	err = s.proxies.WriteVersions(ctx, func(ctx context.Context) ([]string, error) {
		def, err := s.defaultChannelOf(ctx)
		if err != nil {
			return nil, err
		}
		versions, err := s.db.ChannelVersions(ctx)
		if err != nil {
			return nil, err
		}
		old := ""
		if _, err := s.db.ModifyNode(ctx, nodeID, func(n *store.Node) error {
			old = n.EngineChannel
			n.EngineChannel = channel
			return nil
		}); err != nil {
			return nil, err
		}
		if channelsDiffer(versions, cmp.Or(old, def), cmp.Or(channel, def)) {
			return []string{nodeID}, nil
		}
		return nil, nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such node"))
	}
	if err != nil {
		return nil, internal(err)
	}
	resp.Applied = true
	s.audit(ctx, "versions.node_channel", "node:"+nodeID,
		map[string]string{"admin": admin.ID, "channel": channel, "affected_proxies": strconv.Itoa(len(affected))})
	s.log.Info("node channel set", "node", nodeID, "channel", channel, "affected_proxies", len(affected), "admin", admin.ID)
	return connect.NewResponse(resp), nil
}
