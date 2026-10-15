// Package gen_test guards the committed generated code. gen/go has no Go files
// of its own, only the generated sub-packages, so the guard lives in an
// external test package that imports all of them together.
package gen_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/gen/go/postern/edge/v1/edgev1connect"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
)

// TestPackagesCompile only has to build: a missing, stale or conflicting
// generated file breaks the compilation of this file, or panics while the
// descriptors register at init (all three packages share one registry).
func TestPackagesCompile(t *testing.T) {
	_ = &nodev1.NodeState{}
	_ = &edgev1.EdgeConfig{}
	_ = &panelv1.CheckRequest{}

	_ = nodev1connect.NewNodeServiceHandler
	_ = edgev1connect.NewEdgeControlServiceHandler
	_ = panelv1connect.NewHealthServiceHandler
}

// TestMessagesRoundTrip pushes populated messages through the wire format, so
// that oneofs, maps, enums and repeated fields are known to work at runtime and
// not only to compile.
func TestMessagesRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  proto.Message
	}{
		{
			name: "node state",
			msg: &nodev1.NodeState{
				Generation: 7,
				Settings: &nodev1.NodeSettings{
					DefaultChainId: "chain-1",
					DomainPool:     []string{"a.example.com", "b.example.com"},
					BlacklistCidrs: []string{"198.51.100.0/24"},
					IpPolicy:       nodev1.IpPolicy_IP_POLICY_COUNTRIES,
					MgmtSni:        "mgmt.example.com",
				},
				Listeners: []*nodev1.Listener{{
					Id:             "l1",
					Kind:           nodev1.ListenerKind_LISTENER_KIND_TLS,
					BindIp:         "192.0.2.10",
					Port:           443,
					StrangerAction: nodev1.StrangerAction_STRANGER_ACTION_MASK,
					MaskTarget:     "example.com:443",
					NonTlsAction:   nodev1.NonTlsAction_NON_TLS_ACTION_HTTP400,
					TrustedCidrs:   []string{"203.0.113.0/24"},
				}},
				Proxies: []*nodev1.Proxy{{
					Id:                "p1",
					ListenerId:        "l1",
					Type:              nodev1.ProxyType_PROXY_TYPE_FAKETLS,
					Enabled:           true,
					Domain:            "cdn.example.com",
					Engine:            nodev1.Engine_ENGINE_TELEMT,
					EngineVersion:     "3.5.13",
					EgressChainId:     "chain-1",
					EgressScopeChains: map[string]string{"scope-a": "chain-2"},
					Limits:            &nodev1.Limits{Devices: 3, ConnsTotal: 100, ConnsPerIp: 10},
					UseMiddleProxy:    true,
					Web:               &nodev1.WebSettings{BasePath: "/w", Carriers: []string{"c1", "c2"}},
				}},
				Egresses: []*nodev1.Egress{{Id: "e1", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"192.0.2.20:1080"}`}},
				Chains: []*nodev1.EgressChain{{
					Id:              "chain-1",
					MemberEgressIds: []string{"e1"},
					Check:           &nodev1.HealthCheck{IntervalSeconds: 30, TimeoutSeconds: 5, FailThreshold: 3, RecoverThreshold: 2, DcAddrs: []string{"149.154.175.50:443"}},
				}},
				Artifacts: []*nodev1.ArtifactRef{{Engine: "telemt", Version: "3.5.13", Arch: "amd64", Sha256: "00", FileName: "telemt.tar.gz", Binary: "telemt"}},
			},
		},
		{
			name: "watch response with stats oneof",
			msg: &nodev1.WatchResponse{
				Seq:    42,
				TsUnix: 1_700_000_000,
				Payload: &nodev1.WatchResponse_Stats{Stats: &nodev1.StatsBatch{
					MinuteUnix: 1_700_000_000,
					Proxies:    []*nodev1.ProxyMinute{{ProxyId: "p1", Up: 1, Down: 2, ConnsNew: 3, ConnsPeak: 4, Devices: 5, ConnsActive: 6}},
					Node:       &nodev1.NodeMinute{Cpu: 0.5, MemUsed: 1, MemTotal: 2, Load1: 0.25, Conns: 9},
					Ips:        []*nodev1.IpSighting{{ProxyId: "p1", Ip: "2001:db8::1", FirstSeen: 1, LastSeen: 2, Bytes: 3}},
				}},
			},
		},
		{
			name: "upload artifact chunk oneof",
			msg:  &nodev1.UploadArtifactRequest{Part: &nodev1.UploadArtifactRequest_Chunk{Chunk: []byte{0, 1, 2, 3}}},
		},
		{
			name: "edge config",
			msg: &edgev1.EdgeConfig{
				Generation: 9,
				Listeners:  []*edgev1.EdgeListener{{Id: "l1", BindIp: "192.0.2.10", Port: 443, Kind: "tls", StrangerAction: "mask", NonTlsAction: "http400"}},
				Routes: []*edgev1.Route{{
					ListenerId: "l1", Sni: "cdn.example.com", ProxyId: "p1", Kind: "engine", Backend: "127.0.0.1:20000",
					ProxyProtocol: true, Limits: &edgev1.EdgeLimits{Devices: 3},
				}},
				Socks:         []*edgev1.SocksPort{{Port: 30000, ProxyId: "p1", DefaultChainId: "chain-1", ScopeChains: map[string]string{"s": "chain-2"}}},
				Chains:        []*edgev1.Chain{{Id: "chain-1", Members: []*edgev1.ChainMember{{Key: "m1", Kind: "socks5", Addr: "127.0.0.1:35000"}}}},
				Health:        &edgev1.HealthCheck{IntervalSeconds: 30, EchoUrls: []string{"https://example.com/ip"}},
				TestListeners: []*edgev1.TestListener{{Port: 40000, ListenerId: "l1"}},
			},
		},
		{
			name: "edge snapshot with map",
			msg: &edgev1.SnapshotResponse{
				Generation: 9,
				Proxies:    []*edgev1.ProxyCounters{{ProxyId: "p1", BytesUp: 1, BytesDown: 2, BackendActive: map[string]uint32{"127.0.0.1:20000": 2}}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := proto.Marshal(tc.msg)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			got := tc.msg.ProtoReflect().New().Interface()
			if err := proto.Unmarshal(wire, got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !proto.Equal(tc.msg, got) {
				t.Errorf("round trip changed the message:\n got: %v\nwant: %v", got, tc.msg)
			}
		})
	}
}
