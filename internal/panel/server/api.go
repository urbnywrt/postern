package server

import (
	"context"
	"errors"
	"net/http"
	"net/netip"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/deploy"
	"github.com/urbnywrt/postern/internal/panel/diagnostics"
	"github.com/urbnywrt/postern/internal/panel/egress"
	"github.com/urbnywrt/postern/internal/panel/geodb"
	"github.com/urbnywrt/postern/internal/panel/insights"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/probes"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/publicpage"
	"github.com/urbnywrt/postern/internal/panel/selfupdate"
	"github.com/urbnywrt/postern/internal/panel/versions"
)

// The most that a client may send in one message. Without it a message that is
// compressed is read as far as it goes, and http.MaxBytesReader, which counts
// what is on the wire, does not stop a small body that expands into a large one.
// connect.WithReadMaxBytes counts the message once it is decompressed.
const (
	// maxPublicMessage is for the services that anybody can call: sign-in and
	// the health check. The messages are a few hundred bytes. The same limit
	// is on the whole of AuthService, which also has procedures for admins,
	// because the limit is a property of a service handler; they take a
	// password and a code.
	maxPublicMessage = 64 << 10
	// maxAdminMessage is for the services that only admins can call.
	maxAdminMessage = 4 << 20
)

// routeNotFoundMessage is what the API says about a path that it does not have.
const routeNotFoundMessage = "no such API route"

// health is the HealthService: the panel is up and answering. It does not look
// at the database. The call is open to anybody, so it must cost nothing, and it
// is a probe of the process; a database that fails shows in the calls that use it.
type health struct{}

func (health) Check(context.Context, *connect.Request[panelv1.CheckRequest]) (*connect.Response[panelv1.CheckResponse], error) {
	return connect.NewResponse(&panelv1.CheckResponse{}), nil
}

var errorWriter = connect.NewErrorWriter()

// apiNotFound answers a path under /api that is none of the routes with a Connect
// error of code not_found, which is JSON and has the status 404, and not with the
// page of the UI.
func apiNotFound(w http.ResponseWriter, r *http.Request) {
	_ = errorWriter.Write(w, r, connect.NewError(connect.CodeNotFound, errors.New(routeNotFoundMessage)))
}

// services are the handlers that the panel mounts.
type services struct {
	auth      *auth.Service
	nodes     *nodes.Service
	proxies   *proxies.Service          // the listener, proxy, statistics and DNS credential services
	egress    *egress.Service           // the egress and chain services
	versions  *versions.Service         // the VersionService
	geo       *geodb.Service            // the GeoIPService
	settings  *insights.SettingsService // the SettingsService
	metrics   *insights.MetricsService  // the MetricsService
	geoUpload http.Handler              // PUT /api/geoip, the upload of the country database
	relUpload http.Handler              // POST /api/releases/upload, the upload of a Postern release bundle
	public    *publicpage.Service       // the PublicPageService, and the public site
	probes    *probes.Service           // the ProbeService
	diag      *diagnostics.Service      // the DiagnosticsService
	deploy    *deploy.Service           // installs over SSH, and their jobs
	ui        http.Handler

	// publicRouting is whether a request for the host of the public page goes
	// to the public site. Off (POSTERN_PUBLIC_PAGE=off) the admin is served on
	// every host and the page on none: the way out for an operator who gave
	// the page the only name he reaches the panel by.
	publicRouting bool

	// trusted are the reverse proxies that are not on the loopback
	// (POSTERN_TRUSTED_PROXIES): the peers, besides the loopback, that the
	// on-demand TLS question (publicpage.AskRoute) is answered for.
	trusted []netip.Prefix
}

// handler is the whole of the panel as one http.Handler. The path
// publicpage.AskRoute, the reverse proxy's question whether it may get a
// certificate for a name, is answered first, whatever the Host and whether or
// not the public page is routed: the proxy sends the Host of its ask URL, and
// the answer is the same on every host. It answers only the proxy itself (see
// publicpage.Service.AskHandler) and is not behind the authentication
// middleware. A request whose Host is the host of the public page goes to the
// public site (publicpage.Service), whatever its path, and to nothing below:
// not the admin UI, not the API, not the authentication middleware or the
// admin's security headers, also while the page is disabled. Every other host
// is the admin:
//
//	/api/<service>/<method>      the Connect API
//	/api/nodes/{id}/bundle.tar   the download of a bundle
//	/api/node-kit/{arch}         the download of the node kit
//	/api/geoip                   the upload of the country database
//	/api/ and /api               404 in JSON for every other path under /api
//	/                            the UI
//
// The routes go through the authentication middleware, which finds the admin of
// a request and turns away every call to a procedure that is not public when
// there is none, and through the security headers, outside it, so that the
// refusal has them too. Inside the middleware, publicpage.RecordAdminHosts
// notes the Host of every authenticated request, so that the public page is
// never given a name the admin is reached by. The downloads and the upload are
// not procedures, which the middleware would guard by itself: they are behind
// auth.RequireAdmin, as the nodes and geodb packages make them.
func (s services) handler() http.Handler {
	public := connect.WithReadMaxBytes(maxPublicMessage)
	admin := connect.WithReadMaxBytes(maxAdminMessage)

	api := http.NewServeMux()
	api.Handle(panelv1connect.NewHealthServiceHandler(health{}, public))
	api.Handle(panelv1connect.NewAuthServiceHandler(s.auth, public))
	api.Handle(panelv1connect.NewNodeServiceHandler(s.nodes, admin))
	// Join is public: a node joins with a token, not a session.
	api.Handle(panelv1connect.NewJoinServiceHandler(s.nodes, public))
	api.Handle(panelv1connect.NewListenerServiceHandler(s.proxies, admin))
	api.Handle(panelv1connect.NewProxyServiceHandler(s.proxies, admin))
	api.Handle(panelv1connect.NewStatsServiceHandler(s.proxies, admin))
	api.Handle(panelv1connect.NewDnsCredentialServiceHandler(s.proxies, admin))
	api.Handle(panelv1connect.NewGeoIPServiceHandler(s.geo, admin))
	api.Handle(panelv1connect.NewSettingsServiceHandler(s.settings, admin))
	api.Handle(panelv1connect.NewMetricsServiceHandler(s.metrics, admin))
	api.Handle(panelv1connect.NewPublicPageServiceHandler(s.public, admin))
	api.Handle(panelv1connect.NewProbeServiceHandler(s.probes, admin))
	api.Handle(panelv1connect.NewDiagnosticsServiceHandler(s.diag, admin))
	api.Handle(panelv1connect.NewEgressServiceHandler(s.egress, admin))
	api.Handle(panelv1connect.NewChainServiceHandler(s.egress, admin))
	api.Handle(s.versions.Handler(admin))
	api.Handle(panelv1connect.NewDeployServiceHandler(s.deploy, admin))
	api.HandleFunc("/", apiNotFound)

	root := http.NewServeMux()
	root.Handle(nodes.BundleRoute, s.nodes.BundleHandler())
	root.Handle(nodes.KitRoute, s.nodes.KitHandler())
	// Any method: the handler answers a method that is not PUT with a 405.
	root.Handle(geodb.UploadRoute, s.geoUpload)
	root.Handle(selfupdate.UploadRoute, s.relUpload)
	root.Handle("/api/", http.StripPrefix("/api", api))
	root.HandleFunc("/api", apiNotFound)
	root.Handle("/", s.ui)

	adminSite := securityHeaders(s.auth.Middleware(s.public.RecordAdminHosts(root)))
	ask := s.public.AskHandler(s.trusted)
	publicSite := s.public.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == publicpage.AskRoute:
			ask.ServeHTTP(w, r)
		case s.publicRouting && s.public.Serves(r):
			publicSite.ServeHTTP(w, r)
		default:
			adminSite.ServeHTTP(w, r)
		}
	})
}
