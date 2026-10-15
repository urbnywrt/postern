package server

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
)

// The DiagnosticsService is mounted behind the admin's session.
func TestDiagnosticsServiceIsMounted(t *testing.T) {
	p := newPanel(t)
	b := p.signIn()
	ctx := context.Background()
	code := func(err error) connect.Code {
		var ce *connect.Error
		if errors.As(err, &ce) {
			return ce.Code()
		}
		return 0
	}
	diag := panelv1connect.NewDiagnosticsServiceClient(b.http, p.ts.URL+"/api")
	if _, err := diag.LatestChecks(ctx, connect.NewRequest(&panelv1.LatestChecksRequest{})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("LatestChecks without a node: %v, want InvalidArgument from the service", err)
	}
	anon := panelv1connect.NewDiagnosticsServiceClient(p.ts.Client(), p.ts.URL+"/api")
	if _, err := anon.LatestChecks(ctx, connect.NewRequest(&panelv1.LatestChecksRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("anonymous: %v", err)
	}
}
