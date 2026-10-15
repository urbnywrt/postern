package telemt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"

	"github.com/urbnywrt/postern/internal/engines"
)

// logFilter is the log filter of the engine containers, set through RUST_LOG,
// which telemt 3.5.13 takes over the config's log_level at start-up
// (src/maestro/bootstrap.rs, runtime_tasks::log_filter_spec). It is info, the
// highest level that the integration test (TestLogLevel) finds free of
// secrets and client addresses, except for the targets that log the
// addresses of clients at any level, or links:
//
//   - telemt::proxy: the client handshakes and relays (peer=, real_peer=);
//   - telemt::maestro::listeners::accept: "Connection closed with error" and
//     the like, with the client's address from its PROXY header;
//   - telemt::ip_tracker: the addresses of each user;
//   - telemt::links and telemt::config::hot_reload: the proxy links, which
//     carry the secret ([general.links] show = [] keeps them out as well).
//
// A config reload would set the filter back to the config's level (silent:
// warn); the node never reloads an engine, it rolls a new generation.
const logFilter = "info,telemt::proxy=off,telemt::maestro::listeners::accept=off,telemt::ip_tracker=off,telemt::links=off,telemt::config::hot_reload=off"

var _ engines.LogLeveler = Driver{}

// LogEnv is the environment that sets the engine's log level.
func (Driver) LogEnv() []string { return []string{"RUST_LOG=" + logFilter} }

var _ engines.HealthReporter = Driver{}

const (
	dcsPath = "/v1/stats/dcs"
	// maxDCsBody bounds what Health reads of the answer: some 30 KiB for the
	// five datacenters and their endpoints.
	maxDCsBody = 1 << 20
)

// Health asks the engine's API whether it is ready (Ready) and how its middle
// proxies are: GET /v1/stats/dcs with the token. An error is an API that did
// not answer the second question; the first one's answer is in Ready and
// Reason.
func (d Driver) Health(ctx context.Context, in engines.Instance) (engines.EngineHealth, error) {
	var h engines.EngineHealth
	if err := d.Ready(ctx, in); err != nil {
		h.Reason = err.Error()
	} else {
		h.Ready = true
	}
	ctx, cancel := context.WithTimeout(ctx, readyRequestTimeout)
	defer cancel()
	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(int(in.APIPort))) + dcsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return h, fmt.Errorf("telemt: %w", err)
	}
	req.Header.Set("Authorization", in.APIToken)
	resp, err := apiClient.Do(req)
	if err != nil {
		return h, fmt.Errorf("telemt: %s: %w", dcsPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return h, fmt.Errorf("telemt: %s answered HTTP %d", dcsPath, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDCsBody))
	if err != nil {
		return h, fmt.Errorf("telemt: %s: reading the answer: %w", dcsPath, err)
	}
	dcs, err := ParseDCs(body)
	if err != nil {
		return h, err
	}
	h.MiddleProxy, h.DCs = dcs.MiddleProxy, dcs.DCs
	if !dcs.MiddleProxy {
		h.Reason = dcs.Reason
	}
	return h, nil
}

// ParseDCs reads the answer of GET /v1/stats/dcs (telemt 3.5.13,
// src/api/model.rs DcStatusData in SuccessResponse): {ok, data:
// {middle_proxy_enabled, reason, dcs: [{dc, available_endpoints,
// available_pct, coverage_pct, fresh_coverage_pct, ...}]}}. Percentages are
// clamped to 0-100; an answer without fresh_coverage_pct still reads.
// Only MiddleProxy, Reason and DCs of the result are set.
func ParseDCs(body []byte) (engines.EngineHealth, error) {
	var answer struct {
		OK   bool `json:"ok"`
		Data *struct {
			MiddleProxy bool   `json:"middle_proxy_enabled"`
			Reason      string `json:"reason"`
			DCs         []struct {
				DC                 int      `json:"dc"`
				AvailableEndpoints int      `json:"available_endpoints"`
				AvailablePct       float64  `json:"available_pct"`
				CoveragePct        float64  `json:"coverage_pct"`
				FreshCoveragePct   *float64 `json:"fresh_coverage_pct"`
			} `json:"dcs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return engines.EngineHealth{}, fmt.Errorf("telemt: %s: not telemt's JSON", dcsPath)
	}
	if !answer.OK || answer.Data == nil {
		return engines.EngineHealth{}, errors.New("telemt: " + dcsPath + ": the answer is not a success")
	}
	h := engines.EngineHealth{MiddleProxy: answer.Data.MiddleProxy, Reason: clipReason(answer.Data.Reason)}
	for _, dc := range answer.Data.DCs {
		d := engines.DCHealth{
			DC: dc.DC, AvailableEndpoints: max(dc.AvailableEndpoints, 0),
			AvailablePct: pct(dc.AvailablePct), CoveragePct: pct(dc.CoveragePct),
		}
		if dc.FreshCoveragePct != nil {
			d.FreshCoveragePct, d.HasFreshCoverage = pct(*dc.FreshCoveragePct), true
		}
		h.DCs = append(h.DCs, d)
	}
	return h, nil
}

func pct(v float64) float64 {
	if math.IsNaN(v) {
		return 0
	}
	return min(max(v, 0), 100)
}

// clipReason keeps a reason short: telemt's are words like
// "source_unavailable".
func clipReason(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}
