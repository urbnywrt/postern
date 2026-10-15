package diagnostics

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// The sources of the journal, and the page sizes of ListJournal.
const (
	sourceEvents        = "events"
	sourceAudit         = "audit"
	defaultJournalLimit = 50
	maxJournalLimit     = 200
)

// errCursor is a cursor that is not one of ListJournal's, or of another
// source.
var errCursor = errors.New("the cursor is not valid")

// encodeCursor makes the opaque cursor of the row that a page ended with: the
// source, the second and the id.
func encodeCursor(source string, c store.Cursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(source[:1] + ":" + strconv.FormatInt(c.TS.Unix(), 10) + ":" + c.ID))
}

func decodeCursor(source, s string) (*store.Cursor, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errCursor
	}
	parts := strings.SplitN(string(raw), ":", 3)
	if len(parts) != 3 || parts[0] != source[:1] || parts[2] == "" {
		return nil, errCursor
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || ts < 0 {
		return nil, errCursor
	}
	return &store.Cursor{TS: time.Unix(ts, 0).UTC(), ID: parts[2]}, nil
}

func invalid(msg string) error {
	return connect.NewError(connect.CodeInvalidArgument, errors.New(msg))
}

func unixTime(s int64) time.Time {
	if s == 0 {
		return time.Time{}
	}
	return time.Unix(s, 0).UTC()
}

// ListJournal returns a page of the events or of the audit log, newest first.
func (s *Service) ListJournal(ctx context.Context, req *connect.Request[panelv1.ListJournalRequest]) (*connect.Response[panelv1.ListJournalResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	m := req.Msg
	source := m.GetSource()
	if source == "" {
		source = sourceEvents
	}
	limit := int(m.GetLimit())
	switch {
	case limit == 0:
		limit = defaultJournalLimit
	case limit > maxJournalLimit:
		return nil, invalid("limit is at most 200")
	}
	from, to := m.GetFromUnix(), m.GetToUnix()
	if from < 0 || to < 0 || (from != 0 && to != 0 && from >= to) {
		return nil, invalid("from_unix and to_unix must be a range of Unix seconds")
	}
	switch source {
	case sourceEvents:
		if m.GetAdminId() != "" || m.GetActionPrefix() != "" {
			return nil, invalid("admin_id and action_prefix filter the audit log, not the events")
		}
		if _, ok := store.SeverityRank(m.GetMinSeverity()); m.GetMinSeverity() != "" && !ok {
			return nil, invalid("min_severity is info, warning or error")
		}
	case sourceAudit:
		if m.GetNodeId() != "" || m.GetProxyId() != "" || m.GetMinSeverity() != "" || m.GetKindPrefix() != "" {
			return nil, invalid("node_id, proxy_id, min_severity and kind_prefix filter the events, not the audit log")
		}
	default:
		return nil, invalid(`source is "events" or "audit"`)
	}
	before, err := decodeCursor(source, m.GetCursor())
	if err != nil {
		return nil, invalid(err.Error())
	}
	out := &panelv1.ListJournalResponse{}
	// Nodes and probes wrote the text: it is shown without client addresses
	// and secrets.
	txt := newTexts(s.db, s.key, s.log)
	if source == sourceEvents {
		es, err := s.db.ListEventsFiltered(ctx, store.EventFilter{NodeID: m.GetNodeId(), ProxyID: m.GetProxyId(),
			MinSeverity: m.GetMinSeverity(), KindPrefix: m.GetKindPrefix(), From: unixTime(from), To: unixTime(to),
			Before: before, Limit: limit + 1})
		if err != nil {
			return nil, s.fail("could not read the events", err)
		}
		if len(es) > limit {
			es = es[:limit]
			last := es[limit-1]
			out.NextCursor = encodeCursor(source, store.Cursor{TS: last.TS, ID: last.ID})
		}
		for _, e := range es {
			sc, err := txt.ofNode(ctx, e.NodeID)
			if err != nil {
				return nil, s.fail("could not clean the events", err)
			}
			out.Events = append(out.Events, &panelv1.JournalEvent{Id: e.ID, TsUnix: e.TS.Unix(), NodeId: e.NodeID, ProxyId: e.ProxyID,
				Kind: e.Kind, Severity: e.Severity, Message: sc.Clean(e.Message), Details: cleanMap(sc, e.Details)})
		}
		return connect.NewResponse(out), nil
	}
	as, err := s.db.ListAudit(ctx, store.AuditFilter{AdminID: m.GetAdminId(), ActionPrefix: m.GetActionPrefix(),
		From: unixTime(from), To: unixTime(to), Before: before, Limit: limit + 1})
	if err != nil {
		return nil, s.fail("could not read the audit log", err)
	}
	if len(as) > limit {
		as = as[:limit]
		last := as[limit-1]
		out.NextCursor = encodeCursor(source, store.Cursor{TS: last.TS, ID: last.ID})
	}
	sc, err := txt.ofNode(ctx, "")
	if err != nil {
		return nil, s.fail("could not clean the audit log", err)
	}
	names := map[string]string{}
	for _, a := range as {
		name, ok := names[a.AdminID]
		if !ok && a.AdminID != "" {
			switch admin, err := s.db.AdminByID(ctx, a.AdminID); {
			case err == nil:
				name = admin.Username
			case !errors.Is(err, store.ErrNotFound):
				return nil, s.fail("could not read an admin", err)
			}
			names[a.AdminID] = name
		}
		out.Audit = append(out.Audit, &panelv1.JournalAudit{Id: a.ID, TsUnix: a.TS.Unix(), AdminId: a.AdminID, AdminName: name,
			Action: a.Action, Target: a.Target, Details: cleanMap(sc, a.Details)})
	}
	return connect.NewResponse(out), nil
}
