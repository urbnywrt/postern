package geodb

import (
	"errors"
	"net/http"
	"strconv"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/panel/auth"
)

// UploadRoute is the path of the upload: PUT, with the database as the body. A
// panel mounts [Manager.UploadHandler] under it.
const UploadRoute = "/api/geoip"

// UploadHandler is PUT /api/geoip: an admin sends the database, for a panel that
// cannot reach DB-IP. The body is the file as it is, or gzipped as DB-IP
// publishes it (told by its first bytes), and at most 256 MiB. The answer is the
// status of the database as JSON, a GeoIPStatus; a file that is not a country
// database is a 400 that says why, one that is too large a 413, and the
// database that the panel had stays in use in both cases. A successful upload is
// audited as geoip.upload.
//
// The route is not a Connect procedure, which the auth middleware would guard by
// itself, so the handler is wrapped in [auth.RequireAdmin]: a request without an
// admin session gets a 401 before its body is read. Any method but PUT is a 405.
func (m *Manager) UploadHandler() http.Handler {
	return auth.RequireAdmin(http.HandlerFunc(m.serveUpload))
}

func (m *Manager) serveUpload(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodPut {
		h.Set("Allow", http.MethodPut)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tooLarge := (&sizeError{what: "upload", limit: m.maxUpload}).Error()
	if r.ContentLength > m.maxUpload {
		http.Error(w, tooLarge, http.StatusRequestEntityTooLarge)
		return
	}

	st, err := m.Install(r.Context(), http.MaxBytesReader(w, r.Body, m.maxUpload))
	var overRun *http.MaxBytesError
	var oversize *sizeError
	switch {
	case err == nil:
	case errors.As(err, &oversize):
		// What was too large: the upload, or what it unpacks to.
		http.Error(w, oversize.Error(), http.StatusRequestEntityTooLarge)
		return
	case errors.As(err, &overRun):
		http.Error(w, tooLarge, http.StatusRequestEntityTooLarge)
		return
	case errors.Is(err, geoip.ErrInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case r.Context().Err() != nil:
		return // the admin went away: nobody is left to answer
	default:
		m.log.Error("could not install an uploaded country database", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	admin, _ := auth.AdminFrom(r.Context())
	adminID := ""
	if admin != nil {
		adminID = admin.ID
	}
	m.audit(r.Context(), adminID, auditUpload, map[string]string{
		"month":  st.Month,
		"sha256": st.SHA256,
		"size":   strconv.FormatInt(st.Size, 10),
	})
	m.log.Info("country database uploaded", "month", st.Month, "bytes", st.Size, "admin", adminID)

	data, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(statusProto(st))
	if err != nil {
		m.log.Error("could not encode the status of the country database", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data) // the client is gone if this fails
}
