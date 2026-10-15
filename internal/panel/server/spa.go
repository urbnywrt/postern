package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

// spa serves the files of the UI, and index.html for every path that is not a
// file, so that the router of the page, which runs in the browser, decides what
// the path means: /setup, /nodes, a link that was copied from the address bar.
//
// The files are read once, when the handler is made, and served from memory: a
// build of the UI is a few hundred kilobytes, and nothing about a request can
// reach the file system. Files whose names start with a dot are left out.
//
// Each response has a write deadline (spaWriteTimeout), so that a client that
// reads slowly, or not at all, cannot hold its connection and its goroutine for
// as long as it likes. The HTTP server has no write timeout of its own, because
// a response of the API may be a stream and must not be cut off; the files of
// the UI never are streams, so they set the deadline themselves.
type spa struct {
	files map[string]*asset // by slash-separated path, without a leading slash
	index *asset

	// writeTimeout is the time that a response has to be written in; 0 sets no
	// deadline. newSPA makes it spaWriteTimeout, and tests make it shorter.
	writeTimeout time.Duration
}

// An asset is one file of the UI, ready to be served.
type asset struct {
	data         []byte
	contentType  string
	cacheControl string
	etag         string
}

const (
	// A file under assets/ has a hash of its content in its name (that is how
	// the build of the UI names them), so it never changes and can be kept for
	// good.
	immutable = "public, max-age=31536000, immutable"
	// The rest, index.html above all, is checked with the server each time. The
	// ETag makes that a 304 when nothing changed, and an update of the panel is
	// seen at once.
	revalidate = "no-cache"

	// spaWriteTimeout is how long a response for a file of the UI has to be
	// written. The biggest file of a build is under a megabyte, so a client
	// that has not taken it in a minute is not reading it.
	spaWriteTimeout = 60 * time.Second
)

// contentTypes are the types of the files of a web UI. They are listed so that
// the answer does not depend on the type tables of the host, which are not the
// same everywhere, and are not there at all in a small image.
var contentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".htm":         "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".map":         "application/json",
	".webmanifest": "application/manifest+json",
	".txt":         "text/plain; charset=utf-8",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".gif":         "image/gif",
	".webp":        "image/webp",
	".avif":        "image/avif",
	".ico":         "image/x-icon",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
	".ttf":         "font/ttf",
	".otf":         "font/otf",
	".wasm":        "application/wasm",
}

func contentTypeOf(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if t, ok := contentTypes[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	return "application/octet-stream"
}

// newSPA reads the files of fsys. It is an error if there is no index.html.
func newSPA(fsys fs.FS) (*spa, error) {
	s := &spa{files: map[string]*asset{}, writeTimeout: spaWriteTimeout}
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name != "." && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		cache := revalidate
		if strings.HasPrefix(name, "assets/") {
			cache = immutable
		}
		s.files[name] = &asset{
			data:         data,
			contentType:  contentTypeOf(name),
			cacheControl: cache,
			etag:         `"` + hex.EncodeToString(sum[:16]) + `"`,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read the UI: %w", err)
	}
	s.index = s.files["index.html"]
	if s.index == nil {
		return nil, errors.New("the UI has no index.html")
	}
	return s, nil
}

func (s *spa) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The path is looked up as it is, among the files that were read above, and
	// nowhere else: a path that is not one of them, with dots or slashes in odd
	// places or not, is the page, and nothing outside the UI can be named.
	a := s.files[strings.TrimPrefix(r.URL.Path, "/")]
	if a == nil {
		a = s.index
	}
	h := w.Header()
	h.Set("Content-Type", a.contentType)
	h.Set("Cache-Control", a.cacheControl)
	h.Set("ETag", a.etag)
	// The deadline is for this response alone: net/http takes it off the
	// connection when the handler is done, so that the next request on a kept
	// connection, an API call for one, does not start with it. A ResponseWriter
	// that has no deadlines (a test recorder) says so with an error, and there
	// is nothing to bound then.
	if s.writeTimeout > 0 {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(s.writeTimeout))
	}
	// ServeContent answers If-None-Match with a 304, ranges, and HEAD.
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(a.data))
}
