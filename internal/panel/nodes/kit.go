package nodes

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/urbnywrt/postern/internal/panel/auth"
)

// The node kit is what a node is installed from by hand, together with its
// bundle: the postern-node binary of the version of the panel, and the
// installer, deploy/node/install.sh, with the two files that it installs,
// launcher.sh and compose.yaml. The panel image carries a kit for each
// architecture that nodes run on, in one directory ([DefaultKitDir]):
//
//	<dir>/install.sh
//	<dir>/launcher.sh
//	<dir>/compose.yaml
//	<dir>/amd64/postern-node
//	<dir>/arm64/postern-node
//
// and the panel serves it to admins as one tar file per architecture (see
// [Service.KitHandler]). So a node is installed without a release host, also
// before there is any release, and it runs the version of the panel. What the
// panel has is looked at for each request, not once.

const (
	// DefaultKitDir is the directory of the node kit in the panel image.
	DefaultKitDir = "/usr/local/share/postern/node-kit"

	// KitRoute is the pattern under which the panel serves [Service.KitHandler]
	// in an [http.ServeMux]; the handler reads the architecture from {arch}.
	// The pattern has no method, so that every method reaches the handler and
	// one other than GET and HEAD gets its 405, not the 404 of the API.
	KitRoute = "/api/node-kit/{arch}"

	// archPlaceholder stands for the architecture of the kit in
	// installCommand. The UI puts in the one that the admin picks.
	archPlaceholder = "<ARCH>"

	// installCommand installs a node from its bundle and the kit of its
	// architecture, both downloaded under their names into the directory that
	// the command runs in. CreateNode and GetNodeInstall return it.
	installCommand = "tar -xf " + kitFilePrefix + archPlaceholder + kitFileSuffix +
		" && sudo bash install.sh --bundle " + bundleFileName + " --binary ./" + kitBinary

	// The name that the kit of an architecture is downloaded as is
	// kitFilePrefix + arch + kitFileSuffix.
	kitFilePrefix = "postern-node-kit-linux-"
	kitFileSuffix = ".tar"

	// kitBinary is the name of the binary, in the kit directory (under the
	// directory of its architecture) and in the tar.
	kitBinary = "postern-node"

	// tarBlock is the size of a block of a tar file: a header is one, the
	// content of a member is padded to whole blocks, and two blocks of zeros
	// end the archive.
	tarBlock = 512
	// maxKitFile is the largest file that a USTAR header can give the size of
	// (eleven octal digits).
	maxKitFile = 1<<33 - 1

	// kitWriteTimeout is how long the response of a kit has to be written in:
	// a tar of some 16 MB, which takes minutes on a slow link, not a quarter of
	// an hour. A client that stops reading is let go then, and the files that
	// the handler holds open are closed. The HTTP server has no write timeout of
	// its own, since a response of the API may be a stream.
	kitWriteTimeout = 15 * time.Minute
)

// kitArches are the architectures that there are kits for, in the order of
// GetNodeInstall.
var kitArches = []string{"amd64", "arm64"}

// kitMembers are the members of the tar of a kit, in their order, with the
// mode that each has in the tar, whatever the mode of its file.
var kitMembers = []struct {
	name string
	mode int64
}{
	{kitBinary, 0o755},
	{"install.sh", 0o755},
	{"launcher.sh", 0o755},
	{"compose.yaml", 0o644},
}

// errKitChanged is the error of a file of a kit that got shorter after it was
// opened, so that its member cannot be sent whole.
var errKitChanged = errors.New("a file of the node kit got shorter while it was sent")

// An Option changes a Service that NewService makes.
type Option func(*Service)

// WithKitDir makes the service serve the node kit from dir, which is laid out
// as [DefaultKitDir] is in the panel image. Without it, or with an empty dir,
// the panel has no kit.
func WithKitDir(dir string) Option {
	return func(s *Service) { s.kitDir = dir }
}

// WithKitSource makes the kit download and [Service.OpenKitFor] send the node
// binary that src gives (the running panel's version) instead of the one in
// the image kit; the scripts still come from the image kit.
func WithKitSource(src KitSource) Option {
	return func(s *Service) { s.kitSrc = src }
}

// openKitFor opens the kit of arch, with the binary of the kit source when the
// service has one. A source that cannot give a binary leaves the image's, as
// does one whose binary is not a file (the tar needs its size first).
func (s *Service) openKitFor(ctx context.Context, arch string) (*openedKit, error) {
	k, err := openKit(s.kitDir, arch)
	if err != nil || s.kitSrc == nil {
		return k, err
	}
	r, _, version, err := s.kitSrc.NodeBinary(ctx, arch)
	if err != nil {
		s.log.Warn("the node kit sends the binary of the panel image: the kit source has none", "arch", arch, "err", err)
		return k, nil
	}
	f, ok := r.(*os.File)
	var fi os.FileInfo
	if ok {
		fi, err = f.Stat()
	}
	if !ok || err != nil || !fi.Mode().IsRegular() || fi.Size() > maxKitFile {
		_ = r.Close()
		s.log.Warn("the node kit sends the binary of the panel image: the binary of the kit source is not a file", "arch", arch)
		return k, nil
	}
	_ = k.files[0].Close() // kitMembers[0] is the binary
	k.files[0], k.sizes[0] = f, fi.Size()
	if version != "" {
		s.log.Debug("the node kit sends a node binary of the panel's version", "arch", arch, "version", version)
	}
	return k, nil
}

// KitURL is the path at which an admin downloads the node kit of arch.
func KitURL(arch string) string {
	return "/api/node-kit/" + url.PathEscape(arch)
}

// kitFileName is the name that the kit of arch is downloaded as.
func kitFileName(arch string) string {
	return kitFilePrefix + arch + kitFileSuffix
}

// KitArches returns the architectures whose node kit the panel has, in the
// order of the API. When it lacks one, missing says what is wrong with the
// first one that it lacks.
func (s *Service) KitArches() (arches []string, missing error) {
	for _, arch := range kitArches {
		k, err := openKit(s.kitDir, arch)
		if err != nil {
			if missing == nil {
				missing = err
			}
			continue
		}
		k.close()
		arches = append(arches, arch)
	}
	return arches, missing
}

// kitAvailable reports whether the panel has the kit of arch: whether it
// could serve it now.
func (s *Service) kitAvailable(arch string) bool {
	k, err := openKit(s.kitDir, arch)
	if err != nil {
		return false
	}
	k.close()
	return true
}

// hasKitDir reports whether the directory of the node kit is there, which it
// is in the panel image: a kit that cannot be served then is a fault.
func (s *Service) hasKitDir() bool {
	if s.kitDir == "" {
		return false
	}
	fi, err := os.Stat(s.kitDir)
	return err == nil && fi.IsDir()
}

// kitTimeout is how long a kit download has to be written in: kitWriteTimeout,
// unless a test has made it shorter with kitTimeoutOverride.
func (s *Service) kitTimeout() time.Duration {
	if s.kitTimeoutOverride > 0 {
		return s.kitTimeoutOverride
	}
	return kitWriteTimeout
}

// KitHandler serves the node kit of an architecture as an attachment,
// postern-node-kit-linux-<arch>.tar: a tar file of four regular files at its
// top level, in this order,
//
//	postern-node   0755  the node binary of the architecture
//	install.sh     0755
//	launcher.sh    0755
//	compose.yaml   0644
//
// that belong to uid and gid 0, without user or group names, and have the Unix
// epoch as their time, so that the same files make the same tar. The tar is
// USTAR, which every tar reads, and it is written as it is sent, with a
// Content-Length.
//
// The handler reads the architecture from {arch} (see [KitRoute]). Only amd64
// and arm64 are architectures; anything else is a 404, and so is an
// architecture whose kit the panel does not have. It is wrapped in
// [auth.RequireAdmin]: a request without an admin session gets a 401. It
// answers GET and HEAD, and every other method with a 405.
//
// Each file is opened before the response starts, and its member is as large
// as the file was then: exactly that much of it is sent, so a file that grows
// meanwhile does not change the tar. One that shrinks cannot be sent whole.
// Then, as for every error once the response has begun, the error is logged
// and the connection is cut, so that the client never takes a tar that was cut
// short for a whole one. The response has a write deadline (kitWriteTimeout).
//
// When the panel has a kit (its directory is there) and the kit of the
// architecture cannot be served, the 404 is logged as a warning with the
// reason; a panel without a kit (one that runs with go run) logs nothing.
func (s *Service) KitHandler() http.Handler {
	return auth.RequireAdmin(http.HandlerFunc(s.serveKit))
}

func (s *Service) serveKit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	arch := r.PathValue("arch")
	if !slices.Contains(kitArches, arch) {
		http.Error(w, "no such node kit: there are kits for amd64 and arm64", http.StatusNotFound)
		return
	}
	k, err := s.openKitFor(r.Context(), arch)
	if err != nil {
		if s.hasKitDir() {
			s.log.Warn("a node kit that was asked for cannot be served", "arch", arch, "err", err)
		}
		http.Error(w, "this panel image carries no node kit for "+arch, http.StatusNotFound)
		return
	}
	defer k.close()

	// Before the first byte: the deadline bounds the whole response.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(s.kitTimeout()))
	h := w.Header()
	h.Set("Content-Type", "application/x-tar")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": kitFileName(arch)}))
	h.Set("Content-Length", strconv.FormatInt(k.tarSize(), 10))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}

	adminID := adminIDOf(r.Context())
	if err := k.writeTar(w); err != nil {
		if errors.Is(err, errKitChanged) {
			s.log.Error("could not send a node kit", "arch", arch, "admin", adminID, "err", err)
		} else {
			s.log.Warn("the download of a node kit was cut off", "arch", arch, "admin", adminID, "err", err)
		}
		// The status and the length are sent, and the tar is not whole: the
		// connection is cut, which net/http does without a log of its own.
		panic(http.ErrAbortHandler)
	}
	s.log.Info("node kit downloaded", "arch", arch, "admin", adminID)
}

// openedKit is the kit of one architecture with its files open, in the order
// of kitMembers, and the size of each as it was when it was opened.
type openedKit struct {
	files []*os.File
	sizes []int64
}

// openKit opens the files of the kit of arch in dir, and checks them: the
// binary is a regular file that can be executed, and the scripts are regular
// files. The error says what is missing or wrong.
func openKit(dir, arch string) (*openedKit, error) {
	if dir == "" {
		return nil, errors.New("no directory of the node kit is set")
	}
	// arch is a name in a path, so it is one of the few, and nothing else.
	if !slices.Contains(kitArches, arch) {
		return nil, fmt.Errorf("there is no node kit for %q", arch)
	}
	k := &openedKit{}
	for _, m := range kitMembers {
		path := filepath.Join(dir, m.name)
		if m.name == kitBinary {
			path = filepath.Join(dir, arch, m.name)
		}
		f, size, err := openKitFile(path, m.name == kitBinary)
		if err != nil {
			k.close()
			return nil, err
		}
		k.files = append(k.files, f)
		k.sizes = append(k.sizes, size)
	}
	return k, nil
}

// openKitFile opens a file of a kit and returns it with its size, which is
// taken from the file that is open, so that it is the size of what is read
// even when the path is given another file meanwhile.
//
// What is not a regular file is refused before it is opened: opening a FIFO
// waits for a writer, for ever, and opening a device may do something. See
// openCheckedKitFile for a path that is given another file after this look.
func openKitFile(path string, executable bool) (*os.File, int64, error) {
	fi, err := os.Stat(path)
	if err == nil {
		err = kitFileProblem(path, fi, executable)
	}
	if err != nil {
		return nil, 0, err
	}
	return openCheckedKitFile(path, executable)
}

// openCheckedKitFile opens the file of a kit at path, and checks the file that
// is open, which also gives the size of what is read. It opens without waiting
// (O_NONBLOCK, which a read of a regular file does not heed), so that a FIFO
// that the path was given after openKitFile looked at it does not hold the
// request.
func openCheckedKitFile(path string, executable bool) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err == nil {
		err = kitFileProblem(path, fi, executable)
	}
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

// kitFileProblem says what is wrong with the file of a kit at path that fi
// describes: it is not a regular file, it is the binary and cannot be
// executed, or it is too large for a tar file.
func kitFileProblem(path string, fi os.FileInfo, executable bool) error {
	switch {
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", path)
	case executable && fi.Mode().Perm()&0o111 == 0:
		return fmt.Errorf("%s is not executable", path)
	case fi.Size() > maxKitFile:
		return fmt.Errorf("%s is larger than a tar file can hold", path)
	}
	return nil
}

func (k *openedKit) close() {
	for _, f := range k.files {
		_ = f.Close()
	}
}

// tarSize is the size of the tar that writeTar writes: for each member a
// header block and its content padded to whole blocks, and the two blocks of
// zeros that end the archive.
func (k *openedKit) tarSize() int64 {
	total := int64(2 * tarBlock)
	for _, size := range k.sizes {
		total += tarBlock + (size+tarBlock-1)/tarBlock*tarBlock
	}
	return total
}

// writeTar writes the tar of the kit to w, each member exactly as large as its
// file was when it was opened.
func (k *openedKit) writeTar(w io.Writer) error {
	tw := tar.NewWriter(w)
	for i, m := range kitMembers {
		err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     m.name,
			Mode:     m.mode,
			Size:     k.sizes[i],
			ModTime:  time.Unix(0, 0),
			Format:   tar.FormatUSTAR,
		})
		if err != nil {
			return err
		}
		if _, err := io.CopyN(tw, k.files[i], k.sizes[i]); err != nil {
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("%w: %s", errKitChanged, k.files[i].Name())
			}
			return err
		}
	}
	return tw.Close()
}
