package nodeupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
)

// chunkSize is the size of the messages of an UpdateSelf upload.
const chunkSize = 256 << 10

// maxBinary bounds a node binary that is held in memory to be sent (one that
// is not a file).
const maxBinary = 256 << 20

// binary is a node binary to send: its bytes from the start, its size and its
// SHA-256.
type binary struct {
	r    io.Reader
	size uint64
	sha  string
}

// measure reads r once for its size and SHA-256, and returns a binary that
// reads it from the start again: a file is sought back, anything else is held
// in memory (at most maxBinary bytes).
func measure(r io.Reader) (*binary, error) {
	h := sha256.New()
	if f, ok := r.(*os.File); ok {
		n, err := io.Copy(h, f)
		if err != nil {
			return nil, err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return &binary{r: f, size: uint64(n), sha: hex.EncodeToString(h.Sum(nil))}, nil
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBinary+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBinary {
		return nil, fmt.Errorf("the node binary is larger than %d bytes", maxBinary)
	}
	h.Write(data)
	return &binary{r: bytes.NewReader(data), size: uint64(len(data)), sha: hex.EncodeToString(h.Sum(nil))}, nil
}

// updateSelf sends the binary to the node with UpdateSelf: the meta first,
// then the chunks.
func updateSelf(ctx context.Context, c nodev1connect.NodeServiceClient, meta *nodev1.NodeBinary, b *binary) (*nodev1.UpdateSelfResponse, error) {
	stream := c.UpdateSelf(ctx)
	send := func(req *nodev1.UpdateSelfRequest) error {
		err := stream.Send(req)
		if errors.Is(err, io.EOF) {
			// The node answered early (a refusal): the answer says why.
			_, rerr := stream.CloseAndReceive()
			if rerr != nil {
				return rerr
			}
		}
		return err
	}
	if err := send(&nodev1.UpdateSelfRequest{Part: &nodev1.UpdateSelfRequest_Meta{Meta: meta}}); err != nil {
		return nil, err
	}
	buf := make([]byte, chunkSize)
	for {
		n, rerr := b.r.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			if err := send(&nodev1.UpdateSelfRequest{Part: &nodev1.UpdateSelfRequest_Chunk{Chunk: chunk}}); err != nil {
				return nil, err
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			_, _ = stream.CloseAndReceive()
			return nil, rerr
		}
	}
	resp, err := stream.CloseAndReceive()
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// updateEdge asks the node to roll its edge to the version.
func updateEdge(ctx context.Context, c nodev1connect.NodeServiceClient, version string, rollback bool) (*nodev1.UpdateEdgeResponse, error) {
	resp, err := c.UpdateEdge(ctx, connect.NewRequest(&nodev1.UpdateEdgeRequest{Version: version, Rollback: rollback}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// getInfo asks the node about itself.
func getInfo(ctx context.Context, c nodev1connect.NodeServiceClient) (*nodev1.GetInfoResponse, error) {
	resp, err := c.GetInfo(ctx, connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// transient reports whether an error of a call to the node may go away when
// the call is made again: the node is busy or restarting, or the connection
// went away. A refusal (a bad binary, a version the node does not take) is
// not.
func transient(err error) bool {
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeUnknown, connect.CodeCanceled, connect.CodeDeadlineExceeded:
		return true
	}
	return false
}
