package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestSSHTargetRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	db.now = fixedClock(testNow.Add(400 * time.Millisecond))

	in := &SSHTarget{
		NodeID:      n.ID,
		Host:        "192.0.2.10",
		Port:        2222,
		User:        "deploy",
		HostKey:     "SHA256:made-up-fingerprint",
		HostKeyType: "ssh-ed25519",
		AuthKind:    SSHAuthKey,
		SecretEnc:   []byte("sealed-credentials"),
	}
	if err := db.PutSSHTarget(ctx, in); err != nil {
		t.Fatalf("PutSSHTarget: %v", err)
	}
	want := SSHTarget{
		NodeID: n.ID, Host: "192.0.2.10", Port: 2222, User: "deploy",
		HostKey: "SHA256:made-up-fingerprint", HostKeyType: "ssh-ed25519",
		AuthKind: SSHAuthKey, SecretEnc: []byte("sealed-credentials"), UpdatedAt: testNow,
	}
	if !reflect.DeepEqual(*in, want) {
		t.Errorf("the record after PutSSHTarget = %+v, want %+v", *in, want)
	}
	got, err := db.SSHTargetByNode(ctx, n.ID)
	if err != nil {
		t.Fatalf("SSHTargetByNode: %v", err)
	}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("SSHTargetByNode = %+v, want %+v", *got, want)
	}
}

// Putting a target again replaces it; forgetting the credentials leaves no
// sealed bytes behind.
func TestPutSSHTargetReplaces(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	db.now = fixedClock(testNow)
	first := &SSHTarget{NodeID: n.ID, Host: "192.0.2.10", Port: 22, User: "root",
		AuthKind: SSHAuthPassword, SecretEnc: []byte("sealed-password")}
	if err := db.PutSSHTarget(ctx, first); err != nil {
		t.Fatal(err)
	}

	db.now = fixedClock(testNow.Add(time.Hour))
	second := &SSHTarget{NodeID: n.ID, Host: "192.0.2.11", Port: 22, User: "root",
		HostKey: "SHA256:another", HostKeyType: "ecdsa-sha2-nistp256"}
	if err := db.PutSSHTarget(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err := db.SSHTargetByNode(ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := SSHTarget{NodeID: n.ID, Host: "192.0.2.11", Port: 22, User: "root",
		HostKey: "SHA256:another", HostKeyType: "ecdsa-sha2-nistp256", UpdatedAt: testNow.Add(time.Hour)}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("after the second put: %+v, want %+v", *got, want)
	}
	if c := count(t, db, `SELECT count(*) FROM ssh_targets WHERE secret_enc IS NOT NULL`); c != 0 {
		t.Errorf("%d rows still hold sealed credentials", c)
	}
}

func TestSSHTargetOfAnUnknownNode(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.SSHTargetByNode(ctx, "NOPE"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SSHTargetByNode of a node without a target: err = %v, want ErrNotFound", err)
	}
	err := db.PutSSHTarget(ctx, &SSHTarget{NodeID: "NOPE", Host: "192.0.2.10", Port: 22, User: "root"})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("PutSSHTarget for a node that does not exist: err = %v, want ErrNotFound", err)
	}
}

func TestDeleteSSHTarget(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	if err := db.PutSSHTarget(ctx, &SSHTarget{NodeID: n.ID, Host: "192.0.2.10", Port: 22, User: "root"}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteSSHTarget(ctx, n.ID); err != nil {
		t.Fatalf("DeleteSSHTarget: %v", err)
	}
	if _, err := db.SSHTargetByNode(ctx, n.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after the delete: err = %v, want ErrNotFound", err)
	}
	// Deleting what is not there is not an error.
	if err := db.DeleteSSHTarget(ctx, n.ID); err != nil {
		t.Errorf("second DeleteSSHTarget: %v", err)
	}
}

// The credentials of a node go with the node.
func TestSSHTargetGoesWithItsNode(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	if err := db.PutSSHTarget(ctx, &SSHTarget{NodeID: n.ID, Host: "192.0.2.10", Port: 22, User: "root",
		AuthKind: SSHAuthPassword, SecretEnc: []byte("sealed-password")}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteNode(ctx, n.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if c := count(t, db, `SELECT count(*) FROM ssh_targets`); c != 0 {
		t.Errorf("%d SSH targets are left after their node was deleted", c)
	}
}

// The schema takes no kind of credentials that the panel does not know.
func TestSSHTargetAuthKindIsChecked(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	for _, kind := range []string{"token", "Password", "agent"} {
		if err := db.PutSSHTarget(ctx, &SSHTarget{NodeID: n.ID, Host: "192.0.2.10", Port: 22, User: "root", AuthKind: kind}); err == nil {
			t.Errorf("auth kind %q was stored", kind)
		}
	}
	for _, kind := range []string{SSHAuthNone, SSHAuthPassword, SSHAuthKey} {
		if err := db.PutSSHTarget(ctx, &SSHTarget{NodeID: n.ID, Host: "192.0.2.10", Port: 22, User: "root", AuthKind: kind}); err != nil {
			t.Errorf("auth kind %q: %v", kind, err)
		}
	}
}

func TestSSHTargetPortRange(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	for _, port := range []uint32{0, 65536} {
		if err := db.PutSSHTarget(ctx, &SSHTarget{NodeID: n.ID, Host: "192.0.2.10", Port: port, User: "root"}); err == nil {
			t.Errorf("port %d was stored", port)
		}
	}
}
