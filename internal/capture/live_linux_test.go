//go:build linux

package capture

import (
	"errors"
	"os"
	"testing"
)

// An unprivileged capture must explain how to get the privilege.
//
// The hint is the whole point of PermissionError, and it was unreachable:
// pcapgo formats the errno with %s, so errors.Is(err, os.ErrPermission) —
// what this used to test for — is false no matter what went wrong, and every
// unprivileged user got a bare "operation not permitted" instead.
func TestOpenLiveWithoutPrivilegeExplainsHow(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; there is no permission error to classify")
	}

	src, err := OpenLive("lo", LiveOptions{})
	if err == nil {
		src.Close()
		t.Skip("capture is permitted without root; CAP_NET_RAW must be granted to the test binary")
	}

	var pe *PermissionError
	if !errors.As(err, &pe) {
		t.Fatalf("OpenLive without CAP_NET_RAW returned %T (%v), want *PermissionError", err, err)
	}
	if pe.Hint == "" {
		t.Error("PermissionError carries no hint, which is the only reason the type exists")
	}
}

// A name that is not an interface is a different failure, and must not be
// reported as a permission problem even when the caller is unprivileged.
func TestOpenLiveUnknownInterfaceIsNotAPermissionError(t *testing.T) {
	_, err := OpenLive("definitely-not-an-interface0", LiveOptions{})
	if err == nil {
		t.Fatal("OpenLive on a nonexistent interface returned no error")
	}
	var pe *PermissionError
	if errors.As(err, &pe) {
		t.Errorf("nonexistent interface reported as a permission problem: %v", err)
	}
}
