//go:build !linux && !darwin && !windows

package capture

// OpenLive is not implemented on this platform. Capture-file reading is,
// and is the same code path everywhere.
func OpenLive(iface string, opts LiveOptions) (Source, error) {
	return nil, ErrUnsupportedPlatform
}
