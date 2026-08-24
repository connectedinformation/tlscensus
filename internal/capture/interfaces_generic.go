//go:build !windows

package capture

// Everywhere but Windows the capture backend takes the same interface names
// the operating system uses, so the standard library listing is authoritative.
func platformInterfaces() ([]InterfaceInfo, error) { return stdlibInterfaces() }
