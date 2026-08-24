//go:build darwin

package capture

import "runtime"

func runtimeKeepAlive(v any) { runtime.KeepAlive(v) }
