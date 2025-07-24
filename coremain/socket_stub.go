//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package coremain

import (
	"net"
)

func createListenConfig() net.ListenConfig {
	return net.ListenConfig{}
}
