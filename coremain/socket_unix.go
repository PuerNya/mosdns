//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package coremain

import (
	"net"
	"syscall"
)

func createListenConfig() net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var e error
			err := c.Control(func(fd uintptr) {
				e = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if e != nil {
					return
				}
				e = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
				if e != nil {
					return
				}
				e = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 64*1024)
				if e != nil {
					return
				}
				e = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 64*1024)
			})
			if err != nil {
				return err
			}
			if e != nil {
				return e
			}
			return nil
		},
	}
}
