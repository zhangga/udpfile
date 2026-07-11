package main

import "testing"

func TestResolveLoopbackListenAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		resolved, err := resolveLoopbackListenAddress(address)
		if err != nil {
			t.Errorf("resolveLoopbackListenAddress(%q) error = %v", address, err)
		} else if !resolved.IP.IsLoopback() {
			t.Errorf("resolveLoopbackListenAddress(%q) resolved to non-loopback %s", address, resolved.IP)
		}
	}
	for _, address := range []string{"0.0.0.0:8080", "192.168.1.20:8080", ":8080", "example.com:8080"} {
		if _, err := resolveLoopbackListenAddress(address); err == nil {
			t.Errorf("resolveLoopbackListenAddress(%q) accepted a non-loopback address", address)
		}
	}
}
