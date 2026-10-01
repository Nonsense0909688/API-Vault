//go:build !windows

package main

import "log"

// showError is the non-Windows counterpart of the message box: on Linux and
// macOS the server is run from a terminal or a service manager, so the error
// belongs on stderr where the rest of the log already goes.
func showError(err error) {
	log.Printf("[ERROR] %v", err)
}
