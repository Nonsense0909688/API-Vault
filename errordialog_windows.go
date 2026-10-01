//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// showError pops a dialog, because the exe is usually started by
// double-clicking it and the console window disappears with the process.
func showError(err error) {
	windows.MessageBox(
		0,
		windows.StringToUTF16Ptr(fmt.Sprintf("API-Vault Error:\n\n%v", err)),
		windows.StringToUTF16Ptr("API-Vault"),
		windows.MB_OK|windows.MB_ICONERROR,
	)
}
