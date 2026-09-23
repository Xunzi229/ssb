//go:build windows

package service

import (
	"syscall"
	"unsafe"
)

func enableWindowsVT() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getStdHandle := kernel32.NewProc("GetStdHandle")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	handle, _, _ := getStdHandle.Call(^uintptr(10)) // STD_OUTPUT_HANDLE = -11
	if handle == 0 || handle == ^uintptr(0) {
		return false
	}
	var mode uint32
	r, _, _ := getConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return false
	}
	const enableVirtualTerminalProcessing = 0x0004
	r, _, _ = setConsoleMode.Call(handle, uintptr(mode|enableVirtualTerminalProcessing))
	return r != 0
}
