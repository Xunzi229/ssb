package service

import (
	"os"
	"runtime"
)

var useColor = true

func enableANSI() {
	if os.Getenv("NO_COLOR") != "" {
		useColor = false
		return
	}
	if runtime.GOOS != "windows" {
		useColor = true
		return
	}
	useColor = enableWindowsVT()
}

func paint(code, text string) string {
	if !useColor {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}
