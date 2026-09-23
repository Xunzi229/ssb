//go:build !windows

package service

func enableWindowsVT() bool { return true }
