package service

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

// windowsPrivateKeyGrant 保留所有者读写。只给 (R) 时，后续切换和强制生成无法覆盖私钥。
const windowsPrivateKeyGrant = "(R,W)"

func securePrivateKey(path string) error {
	if runtime.GOOS == "windows" {
		return securePrivateKeyWindows(path)
	}
	return os.Chmod(path, 0600)
}

func prepareOverwrite(path string, perm os.FileMode) error {
	if perm != 0600 {
		return nil
	}
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return securePrivateKey(path)
}

func secureOwnerDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return secureDirWindows(path)
	}
	return os.Chmod(path, 0700)
}

func securePrivateKeyWindows(path string) error {
	principal, err := windowsPrincipal()
	if err != nil {
		return err
	}
	if err := runICACLS(path, "/grant:r", principal+":"+windowsPrivateKeyGrant); err != nil {
		return err
	}
	if err := runICACLS(path, "/inheritance:r"); err != nil {
		return err
	}
	dropBroadWindowsACL(path)
	return nil
}

func secureDirWindows(path string) error {
	principal, err := windowsPrincipal()
	if err != nil {
		return err
	}
	if err := runICACLS(path, "/grant:r", principal+":(OI)(CI)F"); err != nil {
		return err
	}
	if err := runICACLS(path, "/inheritance:r"); err != nil {
		return err
	}
	dropBroadWindowsACL(path)
	return nil
}

func dropBroadWindowsACL(path string) {
	// Everyone, Users, Authenticated Users. 用 SID，避免系统语言不同导致名称对不上。
	for _, sid := range []string{"*S-1-1-0", "*S-1-5-32-545", "*S-1-5-11"} {
		_ = runICACLS(path, "/remove:g", sid)
	}
}

func windowsPrincipal() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(u.Uid, "S-1-") {
		return "*" + u.Uid, nil
	}
	if u.Username != "" {
		return u.Username, nil
	}
	return "", fmt.Errorf("cannot resolve current user")
}

func runICACLS(args ...string) error {
	out, err := exec.Command("icacls", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return err
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}
