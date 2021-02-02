package service

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	// "syscall"
)

// 是否存在
func existDir(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func HideDir(dir string) {
	switch runtime.GOOS {
	case "windows":
		if err := hideWindowDir(dir); err != nil {
			log.Println(err)
		}
	default:
		if err := hideUnixDir(dir); err != nil {
			log.Println(err)
		}
	}
}

func HideFile(doc string) {
	switch runtime.GOOS {
	case "windows":
		if err := hideWindowDir(doc); err != nil {
			log.Println(err)
		}
	default:
		if err := hideUnixDir(doc); err != nil {
			log.Println(err)
		}
	}
}

// windows
func hideWindowDir(pathName string) error {
	// 暂时编译的问题没处理好
	// var err error

	// if runtime.GOOS == "windows" {
	// 	fileName, err := syscall.UTF16PtrFromString(pathName)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	err = syscall.SetFileAttributes(fileName, syscall.FILE_ATTRIBUTE_HIDDEN)
	// }
	return nil
}

// unix
func hideUnixDir(pathName string) error {
	if strings.HasPrefix(filepath.Base(pathName), ".") {
		return nil
	}
	return os.Rename(pathName, "."+pathName)
}
