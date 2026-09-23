package service

import (
	"archive/zip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExpandHome(t *testing.T) {
	if expandHome("~") != homeDir {
		t.Fatalf("expand ~ = %s", expandHome("~"))
	}
	want := filepath.Join(homeDir, "Desktop")
	if expandHome("~/Desktop") != want {
		t.Fatalf("expand ~/Desktop = %s", expandHome("~/Desktop"))
	}
	if expandHome(`~\Desktop`) != want {
		t.Fatalf("expand ~\\Desktop = %s", expandHome(`~\Desktop`))
	}
	const raw = "/tmp/a~b"
	if expandHome(raw) != raw {
		t.Fatalf("tilde in the middle was expanded: %s", expandHome(raw))
	}
}

func TestFormatUser(t *testing.T) {
	if got := format(`DOMAIN\user`); got != "user" {
		t.Fatalf("got %s", got)
	}
	if got := format("user"); got != "user" {
		t.Fatalf("got %s", got)
	}
}

func TestInDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ssb-root")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	ok, err := inDir(root, root)
	if err != nil || !ok {
		t.Fatalf("same dir: %v %v", ok, err)
	}
	ok, err = inDir(root, filepath.Join(root, "child"))
	if err != nil || !ok {
		t.Fatalf("child: %v %v", ok, err)
	}
	ok, err = inDir(root, filepath.Dir(root))
	if err != nil || ok {
		t.Fatalf("parent: %v %v", ok, err)
	}
}

func TestZipEntryUsesSlash(t *testing.T) {
	tmp := t.TempDir()
	store := filepath.Join(tmp, ".ssb")
	id := strings.Repeat("a", 32)
	keyDir := filepath.Join(store, id)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, ".ssbconfig"), []byte(`{"`+id+`":"home"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "id_rsa"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "id_rsa.pub"), []byte("public"), 0644); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(tmp, "backup.zip")
	if err := ZipFiles(zipPath, store); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if len(zr.File) == 0 {
		t.Fatal("empty zip")
	}
	for _, f := range zr.File {
		if containsBackslash(f.Name) {
			t.Fatalf("zip entry has backslash: %s", f.Name)
		}
	}

	dst := filepath.Join(tmp, "out")
	var got []string
	if err := UnZipFile(zipPath, dst, func(md5, tag string) error {
		got = append(got, md5+":"+tag)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	priv := filepath.Join(dst, ".ssb", id, "id_rsa")
	data, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "private" {
		t.Fatalf("content %q", data)
	}
	info, err := os.Stat(priv)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("perm %o", info.Mode().Perm())
	}
	if len(got) != 1 || got[0] != id+":home" {
		t.Fatalf("config callback %#v", got)
	}
}

func TestSecurePrivateKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("acl is covered by icacls on Windows")
	}
	path := filepath.Join(t.TempDir(), "id_rsa")
	if err := os.WriteFile(path, []byte("k"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := securePrivateKey(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("perm %o", info.Mode().Perm())
	}
}

func containsBackslash(s string) bool {
	for _, r := range s {
		if r == '\\' {
			return true
		}
	}
	return false
}
