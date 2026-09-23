package service

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsPrivateKeyGrantIncludesWrite(t *testing.T) {
	if windowsPrivateKeyGrant != "(R,W)" {
		t.Fatal(windowsPrivateKeyGrant)
	}
}

func TestOverwriteReadOnlyPrivateKey(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(src, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := cp(src, dst, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("content %q", got)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("perm %o", info.Mode().Perm())
	}

	if err := writeKeyToFile([]byte("again"), dst, 0600); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "again" {
		t.Fatalf("content %q", got)
	}
}

func TestBackupDefaultTagAndFailedBackup(t *testing.T) {
	home := t.TempDir()
	defer useHome(home)()
	seedCurrent(t, "OLD-PRIVATE", "OLD-PUBLIC")
	stubAsk(t, func(string) string { return "" })

	if err := backUpCurrent(context.Background(), "backup"); err != nil {
		t.Fatal(err)
	}
	m := configMap(t)
	if len(m) != 1 {
		t.Fatalf("config %#v", m)
	}
	for id, tag := range m {
		if len(tag) != 12 {
			t.Fatalf("tag %q", tag)
		}
		if _, err := os.Stat(filepath.Join(ssbDir, id, "id_rsa")); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(ssbDir, id, "id_rsa.pub")); err != nil {
			t.Fatal(err)
		}
	}

	home2 := t.TempDir()
	defer useHome(home2)()
	seedCurrent(t, "OLD-PRIVATE", "OLD-PUBLIC")
	if err := os.WriteFile(ssbDir, []byte("not-a-dir"), 0600); err != nil {
		t.Fatal(err)
	}
	n := 0
	stubAsk(t, func(string) string {
		n++
		if n == 1 {
			return "y"
		}
		return ""
	})
	if err := Generate(context.Background()); err == nil {
		t.Fatal("expected backup failure")
	}
	got, err := os.ReadFile(rsaPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "OLD-PRIVATE" {
		t.Fatalf("private key changed: %q", got)
	}
	pub, err := os.ReadFile(rsaPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(pub) != "OLD-PUBLIC" {
		t.Fatalf("public key changed: %q", pub)
	}
}

func TestBackupCustomTag(t *testing.T) {
	home := t.TempDir()
	defer useHome(home)()
	seedCurrent(t, "priv", "pub")
	stubAsk(t, func(string) string { return "work" })
	if err := backUpCurrent(context.Background(), "backup"); err != nil {
		t.Fatal(err)
	}
	m := configMap(t)
	if len(m) != 1 {
		t.Fatalf("%#v", m)
	}
	for _, tag := range m {
		if tag != "work" {
			t.Fatalf("tag %q", tag)
		}
	}
}

func TestGenerateKeepsOldKeyInBackup(t *testing.T) {
	home := t.TempDir()
	defer useHome(home)()
	seedCurrent(t, "OLD-PRIVATE", "OLD-PUBLIC")
	n := 0
	stubAsk(t, func(string) string {
		n++
		if n == 1 {
			return "y"
		}
		return ""
	})
	if err := Generate(context.Background()); err != nil {
		t.Fatal(err)
	}
	cur, err := os.ReadFile(rsaPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur) == "OLD-PRIVATE" {
		t.Fatal("key was not replaced")
	}
	if !backupContains(t, "OLD-PRIVATE", "OLD-PUBLIC") {
		t.Fatal("old key pair missing from backup")
	}
}

func TestUnZipRejectsEscape(t *testing.T) {
	names := []string{
		"../escaped/payload",
		`..\escaped\payload`,
		"/tmp/escaped",
		`C:/.ssb/x`,
		`\\server\share\x`,
		"//server/share/x",
		".ssb/../escaped",
		"not-ssb/file",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			z := buildZip(t, [][2]string{{name, "pwn"}})
			err := UnZipFile(z, home, func(string, string) error { return nil })
			if err == nil {
				t.Fatal("accepted")
			}
			if _, statErr := os.Stat(filepath.Join(home, ".ssb")); !os.IsNotExist(statErr) {
				t.Fatal("partial write")
			}
			if _, statErr := os.Stat(filepath.Join(home, "escaped", "payload")); !os.IsNotExist(statErr) {
				t.Fatal("wrote outside")
			}
		})
	}
}

func TestUnZipRejectsSymlink(t *testing.T) {
	home := t.TempDir()
	id := strings.Repeat("d", 32)
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssb"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, ".ssb", id)); err != nil {
		t.Fatal(err)
	}
	z := buildZip(t, [][2]string{
		{".ssb/.ssbconfig", `{"` + id + `":"home"}`},
		{".ssb/" + id + "/id_rsa", "priv"},
		{".ssb/" + id + "/id_rsa.pub", "pub"},
	})
	if err := UnZipFile(z, home, func(string, string) error { return nil }); err == nil {
		t.Fatal("accepted symlink path")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("wrote through symlink: %v", entries)
	}
}

func TestUnZipRejectsSymlinkEntry(t *testing.T) {
	home := t.TempDir()
	id := strings.Repeat("e", 32)
	path := filepath.Join(t.TempDir(), "in.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	hdr := &zip.FileHeader{Name: ".ssb/" + id + "/id_rsa"}
	hdr.SetMode(os.ModeSymlink | 0777)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("out")); err != nil {
		t.Fatal(err)
	}
	cfg, err := zw.Create(".ssb/.ssbconfig")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Write([]byte(`{"` + id + `":"home"}`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := UnZipFile(path, home, func(string, string) error { return nil }); err == nil {
		t.Fatal("accepted symlink entry")
	}
	if _, statErr := os.Stat(filepath.Join(home, ".ssb")); !os.IsNotExist(statErr) {
		t.Fatal("partial write")
	}
}

func TestImportTagAndLegacyNames(t *testing.T) {
	home := t.TempDir()
	defer useHome(home)()
	id := strings.Repeat("a", 32)
	z := buildZip(t, [][2]string{
		{".ssb/" + id + "/id_rsa.pub", "pub"},
		{".ssb/.ssbconfig", `{"` + id + `":"home"}`},
		{".ssb/" + id + "/id_rsa", "priv"},
	})
	if err := Load(context.Background(), z); err != nil {
		t.Fatal(err)
	}
	if configMap(t)[id] != "home" {
		t.Fatalf("%#v", configMap(t))
	}

	if err := os.WriteFile(ssbConfig, []byte(`{"`+id+`":"custom"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Load(context.Background(), z); err != nil {
		t.Fatal(err)
	}
	if configMap(t)[id] != "custom" {
		t.Fatalf("reimport changed tag: %#v", configMap(t))
	}

	id2 := strings.Repeat("b", 32)
	id3 := strings.Repeat("c", 32)
	z2 := buildZip(t, [][2]string{
		{".ssb/.ssbconfig", `{"` + id2 + `":"home","` + id3 + `":"home"}`},
		{"/.ssb/" + id2 + "/id_rsa", "p2"},
		{`\.ssb\` + id2 + `\id_rsa.pub`, "u2"},
		{".ssb/" + id3 + "/id_rsa", "p3"},
		{".ssb/" + id3 + "/id_rsa.pub", "u3"},
	})
	if err := Load(context.Background(), z2); err != nil {
		t.Fatal(err)
	}
	got := map[string]struct{}{}
	for _, tag := range configMap(t) {
		got[tag] = struct{}{}
	}
	for _, tag := range []string{"custom", "home", "home-copy"} {
		if _, ok := got[tag]; !ok {
			t.Fatalf("missing %s in %#v", tag, configMap(t))
		}
	}

	id4 := strings.Repeat("d", 32)
	z3 := buildZip(t, [][2]string{
		{".ssb/.ssbconfig", `{"` + id4 + `":"home"}`},
		{".ssb/" + id4 + "/id_rsa", "only"},
	})
	if err := Load(context.Background(), z3); err != nil {
		t.Fatal(err)
	}
	if _, ok := configMap(t)[id4]; ok {
		t.Fatalf("incomplete pair recorded: %#v", configMap(t))
	}
}

func TestTagCopyCollision(t *testing.T) {
	m := map[string]string{
		strings.Repeat("a", 32): "home",
		strings.Repeat("b", 32): "home-copy",
	}
	id := strings.Repeat("c", 32)
	if got := tagNameUnique(m, id, "home"); got != "home-copy-copy" {
		t.Fatal(got)
	}
	if got := tagNameUnique(m, strings.Repeat("a", 32), "home"); got != "home" {
		t.Fatal(got)
	}
}

func TestSwitchDoesNotGuess(t *testing.T) {
	id1 := strings.Repeat("a", 31) + "1"
	id2 := strings.Repeat("a", 31) + "2"
	id3 := strings.Repeat("b", 32)

	t.Run("empty", func(t *testing.T) {
		home := t.TempDir()
		defer useHome(home)()
		seedCurrent(t, "current", "pub")
		seedBackup(t, id1, "one", "pub1")
		writeCfg(t, map[string]string{id1: "home", id2: "work"})
		seedBackup(t, id2, "two", "pub2")
		calls := stubAgent(t)
		stubAsk(t, func(string) string { return "   " })
		if err := Switch(context.Background(), "  "); err == nil {
			t.Fatal("expected error")
		}
		assertCurrent(t, "current")
		if *calls != 0 {
			t.Fatalf("agent calls %d", *calls)
		}
	})

	t.Run("ambiguous prefix", func(t *testing.T) {
		home := t.TempDir()
		defer useHome(home)()
		seedCurrent(t, "current", "pub")
		seedBackup(t, id1, "one", "pub1")
		seedBackup(t, id2, "two", "pub2")
		writeCfg(t, map[string]string{id1: "home", id2: "work"})
		calls := stubAgent(t)
		stubAsk(t, func(string) string { return "" })
		if err := Switch(context.Background(), strings.Repeat("a", 31)); err == nil {
			t.Fatal("expected error")
		}
		assertCurrent(t, "current")
		if *calls != 0 {
			t.Fatalf("agent calls %d", *calls)
		}
	})

	t.Run("ambiguous tag", func(t *testing.T) {
		home := t.TempDir()
		defer useHome(home)()
		seedCurrent(t, "current", "pub")
		seedBackup(t, id1, "one", "pub1")
		seedBackup(t, id2, "two", "pub2")
		writeCfg(t, map[string]string{id1: "home", id2: "home"})
		calls := stubAgent(t)
		stubAsk(t, func(string) string { return "" })
		if err := Switch(context.Background(), "home"); err == nil {
			t.Fatal("expected error")
		}
		assertCurrent(t, "current")
		if *calls != 0 {
			t.Fatalf("agent calls %d", *calls)
		}
	})

	t.Run("unique", func(t *testing.T) {
		home := t.TempDir()
		defer useHome(home)()
		seedCurrent(t, "current", "pub")
		seedBackup(t, id1, "one", "pub1")
		seedBackup(t, id3, "three", "pub3")
		writeCfg(t, map[string]string{id1: "home", id3: "work"})
		calls := stubAgent(t)
		if err := Switch(context.Background(), "home"); err != nil {
			t.Fatal(err)
		}
		assertCurrent(t, "one")
		if err := Switch(context.Background(), id3); err != nil {
			t.Fatal(err)
		}
		assertCurrent(t, "three")
		if err := Switch(context.Background(), strings.Repeat("a", 31)); err != nil {
			t.Fatal(err)
		}
		assertCurrent(t, "one")
		if *calls == 0 {
			t.Fatal("agent not called")
		}
	})
}

func TestExportPathGuard(t *testing.T) {
	home := t.TempDir()
	defer useHome(home)()
	if err := os.MkdirAll(ssbDir, 0700); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(home); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)

	inside, err := inDir(ssbDir, ".ssb")
	if err != nil || !inside {
		t.Fatalf("relative: %v %v", inside, err)
	}
	if err := Export(context.Background(), ".ssb"); err == nil {
		t.Fatal("expected reject")
	}
	if _, statErr := os.Stat(filepath.Join(ssbDir, "backup.zip")); !os.IsNotExist(statErr) {
		t.Fatal("backup.zip created")
	}

	link := filepath.Join(home, "alias")
	if err := os.Symlink(ssbDir, link); err != nil {
		t.Fatal(err)
	}
	if err := Export(context.Background(), "alias"); err == nil {
		t.Fatal("expected symlink reject")
	}
	if _, statErr := os.Stat(filepath.Join(ssbDir, "backup.zip")); !os.IsNotExist(statErr) {
		t.Fatal("backup.zip created via symlink")
	}

	zipInside := filepath.Join(ssbDir, "backup.zip")
	if err := ZipFiles(zipInside, ssbDir); err == nil {
		t.Fatal("ZipFiles accepted inside path")
	}
	if _, statErr := os.Stat(zipInside); !os.IsNotExist(statErr) {
		t.Fatal("ZipFiles created archive")
	}

	outName := ".ssb-out"
	if err := os.MkdirAll(filepath.Join(home, outName), 0700); err != nil {
		t.Fatal(err)
	}
	seedCurrent(t, "priv", "pub")
	stubAsk(t, func(string) string { return "" })
	if err := Export(context.Background(), outName); err != nil {
		t.Fatal(err)
	}
	z := filepath.Join(home, outName, "backup.zip")
	zr, err := zip.OpenReader(z)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if len(zr.File) == 0 {
		t.Fatal("empty export")
	}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "backup.zip") {
			t.Fatalf("archive contains itself: %s", f.Name)
		}
	}
}

func stubAsk(t *testing.T, fn func(string) string) {
	t.Helper()
	prev := ask
	ask = fn
	t.Cleanup(func() { ask = prev })
}

func stubAgent(t *testing.T) *int {
	t.Helper()
	n := 0
	prevR, prevA := removeFromAgent, addToAgent
	removeFromAgent = func(string) { n++ }
	addToAgent = func(string) { n++ }
	t.Cleanup(func() {
		removeFromAgent = prevR
		addToAgent = prevA
	})
	return &n
}

func seedCurrent(t *testing.T, priv, pub string) {
	t.Helper()
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rsaPrivatePath, []byte(priv), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rsaPublicPath, []byte(pub), 0644); err != nil {
		t.Fatal(err)
	}
}

func seedBackup(t *testing.T, id, priv, pub string) {
	t.Helper()
	dir := filepath.Join(ssbDir, id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_rsa"), []byte(priv), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_rsa.pub"), []byte(pub), 0644); err != nil {
		t.Fatal(err)
	}
}

func writeCfg(t *testing.T, m map[string]string) {
	t.Helper()
	if err := os.MkdirAll(ssbDir, 0700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ssbConfig, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func configMap(t *testing.T) map[string]string {
	t.Helper()
	m := map[string]string{}
	if err := json.Unmarshal(readConfig(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func assertCurrent(t *testing.T, want string) {
	t.Helper()
	got, err := os.ReadFile(rsaPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("current %q", got)
	}
}

func backupContains(t *testing.T, priv, pub string) bool {
	t.Helper()
	found := false
	_ = filepath.Walk(ssbDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() != "id_rsa" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil || string(b) != priv {
			return nil
		}
		pb, err := os.ReadFile(filepath.Join(filepath.Dir(path), "id_rsa.pub"))
		if err == nil && string(pb) == pub {
			found = true
		}
		return nil
	})
	return found
}

func buildZip(t *testing.T, entries [][2]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "in.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		w, err := zw.Create(e[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
