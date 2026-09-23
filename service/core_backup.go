package service

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/muja/goconfig"
)

// isBackup
// Determine whether the file has been backed up
func isBackup(key string) bool {
	if !validKeyID(key) {
		return false
	}
	dir := filepath.Join(ssbDir, key)
	if _, err := os.Stat(filepath.Join(dir, "id_rsa")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "id_rsa.pub")); err != nil {
		return false
	}
	m := map[string]string{}
	if json.Unmarshal(readConfig(), &m) != nil {
		return false
	}
	_, ok := m[key]
	return ok
}

// backUpDir
// Determine whether the program configuration directory exists. If not, create the directory
func backUpDir() error {
	info, err := os.Stat(ssbDir)
	if err == nil && !info.IsDir() {
		return fmt.Errorf("Backup directory name occupied: %s", ssbDir)
	}
	if err := secureOwnerDir(ssbDir); err != nil {
		return err
	}
	HideDir(ssbDir)
	return nil
}

func backUpSSH(md5 string) error {
	if err := backUpDir(); err != nil {
		return err
	}
	dir := filepath.Join(ssbDir, md5)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0700); err != nil {
			return err
		}
	}
	if err := cp(rsaPrivatePath, filepath.Join(dir, "id_rsa"), 0600); err != nil {
		return err
	}
	return cp(rsaPublicPath, filepath.Join(dir, "id_rsa.pub"), 0644)
}

func adjustConfig(md5, tagName string) error {
	m := map[string]string{}
	if err := json.Unmarshal(readConfig(), &m); err != nil {
		return err
	}
	m[md5] = tagNameUnique(m, md5, tagName)
	dirtyConfig(&m)
	config, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(ssbConfig, config, 0600)
}

func dirtyConfig(m *map[string]string) {
	for k := range *m {
		f := filepath.Join(ssbDir, k)
		if _, err := os.Stat(f); err != nil {
			delete(*m, k)
		}
	}
}

func tagNameUnique(m map[string]string, id, name string) string {
	used := map[string]struct{}{}
	for k, v := range m {
		if k == id {
			continue
		}
		used[v] = struct{}{}
	}
	if _, ok := used[name]; !ok {
		return name
	}
	next := name
	for {
		next += "-copy"
		if _, ok := used[next]; !ok {
			return next
		}
	}
}

func readConfig() []byte {
	if _, err := os.Stat(ssbConfig); err != nil {
		return []byte("{}")
	}

	data, err := os.ReadFile(ssbConfig)
	if err != nil {
		err = os.WriteFile(ssbConfig, []byte("{}"), 0600)
		if err != nil {
			log.Fatalln(err)
		}
		return []byte("{}")
	}
	return data
}

func cp(source, dest string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}
	if err := prepareOverwrite(dest, perm); err != nil {
		return err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err = os.WriteFile(dest, data, perm); err != nil {
		return err
	}
	if perm == 0600 {
		return securePrivateKey(dest)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	return os.Chmod(dest, perm)
}

// ZipFile
// Archive file
func ZipFiles(zipPath, destPath string) error {
	destPath = filepath.Clean(destPath)
	inside, err := inDir(destPath, zipPath)
	if err != nil {
		return err
	}
	if inside {
		return fmt.Errorf("压缩到的文件目录选择错误")
	}
	destFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	zw := zip.NewWriter(destFile)
	defer zw.Close()

	root := filepath.Dir(destPath)
	return filepath.Walk(destPath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		w, err := zw.Create(filepath.ToSlash(relPath))
		if err != nil {
			return err
		}
		f, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	})
}

type zipItem struct {
	file *zip.File
	rel  string
	id   string
	kind string
}

func UnZipFile(srcZip, dstDir string, updateConfig func(id, tag string) error) error {
	zr, err := zip.OpenReader(srcZip)
	if err != nil {
		return err
	}
	defer zr.Close()

	var items []zipItem
	var configRaw []byte
	for _, file := range zr.File {
		if file.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("拒绝符号链接: %s", file.Name)
		}
		rel, err := normalizeZipName(file.Name)
		if err != nil {
			return err
		}
		id, kind, err := classifyZipEntry(rel)
		if err != nil {
			return err
		}
		if _, err := withinRoot(dstDir, rel); err != nil {
			return err
		}
		if kind == "config" {
			raw, err := readZip(file)
			if err != nil {
				return err
			}
			configRaw = raw
		}
		items = append(items, zipItem{file: file, rel: rel, id: id, kind: kind})
	}
	if configRaw == nil {
		return nil
	}
	mc := map[string]string{}
	if err := json.Unmarshal(configRaw, &mc); err != nil {
		return fmt.Errorf("备份配置无效: %w", err)
	}

	type pair struct{ priv, pub bool }
	has := map[string]pair{}
	for _, it := range items {
		st := has[it.id]
		switch it.kind {
		case "priv":
			st.priv = true
		case "pub":
			st.pub = true
		}
		has[it.id] = st
	}

	if dstDir != "" {
		if err := os.MkdirAll(dstDir, 0700); err != nil {
			return err
		}
	}
	wrote := map[string]bool{}
	for _, it := range items {
		if it.kind != "priv" && it.kind != "pub" {
			continue
		}
		path, err := withinRoot(dstDir, it.rel)
		if err != nil {
			return err
		}
		if _, statErr := os.Lstat(path); statErr == nil {
			continue
		}
		if err := writeZipItem(it.file, path); err != nil {
			return err
		}
		wrote[it.id] = true
	}
	for id, st := range has {
		if !st.priv || !st.pub || !wrote[id] {
			continue
		}
		tag, ok := mc[id]
		if !ok {
			continue
		}
		if err := updateConfig(id, tag); err != nil {
			return err
		}
	}
	return nil
}

func readZip(file *zip.File) ([]byte, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func writeZipItem(file *zip.File, path string) error {
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	fw, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(fw, rc)
	closeErr := fw.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	switch filepath.Base(path) {
	case "id_rsa":
		return securePrivateKey(path)
	case "id_rsa.pub":
		if runtime.GOOS == "windows" {
			return nil
		}
		return os.Chmod(path, 0644)
	default:
		return fmt.Errorf("非法备份条目: %s", path)
	}
}

func normalizeZipName(name string) (string, error) {
	if strings.ContainsRune(name, 0) || strings.HasPrefix(name, `\\`) || strings.HasPrefix(name, "//") {
		return "", fmt.Errorf("非法备份条目: %s", name)
	}
	slashed := strings.ReplaceAll(name, `\`, `/`)
	if len(slashed) >= 2 && slashed[1] == ':' && isASCIILetter(slashed[0]) {
		return "", fmt.Errorf("非法备份条目: %s", name)
	}
	if strings.HasPrefix(slashed, "/") {
		slashed = strings.TrimPrefix(slashed, "/")
	}
	if slashed == "" || strings.HasPrefix(slashed, "/") {
		return "", fmt.Errorf("非法备份条目: %s", name)
	}
	for _, p := range strings.Split(slashed, "/") {
		if p == "" || p == "." || p == ".." {
			return "", fmt.Errorf("非法备份条目: %s", name)
		}
	}
	return slashed, nil
}

func isASCIILetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func classifyZipEntry(name string) (id, kind string, err error) {
	parts := strings.Split(name, "/")
	if len(parts) == 0 || parts[0] != ".ssb" {
		return "", "", fmt.Errorf("非法备份条目: %s", name)
	}
	switch len(parts) {
	case 1:
		return "", "dir", nil
	case 2:
		if parts[1] == ".ssbconfig" {
			return "", "config", nil
		}
		if validKeyID(parts[1]) {
			return parts[1], "dir", nil
		}
	case 3:
		if !validKeyID(parts[1]) {
			break
		}
		switch parts[2] {
		case "id_rsa":
			return parts[1], "priv", nil
		case "id_rsa.pub":
			return parts[1], "pub", nil
		}
	}
	return "", "", fmt.Errorf("非法备份条目: %s", name)
}

func validKeyID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func withinRoot(root, rel string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	full := filepath.Join(rootAbs, filepath.FromSlash(rel))
	relOut, err := filepath.Rel(rootAbs, full)
	if err != nil {
		return "", err
	}
	if relOut == ".." || strings.HasPrefix(relOut, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("非法备份条目: %s", rel)
	}
	cur := rootAbs
	if err := rejectSymlink(cur); err != nil {
		return "", err
	}
	for _, p := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, p)
		if err := rejectSymlink(cur); err != nil {
			return "", err
		}
	}
	return full, nil
}

func rejectSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("拒绝符号链接: %s", path)
	}
	return nil
}

func userName() string {
	u, err := user.LookupId(osUser.Uid)
	if err != nil || len(u.Name) == 0 {
		return "unknown"
	}
	return u.Name
}

func pcName() string {
	return format(osUser.Username)
}

func userEmail() string {
	gitConfig := filepath.Join(osUser.HomeDir, ".gitconfig")
	bytes, _ := os.ReadFile(gitConfig)
	config, _, err := goconfig.Parse(bytes)
	if err == nil {
		if email, ok := config["user.email"]; ok {
			return email
		}
	}
	return fmt.Sprintf("%s@%s.com", userName(), pcName())
}

func format(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	parts := strings.Split(name, "/")
	return parts[len(parts)-1]
}
