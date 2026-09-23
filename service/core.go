package service

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"ssb/config"
	"ssb/dao"
	"strings"
	"time"
)

var (
	bitSize = 2048
	osUser  *user.User
	homeDir string

	sshDir         string
	rsaPrivatePath string
	rsaPublicPath  string
	ssbDir         string
	ssbConfig      string

	ask             = dao.ScreenInput
	removeFromAgent = removeAgentKey
	addToAgent      = addAgentKey
)

func init() {
	var err error
	homeDir, err = os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	osUser, err = user.Current()
	if err != nil {
		osUser = &user.User{Username: "unknown", Name: "unknown", HomeDir: homeDir}
	}
	sshDir = filepath.Join(homeDir, ".ssh")
	rsaPrivatePath = filepath.Join(sshDir, "id_rsa")
	rsaPublicPath = filepath.Join(sshDir, "id_rsa.pub")
	ssbDir = filepath.Join(homeDir, ".ssb")
	ssbConfig = filepath.Join(ssbDir, ".ssbconfig")
	enableANSI()
}

// Generate new rsa key
// If the file already exists, you need to force it to be created
func Generate(ctx context.Context) error {
	// Determine whether the original key needs to be covered. If it is covered, the data will be backed up before
	if !existDir(rsaPrivatePath) || !existDir(rsaPublicPath) {
		if err := makeSSHKeyPair(rsaPublicPath, rsaPrivatePath); err != nil {
			return err
		}
	} else {
		needForce := ask("是否需要强制更新SSH(y/n):")
		if needForce != "y" {
			return nil
		}
		if err := backUpCurrent(ctx, "\n\n------------------------正在备份旧的Key------------------------"); err != nil {
			return err
		}
		if err := makeSSHKeyPair(rsaPublicPath, rsaPrivatePath); err != nil {
			return err
		}
	}
	return backUpCurrent(ctx, "\n\n------------------------正在备份新生成的Key------------------------")
}

// Back up the current SSH key
func Backup(ctx context.Context, tagName string) error {
	md := calcMd5(rsaPrivatePath)
	if md == "" {
		return fmt.Errorf("当前私钥不存在，无法备份")
	}
	if isBackup(md) {
		fmt.Println("Backup completed！！！")
		return nil
	}
	if err := backUpSSH(md); err != nil {
		return err
	}
	if err := adjustConfig(md, tagName); err != nil {
		return err
	}
	if !isBackup(md) {
		return fmt.Errorf("备份不完整")
	}
	return nil
}

// show backup list
func List(ctx context.Context) {
	conf := readConfig()
	m := map[string]string{}
	_ = json.Unmarshal(conf, &m)
	md := calcMd5(rsaPrivatePath)

	for k, v := range m {
		short := k
		if len(k) >= 10 {
			short = k[:10]
		}
		line := fmt.Sprintf("%s \t %s", short, v)
		if md == k {
			fmt.Println(paint("32", "* "+line))
			continue
		}
		fmt.Println(line)
	}
}

// switch ssh key
func Switch(ctx context.Context, dst string) error {
	dst = strings.TrimSpace(dst)

	conf := readConfig()
	m := map[string]string{}
	_ = json.Unmarshal(conf, &m)
	md := calcMd5(rsaPrivatePath)

	sMD := switchKey(m, dst, 0)
	if sMD == "" {
		return fmt.Errorf("switch error")
	}
	if sMD == md {
		fmt.Println(paint("33", "无需切换"))
		return nil
	}

	if err := secureOwnerDir(sshDir); err != nil {
		return err
	}
	removeFromAgent(rsaPrivatePath)

	dir := filepath.Join(ssbDir, sMD)
	if err := cp(filepath.Join(dir, "id_rsa"), rsaPrivatePath, 0600); err != nil {
		return err
	}
	if err := cp(filepath.Join(dir, "id_rsa.pub"), rsaPublicPath, 0644); err != nil {
		return err
	}
	addToAgent(rsaPrivatePath)

	List(ctx)
	return nil
}

// 导出配置
// 简单模式 ，只简单的备份key
func Export(ctx context.Context, src string) error {
	src = strings.TrimSpace(src)
	switch src {
	case "":
		src = homeDir
	case ".":
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		src = wd
	default:
		src = expandHome(src)
	}

	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	inside, err := inDir(ssbDir, src)
	if err != nil {
		return err
	}
	if !info.IsDir() || inside {
		return fmt.Errorf("压缩到的文件目录选择错误")
	}
	// 将当前的SSHKey先备份
	if err := backUpCurrent(ctx, "正在备份当前的Key:..."); err != nil {
		return err
	}

	output := filepath.Join(src, "backup.zip")
	if err := ZipFiles(output, ssbDir); err != nil {
		return err
	}
	fmt.Println("Zipped File:", output)
	return nil
}

// import ssh key
func Load(ctx context.Context, srcZip string) error {
	srcZip = expandHome(strings.TrimSpace(srcZip))
	return UnZipFile(srcZip, homeDir, func(id, tagName string) error {
		return adjustConfig(id, tagName)
	})
}

func expandHome(p string) string {
	if p == "~" {
		return homeDir
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(homeDir, p[2:])
	}
	return p
}

func inDir(dir, target string) (bool, error) {
	d, err := resolvePath(dir)
	if err != nil {
		return false, err
	}
	t, err := resolvePath(target)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(d, t)
	if err != nil {
		return false, err
	}
	if rel == "." {
		return true, nil
	}
	prefix := ".." + string(filepath.Separator)
	if rel == ".." || strings.HasPrefix(rel, prefix) {
		return false, nil
	}
	return true, nil
}

func resolvePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return evalExisting(abs)
}

func evalExisting(abs string) (string, error) {
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	var missing []string
	cur := abs
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("无法解析路径: %s", abs)
		}
		missing = append([]string{filepath.Base(cur)}, missing...)
		if _, statErr := os.Lstat(parent); statErr != nil {
			if os.IsNotExist(statErr) {
				cur = parent
				continue
			}
			return "", statErr
		}
		parentResolved, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return "", err
		}
		parts := append([]string{parentResolved}, missing...)
		return filepath.Join(parts...), nil
	}
}

func calcMd5(path string) string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("open file error")
		return ""
	}
	defer f.Close()
	md5h := md5.New()
	_, _ = io.Copy(md5h, f)
	return hex.EncodeToString(md5h.Sum(nil))
}

func switchKey(m map[string]string, dst string, n int) string {
	if n == 3 {
		fmt.Println(paint("31", "switch error!!!"))
		return ""
	}
	if id, ok := matchKey(m, dst); ok {
		return id
	}
	fmt.Println(paint("31", "switch error!!!"))
	fmt.Println("\n--------------需要从以下配置项选择--------------")
	List(context.Background())
	return switchKey(m, ask("请输入切换的配置:"), n+1)
}

func matchKey(m map[string]string, dst string) (string, bool) {
	dst = strings.TrimSpace(dst)
	if dst == "" {
		return "", false
	}
	if _, ok := m[dst]; ok {
		return dst, true
	}
	tagID := ""
	tags := 0
	for k, v := range m {
		if v == dst {
			tags++
			tagID = k
		}
	}
	if tags == 1 {
		return tagID, true
	}
	if tags > 1 {
		return "", false
	}
	prefixID := ""
	prefixes := 0
	for k := range m {
		if strings.HasPrefix(k, dst) {
			prefixes++
			prefixID = k
		}
	}
	if prefixes == 1 {
		return prefixID, true
	}
	return "", false
}

func backUpCurrent(ctx context.Context, tips string) error {
	md := calcMd5(rsaPrivatePath)
	if md == "" {
		return fmt.Errorf("当前私钥不存在，无法备份")
	}
	if isBackup(md) {
		return nil
	}
	fmt.Println(tips)
	tagName := time.Now().Format(config.BackUpTime)
	if str := strings.TrimSpace(ask(fmt.Sprintf("请输入TagName(%s):", tagName))); str != "" {
		tagName = str
	}
	return Backup(ctx, tagName)
}

func useHome(dir string) func() {
	prevHome, prevUser := homeDir, osUser
	prevSSH, prevPriv, prevPub := sshDir, rsaPrivatePath, rsaPublicPath
	prevSSB, prevCfg := ssbDir, ssbConfig
	homeDir = dir
	osUser = &user.User{Username: "tester", Name: "tester", HomeDir: dir, Uid: "1"}
	sshDir = filepath.Join(dir, ".ssh")
	rsaPrivatePath = filepath.Join(sshDir, "id_rsa")
	rsaPublicPath = filepath.Join(sshDir, "id_rsa.pub")
	ssbDir = filepath.Join(dir, ".ssb")
	ssbConfig = filepath.Join(ssbDir, ".ssbconfig")
	return func() {
		homeDir, osUser = prevHome, prevUser
		sshDir, rsaPrivatePath, rsaPublicPath = prevSSH, prevPriv, prevPub
		ssbDir, ssbConfig = prevSSB, prevCfg
	}
}

func removeAgentKey(path string) {
	_ = exec.Command("ssh-add", "-d", path).Run()
}

func addAgentKey(path string) {
	cmd := exec.Command("ssh-add", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		fmt.Println("密钥文件已切换，ssh-agent 未更新:", msg)
	}
}
