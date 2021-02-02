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
  "os/user"
  "ssb/config"
  "ssb/dao"
  "strings"
  "time"
)

var (
	bitSize   = 2048
	osUser, _ = user.Current()
	homeDir   = osUser.HomeDir

	rsaPrivatePath = strings.Join([]string{homeDir, ".ssh", "id_rsa"}, "/")
	rsaPublicPath  = strings.Join([]string{homeDir, ".ssh", "id_rsa.pub"}, "/")
	ssbDir         = strings.Join([]string{homeDir, ".ssb"}, "/")
	ssbConfig      = strings.Join([]string{ssbDir, ".ssbconfig"}, "/")
)

// Generate new rsa key
// If the file already exists, you need to force it to be created
func Generate(ctx context.Context) {
	// Determine whether the original key needs to be covered. If it is covered, the data will be backed up before
	if !existDir(rsaPrivatePath) || !existDir(rsaPublicPath) {
		makeSSHKeyPair(rsaPublicPath, rsaPrivatePath)
	} else {
		needForce := dao.ScreenInput("是否需要强制更新SSH(y/n):")
		if needForce != "y" {
			return
		}
		backUpCurrent(ctx, "\n\n------------------------正在备份旧的Key------------------------")
		makeSSHKeyPair(rsaPublicPath, rsaPrivatePath)
	}
	backUpCurrent(ctx, "\n\n------------------------正在备份新生成的Key------------------------")
}

// Back up the current SSH key
func Backup(ctx context.Context, tagName string) {
	md := calcMd5(rsaPrivatePath)

	// 如果备份了， 则返回
	if ok := isBackup(md); ok {
		fmt.Println("Backup completed！！！")
		return
	}
	backUpSSH(md)
	adjustConfig(md, tagName)
}

// show backup list
func List(ctx context.Context) {
	conf := readConfig()
	m := map[string]string{}
	_ = json.Unmarshal(conf, &m)
	md := calcMd5(rsaPrivatePath)

	for k, v := range m {
		if md == k {
			fmt.Printf("\x1b[32m* %s \t %s \x1b[0m\n", k[0:10], v)
			continue
		}
		fmt.Printf("%s \t %s\n", k[0:10], v)
	}
}

// switch ssh key
func Switch(ctx context.Context, dst string) {
	dst = strings.TrimSpace(dst)

	conf := readConfig()
	m := map[string]string{}
	_ = json.Unmarshal(conf, &m)
	md := calcMd5(rsaPrivatePath)

	sMD := switchKey(m, dst, 0)
	if sMD == md {
		fmt.Println("\x1b[33m无需切换\x1b[0m")
		return
	}

	dir := strings.Join([]string{ssbDir, sMD}, "/")
	/*------------------------------*/
	priFile := strings.Join([]string{dir, "id_rsa"}, "/")
	cp(priFile, rsaPrivatePath, 0600)

	/*------------------------------*/
	pubFile := strings.Join([]string{dir, "id_rsa.pub"}, "/")
	cp(pubFile, rsaPublicPath, 0644)
	/*------------------------------*/

	List(ctx)
}

// 导出配置
// 简单模式 ，只简单的备份key
func Export(ctx context.Context, src string) {
	if src == "." {
		src, _ = os.Getwd()
	}
	src = strings.ReplaceAll(src, "~", homeDir)

	if len(src) != 0 {
		_, err := os.Stat(src)
		if err != nil {
			panic(err)
		}
	} else {
		src = homeDir
	}
	if s, err := os.Stat(src); err != nil {
		fmt.Println(err)
		return
	} else {
		if !s.IsDir() || strings.HasPrefix(src, ssbDir) {
			fmt.Println("压缩到的文件目录选择错误")
			return
		}
	}
	// 将当前的SSHKey先备份
	backUpCurrent(ctx, "正在备份当前的Key:...")

	if src[len(src)-1] == '/' {
		src = src[0 : len(src)-1]
	}
	output := strings.Join([]string{src, "backup.zip"}, "/")
	if err := ZipFiles(output, ssbDir); err != nil {
		log.Fatalln(err)
	}
	fmt.Println("Zipped File:", output)
}

// import ssh key
func Load(ctx context.Context, srcZip string) {
	_ = UnZipFile(srcZip, homeDir, func(rsa, tagName string) {
		adjustConfig(rsa, tagName)
	})
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
		fmt.Printf("\x1b[31m%s\x1b[0m\n", "switch error!!!")
		return ""
	}

	for k, v := range m {
		if strings.HasPrefix(k, dst) || dst == v {
			return k
		}
	}
	fmt.Printf("\x1b[31m%s\x1b[0m\n", "switch error!!!")
	fmt.Println("\n--------------需要从以下配置项选择--------------")
	List(context.Background())

	tip := fmt.Sprintf("请输入切换的配置:")
	key := dao.ScreenInput(tip)
	return switchKey(m, key, n+1)
}

func backUpCurrent(ctx context.Context, tips string) {
	md := calcMd5(rsaPrivatePath)
	if ok := isBackup(md); !ok {
		fmt.Println(tips)
		tagName := time.Now().Format(config.BackUpTime)
		tip := fmt.Sprintf("请输入TagName(%s):", tagName)
		if str := dao.ScreenInput(tip); len(str) != 0 {
			tagName = str
			Backup(ctx, tagName)
		}
	}
}
