package service

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"github.com/muja/goconfig"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// isBackup
// Determine whether the file has been backed up
func isBackup(key string) bool {
	backUpDir()

	dir := strings.Join([]string{ssbDir, key}, "/")
	s, _ := os.Stat(dir)
	if s == nil {
		return false
	}
	return s.IsDir()
}

// backUpDir
// Determine whether the program configuration directory exists. If not, create the directory
func backUpDir() {
	// hide Dir
	s, err := os.Stat(ssbDir)
	if err != nil {
		if os.IsExist(err) {
			log.Println(err)
			return
		}
		_ = os.Mkdir(ssbDir, os.ModePerm)
		HideDir(ssbDir) //
	  	s, _ = os.Stat(ssbDir)
	}
	if !s.IsDir() {
		log.Panicf("Backup directory name occupied: %s", ssbDir)
	}
}

func backUpSSH(md5 string) {
	backUpDir()
	dir := strings.Join([]string{ssbDir, md5}, "/")
	_ = os.Mkdir(dir, os.ModePerm)

	/*------------------------------*/
	priFile := strings.Join([]string{dir, "id_rsa"}, "/")
	cp(rsaPrivatePath, priFile, os.ModePerm)

	/*------------------------------*/
	pubFile := strings.Join([]string{dir, "id_rsa.pub"}, "/")
	cp(rsaPublicPath, pubFile, os.ModePerm)
	/*------------------------------*/

}

func adjustConfig(md5, tagName string) {
	config := readConfig()
	m := map[string]string{}
	_ = json.Unmarshal(config, &m)
	m[md5] = tagNameUnique(m, tagName)
	dirtyConfig(&m)
	config, _ = json.Marshal(m)
	if err := ioutil.WriteFile(ssbConfig, config, os.ModePerm); err != nil {
		log.Fatalln(err)
	}
}

func dirtyConfig(m *map[string]string) {
	for k, _ := range *m {
		f := strings.Join([]string{ssbDir, k}, "/")
		if _, err := os.Stat(f); err != nil {
			delete(*m, k)
		}
	}
}

func tagNameUnique(m map[string]string, name string) string {
	for _, v := range m {
		if v == name {
			return fmt.Sprintf("%s-copy", name)
		}
	}
	return name
}

func readConfig() []byte {
  	if _, err := os.Stat(ssbConfig); err != nil {
  		return []byte("{}")
	}

	data, err := ioutil.ReadFile(ssbConfig)
	if err != nil {
		err = ioutil.WriteFile(ssbConfig, []byte("{}"), os.ModePerm)
		if err != nil {
			log.Fatalln(err)
		}
		return []byte("{}")
	}
	return data
}

func cp(source, dest string, perm os.FileMode) {
	data, err := ioutil.ReadFile(source)
	if err != nil {
		log.Fatalln(err)
	}
	//fmt.Println("copy:", source, "->", dest)
	err = ioutil.WriteFile(dest, data, perm)
	if err != nil {
	  	log.Fatalln(err)
	}
}

// ZipFile
// Archive file
func ZipFiles(zipPath, destPath string) error {
	destFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	oZip := zip.NewWriter(destFile)
	defer func() { _ = oZip.Close() }()

	err = filepath.Walk(destPath, func(filePath string, info os.FileInfo, err error) error {
		if info.IsDir() || err != nil {
			return nil
		}
		//if info.Name() == ".ssbconfig" {
		//	return nil
		//}
		relPath := strings.TrimPrefix(filePath, filepath.Dir(destPath))
		zipFile, err := oZip.Create(relPath)
		if err != nil {
			return err
		}
		fsFile, err := os.Open(filePath)
		if err != nil {
			return err
		}
		_, err = io.Copy(zipFile, fsFile)
		return err
	})
	return err
}

func UnZipFile(srcZip, dstDir string, updateConfig func(rsa, tag string)) (err error) {
	zr, err := zip.OpenReader(srcZip)
	defer func() { _ = zr.Close() }()
	if err != nil {
		return
	}

	// 如果解压后不是放在当前目录就按照保存目录去创建目录
	if dstDir != "" {
		if err := os.MkdirAll(dstDir, os.ModePerm); err != nil {
			return err
		}
	}

	mc := map[string]string{}
	for _, file := range zr.File {
		if strings.HasSuffix(file.Name, ".ssbconfig") {
			func() {
				fr, _ := file.Open()
				defer func() { _ = fr.Close() }()
				r, _ := ioutil.ReadAll(fr)
				_ = json.Unmarshal(r, &mc)
			}()
		}
	}
	if len(mc) == 0 {
		return err
	}
	// 遍历 zr ，将文件写入到磁盘
	for _, file := range zr.File {
		path := filepath.Join(dstDir, file.Name)
		// 如果对应的文件不存在， 才会创建相关的数据
		if _, err := os.Stat(path); err == nil || strings.HasSuffix(file.Name, ".ssbconfig") {
			continue
		}
		// 如果是目录，就创建目录
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(path, file.Mode()); err != nil {
				return err
			}
		}

		md5 := ""
		// 将最后一个或文件移除
		if !file.FileInfo().IsDir() {
			d := strings.Split(strings.ReplaceAll(path, `\`, `/`), `/`)
			p := strings.Join(d[0:len(d)-1], "/")
			if _, err := os.Stat(p); err != nil {
				if err := os.MkdirAll(p, file.Mode()); err != nil {
					return err
				}
			}
			md5 = d[len(d)-2]
		}
		err = func() error {
			// 获取 Reader
			fr, err := file.Open()
			if err != nil {
				return err
			}

			// 创建要写文件对应的 Write
			fw, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, file.Mode())
			if err != nil {
				log.Fatalln(err)
				return err
			}

			defer func() { _ = fw.Close() }()
			defer func() { _ = fr.Close() }()

			if _, err = io.Copy(fw, fr); err != nil {
				log.Fatalln(err)
				return err
			}
			updateConfig(md5, mc[md5])
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func userName() string {
	u, _ := user.LookupId(osUser.Uid)
	name := u.Name
	if len(name) == 0 {
		return "unknown"
	}
	return name
}

func pcName() string {
	return format(osUser.Username)
}

func userEmail() string {
	gitConfig := filepath.Join(osUser.HomeDir, ".gitconfig")
	bytes, _ := ioutil.ReadFile(gitConfig)
	config, _, err := goconfig.Parse(bytes)
	if err == nil {
		if email, ok := config["user.email"]; ok {
			return email
		}
	}
	return fmt.Sprintf("%s@%s.com", userName(), pcName())
}

func format(name string) string {
	names := strings.Split(name, `\`)
	return names[0]
}
