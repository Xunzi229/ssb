# SSB

用于管理不同场景下SSH KEY。 

有时候我们办公用的是一套SSH KEY, 个人使用一套SSH KEY ，如果每次都是手动变更配置，
其实相当的麻烦， 所以基于这个场景， 于是肝了一天， 写了一个SSH配置管理的工具。

这个工具的用途

    * 基于 rsa 生成 ssh key
    * 备份当前的 ssh 配置
    * 导出配置
    * 导入配置
    * 跨平台
    * 切换 ssh 配置

#### Usage

主要用于管理多ssh key的问题

* 安装

```shell
$: go install .
```

* 生成的新的KEY
```shell
$: ssb g 
# 或者
$: ssb gen
```

* 备份当前的 key
```shell
$: ssb backup tagName
# 或者
$: ssb b tagName

#   UniqueId    TagName
#* 6fed5f86d8     home
#  6fed5f86d8     work
```

tagName: 用户恢复 或者切换配置的时候使用的

* 切换的备份

```shell
$: ssb switch tagName # ssb switch UniqueId
# 或者
$: ssb s tagName      # ssb switch TagName
```

* 导出备份文件

> 默认备份在主目录 $HOME

```shell
$: ssb p # 默认备份在主目录
$: ssb p ~/Desktop/ # 备份文件存在桌面
$: ssb export .     # 备份文件存在当前目录
```

* 恢复备份文件

```shell
$: ssb load ~/Desktop/backup.zip
```


### 权限问题

可能在配置的时候出现权限的问题。

> 保证初始的权限， 不然会更新异常的问题

```shell
chmod -R 755 ~/.ssh
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
```