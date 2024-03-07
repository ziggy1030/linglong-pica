# ll-pica使用

## 安装

### 手动编译安装

- 配置go环境
  参考 [配置go开发环境](https://blog.csdn.net/qq_41648043/article/details/117782776)
  或者：安装deb配置go环境。

```
sudo apt update
sudo apt install golang-go golang-dlib-dev
```

- 下载代码
  源码[linglong-pica](https://gitlabwh.uniontech.com/wuhan/v23/linglong/linglong-pica)
- 安装release版本（未开启开发者模式，日志调试模式关闭。）

```
git clone https://gitlabwh.uniontech.com/wuhan/v23/linglong/linglong-pica.git
git checkout develop/snipe
cd linglong-pica
make
sudo make install
```

- 安装debug版本（开启开发者模式，日志调试模式开启。）

```
git clone https://gitlabwh.uniontech.com/wuhan/v23/linglong/linglong-pica.git
git checkout develop/snipe
cd linglong-pica
make debug
sudo make install
```

- 手动安装使用依赖包，当deb包安装时无需手动下载

```bash
sudo apt update
sudo apt install linglong-builder
```

## 工具说明

本工具目前提供deb包转换为玲珑包的能力。本工具需要提供对于被转换的目标的描述文件，通过描述文件
可以配置转换所需的环境和资源，同时描述文件可以通过定制，干预转换过程。

### 工具安装

本工具当前主要在deepin/UOS系统上适配，deepin/UOS系统可以通过添加如下仓库

- 仓库（社区版本）
  `deb https://community-packages.deepin.com/beige/ beige main commercial community`
- 仓库（专业版本）
  敬请期待。
- 下载安装

```
sudo apt update
sudo apt install linglong-pica
```

## 工具使用

### 参数介绍

ll-pica是本工具的命令行工具，主要包含转换环境的初始化、转包、上传玲珑包等功能。

查看ll-pica帮助信息：

`ll-pica --help`

ll-pica帮助信息显示如下：

```bash
Convert the deb to uab. For example:
Simple:
        ll-pica init -c package -w work-dir
        ll-pica convert -c package.yaml -w work-dir
        ll-pica push -i appid -w work-dir
        ll-pica help

Usage:
  ll-pica [flags]
  ll-pica [command]

Available Commands:
  convert     Convert deb to uab
  help        Help about any command
  init        init config template
  push        push app to repo

Flags:
  -h, --help      help for ll-pica
  -v, --verbose   verbose output

Use "ll-pica [command] --help" for more information about a command
```

ll-pica包含init、convert、push等命令参数

- init 初始化模板。
- convert 转包操作。
- push上传玲珑包操作。

### 环境初始化

通过使用ll-pica的init命令，对转换所需的环境初进行始化。

通过 `ll-pica init --help`命令的查找帮助信息：

ll-pica init 帮助信息显示如下：

```bash
init config template.

Usage:
  ll-pica init [flags]

Flags:
  -c, --config string    config (default "package")
  -h, --help             help for init
  -w, --workdir string   work directory

Global Flags:
  -v, --verbose   verbose output
```

运行ll-pica init命令初始化runtime环境：
`ll-pica init -c package -w workdir` 或 `ll-pica init`

#### 参数说明

config参数，-c, --config 指定配置的模板类型，目前只有 package，且为默认参数，可以不进行指定参数。

workdir参数，-w, --workdir 工具的工作目录，下载 deb 包，解压文件，生成 linglong.yaml 都会在该工作目录下，可以不指定参数，默认路径为 `~/.cache/linglong-pica`。

配置文件模板如下：

```bash
runtime:
  type: ostree
  id: org.deepin.Runtime
  version: 23.0.0
file:
  deb:
    - type: repo
      id: com.baidu.baidunetdisk
      name: baidunetdisk
      ref: https://com-store-packages.uniontech.com/appstorev23/pool/appstore/c/com.baidu.baidunetdisk/com.baidu.baidunetdisk_4.17.7_amd64.deb
      kind: app
      hash: 

    - type: repo
      id: com.qq.wemeet
      name: wemeet
      ref: https://com-store-packages.uniontech.com/appstorev23/pool/appstore/c/com.qq.wemeet/com.qq.wemeet_3.19.0.401_amd64.deb
      kind: app
      hash: 

    # - type: local
    #   id: com.baidu.baidunetdisk
    #   name: baidunetdisk
    #   ref: /tmp/com.baidu.baidunetdisk_4.17.7_amd64.deb
    #   kind: app
    #   hash: 

```

模板字段说明

- runtime 字段为必须配置，需要运行玲珑应用的基础环境，指定包名和版本。

  - type 字段必须配置，调用的方式 ostree。
  - id 字段必须配置，包的唯一识别名称。
  - version 字段必须配置，运行环境的版本。
- file 字段为必须配置，需要转换的包文件类型。

  - deb 字段为必须配置，表示 deb 包类型的包
    - type 字段必须配置，获取包的方式，repo 指定 url 下载，local 指定本地路径。
    - id 字段必须配置，对应玲珑包唯一识别名称。
    - name 字段为必须配置，软件包名称。
    - ref 字段被可选配置，如果指定了 type 为 repo ，就使用 url 地址，并且 ref 留空，使用 apt 自动查询源里可用的，如果指定 type 为 local, 就指定本地绝对路径。
    - kind 字段必须配置，app 指应用软件包，lib 指开发库。
    - hash 字段备选配置，如果为空不进行 hash 验证，否则进行验证。

### 转包

通过使用 `ll-pica convert `命令进行转包。

ll-pica convert帮助信息显示如下：

```bash
Convert the deb to uab For example:
Convert:
        ll-pica init
        ll-pica convert  --config package.yaml --workdir /mnt/workdir --build true

Usage:
  ll-pica convert [flags]

Flags:
  -b, --build            build linglong
  -c, --config string    config (default "package.yaml")
  -h, --help             help for convert
  -w, --workdir string   work directory

Global Flags:
  -v, --verbose   verbose output
```

执行 `ll-pica convert  -c config.yaml -w /mnt/workdir`命令进行转包：

#### 参数说明

config参数，-c, --config 指需要转包的配置文件，默认参数为package.yaml，可以不进行指定参数。

workdir参数，-w, --workdir 工具的工作目录，下载 deb 包，解压文件，生成 linglong.yaml 都会在该工作目录下，可以不指定参数，默认路径为 `~/.cache/linglong-pica`。

build参数，-b, --build 指需要进行玲珑包构建，默认参数为 false，如果为 true 生成 linglong.yaml 文件并进行构建导出 layer 文件。

### 上传玲珑包

通过使用 `ll-pica push`命令用于玲珑包上传仓库。

查看ll-pica push帮助信息：

`ll-pica push --help`
ll-pica convert帮助信息显示如下：

```
Push app to repo that used ll-builder push For example:
push:
        ll-pica push -u deepin -p deepin -i appid -w workdir

Usage:
  ll-pica push [flags]

Flags:
  -i, --appid string       app id
  -c, --channel string     app channel (default "linglong")
  -h, --help               help for push
  -p, --passwords string   passwords
  -r, --repo string        repo url
  -n, --reponame string    repo name
  -u, --user string    username
  -w, --workdir string     work directory

Global Flags:
  -v, --verbose   verbose output
```

运行ll-pica push命令如下：
`ll-pica push -u deepin -p deepin -i org.deepin.calculator -w work-dir`

#### 参数说明

-i, --appid 指定app id 名。
-c, --channel 指定channel,默认为linglong。
-u, --user 指定上传账号。
-p, --passwords 指定上传账号密码。
-r, --repo 指定上传仓库url。
-n,--reponame 指定上传仓库名。
-w,--workdir 指定工作目录。
