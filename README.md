# LG webOS C4 root 实测过程

本仓库记录在 **LG OLED42C4PCA.ACNQLJD、软件版本 43.21.96、webOS 26 / 11.2.0-3711** 上成功取得 root 命令执行并建立 SSH 通道的过程，提供脱敏后的工具与离线测试。

基础研究来自 [p0luxthr0w/webos-downloadmanager-root](https://github.com/p0luxthr0w/webos-downloadmanager-root)。上游固定版本仍将这条链标为静态发现；本仓库补充的是这台 C4 的历史现场验证与适配整理。**本次公开整理后的工具只做了离线验证，未在电视上重新运行。** 其他机型、固件和后续系统更新的兼容性尚未验证。

## 成功路径

```text
电脑提供临时 HTTP 页面和文件
  → 电视允许 SSAP 配对，使用 tinybrowser 的 contentTarget 打开页面
  → downloadmanager 写入可写分区的 volatile.cache
  → 用户彻底断电后重新开机
  → 启动阶段以 root 执行 volatile.cache
  → 验证 uid=0，再建立使用个人公钥的 SSH 通道
```

目标文件是 `/mnt/lg/cmn_data/var/cache/volatile.cache`；在本次验证的系统上，该可写目录映射到 `/var/cache`，启动消费者会执行其中的脚本。详细步骤见 [过程说明](docs/PROCESS.md)，历史结果见 [验证记录](docs/VERIFICATION.md)。

SlopBro 的 `jsserver/run` 在本次目标上返回 `Invalid input parameter`，没有用这条路径获得 root。历史测试中，2323 端口的 telnet 也未形成可靠通道，最终使用 root 命令执行与 Dropbear SSH 2222 完成接入。

## 开始前

- 使用自己拥有且能够进行现场恢复的电视；电脑与电视应在可信局域网内。
- 临时 HTTP 服务使用本机局域网地址；SSAP 的电视自签名 TLS 证书未校验或固定，网络信任边界见 [来源与实现说明](NOTICE.md)。
- 需要 Python 3.10 或更新版本。工具只使用 Python 标准库；首次连接须加 `--pair` 并在电视上允许配对，后续可复用本机配对文件。
- 先读取 [恢复与清理](docs/RECOVERY.md)。`stage` / `ssh` 会覆盖启动缓存文件，工具不会自动取得其原内容，也不能承诺恢复未备份的文件。
- 先运行默认的 `probe`。下载返回成功只说明下载请求被接受；root 身份与 SSH 登录需要后续各自验证。

所有示例地址均为文档保留地址，必须替换为自己的局域网地址。终端命令在仓库根目录执行；Windows 可使用 `python`，其他系统也可使用 `python3`。

## 使用

```sh
git clone https://github.com/RickeyRen/lg-webos-c4-root.git
cd lg-webos-c4-root
python tools/root_flow.py --help
```

### 1. 默认探测

```sh
python tools/root_flow.py --tv 192.0.2.10 --local-ip 192.0.2.20 --pair
```

默认模式为 `probe`，仅投递探测文件，不修改启动入口、不重启电视。配对数据默认留在本机 `.local/`，该目录不应上传或分发。

### 2. 验证启动阶段的 root 身份

确认已有恢复方案后，显式选择 `stage`：

```sh
python tools/root_flow.py --tv 192.0.2.10 --local-ip 192.0.2.20 --mode stage --acknowledge-cache-overwrite
```

等候工具确认文件投递，再按其提示执行彻底断电重启，保持电脑与工具运行。默认等待时间为 600 秒，可通过 `--timeout` 调整。遥控器电源键可能只进入待机。启动后的身份回报包含 `uid=0` 才能证明执行进程具有 root 权限；收到投递成功或看到端口开放都不能单独证明这一点。

### 3. 建立 SSH

准备一对仅用于自己电视的 **Ed25519 SSH 密钥**，并自行取得与电视架构及用户空间兼容的 Dropbear 服务器文件。仓库不分发服务器二进制、私钥、配对令牌或共享密码。

历史现场成功使用的服务器来自 [webOS Homebrew Channel 0.7.3 官方发布包](https://github.com/webosbrew/webos-homebrew-channel/releases/tag/v0.7.3)。解开 IPK 的数据归档后，取出其中的相对路径：

```text
usr/palm/services/org.webosbrew.hbchannel.service/bin/dropbear
```

本次现场使用文件的 SHA-256 为：

```text
8f5b03abd1075b843eba4b204de380cd30f7cb2940090f7c13276b54aab70f20
```

可以只提取该文件供 `--dropbear` 使用，无需为本流程安装 Homebrew Channel。本仓库不镜像或分发该二进制；历史哈希用于确认曾使用的文件，不证明它对其他系统通用兼容，也不代替检查其来源与许可证。

```sh
python tools/root_flow.py --tv 192.0.2.10 --local-ip 192.0.2.20 --mode ssh --acknowledge-cache-overwrite --ssh-pubkey /path/to/tv-key.pub --dropbear /path/to/compatible-dropbear --ssh-port 2222
```

完成工具提示的冷启动后，使用自己的私钥登录并检查身份：

```sh
ssh -i /path/to/tv-key -p 2222 root@192.0.2.10 id
```

历史现场中曾成功启动 SSH 2222。公开工具以一次启动流程为边界，不自动安装永久启动服务，也不保证 SSH 会跨越后续每次重启持续运行。

如果已有原始 `volatile.cache` 文件备份，可为 `stage` / `ssh` 添加 `--restore-cache /path/to/original-volatile.cache`。载荷先检查本次标记并将自己移到非启动名 `volatile.cache.disabled-<run-id>`，再下载、校验备份后恢复。下载或校验失败会停止并保留隔离副本，不写入 root 证明文件，也不继续启动 SSH；已隔离的副本不会在下次启动时被缓存消费者执行。工具不能自动找回未备份的旧内容，隔离失败也需人工检查。详见 [恢复说明](docs/RECOVERY.md)。

## 离线验证

```sh
python tools/root_flow.py --tv 192.0.2.10 --local-ip 192.0.2.20 --mode stage --acknowledge-cache-overwrite --dry-run
python -m unittest discover -s tests -v
```

`--dry-run` 不连接电视、不开启 HTTP 服务，只检查参数和生成结果摘要。离线测试验证请求构造、运行隔离与载荷处理；它不能证明电视固件允许相同的请求，也不能代替新的真机兼容性测试。

当前共有 20 项离线测试。Linux 有可用的 POSIX shell 时可直接运行。Windows 若已有 Git for Windows，可在 PowerShell 指定其 Bash，让 shell 夹具一并运行：

```powershell
$env:LG_ROOT_TEST_SHELL = 'C:/Program Files/Git/usr/bin/bash.exe'
python -m unittest discover -s tests -v
```

按自己的实际安装位置修改路径；没有可用 shell 时，6 项 shell 夹具会明确跳过，其余测试照常执行。GitHub Actions 为 Ubuntu 与 Windows 分别指定 shell，检查完整测试集。

## 与 LG TV 控制器配合

取得并验证 root SSH 后，可在 [LG TV 控制器](https://github.com/RickeyRen/lg-tv-controller) 的连接设置中填写电视 IP、SSH 端口和自己的私钥路径。控制器是独立项目；其仓库当前为私有，访问需要相应权限。普通遥控配对和 root SSH 使用各自的授权信息。

## 来源与许可证

本项目采用 **AGPL-3.0-or-later**。上游研究与代码来源、固定提交及本次修改范围见 [NOTICE.md](NOTICE.md)，完整许可证见 [LICENSE](LICENSE)。此项目与 LG 官方没有隶属或认可关系，LG 与 webOS 名称归各自权利人所有。
