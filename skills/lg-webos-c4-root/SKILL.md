---
name: lg-webos-c4-root
description: 复现和诊断用户自有 LG C4 的 downloadmanager/volatile.cache root 流程，验证 root 身份并建立个人密钥 SSH。适用于 C4 root、SlopBro Invalid input parameter 后的替代路径和冷启动后验证；历史真机范围仅为 OLED42C4PCA 43.21.96 / webOS 11.2.0-3711。
---

# LG webOS C4 root

使用随技能分发的 Python 标准库工具完成探测、一次启动阶段验证和可选 SSH 接入。Python 需 3.10 或更新版本。技能可独立安装，不依赖完整源码仓库、第三方 MCP 或电视控制器。

## 先确认范围

- 仅针对用户拥有或获授权测试的具体电视。记录完整型号、软件版本、webOS 版本、电视 IPv4 和电脑在同一可信局域网中的 IPv4；优先使用用户已有信息，不扫描无关设备。
- [历史验证](references/VERIFICATION.md) 只覆盖 OLED42C4PCA.ACNQLJD、43.21.96、webOS 26 / 11.2.0-3711。其他组合属于未验证兼容性；不能承诺通用成功。公开整理工具和本技能只做了离线测试，没有再次真机回归。
- 用户只要求解释、评估或检测已有 root 时，保持相应范围。有已授权的 SSH 连接信息时先执行新的 SSH 登录和 `id`，能够取得 root 就无需重新投递启动缓存。不要在创建技能、读文档或运行离线测试时连接电视。
- 先读 [恢复与清理](references/RECOVERY.md)。`stage` / `ssh` 会覆盖 `/mnt/lg/cmn_data/var/cache/volatile.cache`，工具不能自动读取旧内容或找回未备份内容。执行前向用户说明该具体写入及其现有恢复方案；已有明确授权可继续，不重复索要确认。用户未授权修改时仅准备命令和离线检查。
- 临时 HTTP 和 SSAP 仅用于可信局域网。电视自签名 WSS 证书未验证或固定；不要开放到公网，也不要自行修改路由器、防火墙或系统网络设置。具体来源和信任边界见 [NOTICE.md](NOTICE.md)。

## 使用随包工具

把 `<技能目录>` 替换为本 SKILL.md 所在目录的绝对路径。Python 可用 `python` 或 `python3`。在技能目录之外创建本次工作目录并在那里执行，使用 `--key-file` 显式指定本机配对文件；配对文件和运行记录不得写入技能分发目录或提交 Git。示例中的 `192.0.2.*` 是文档地址，真实执行前必须替换。

先检查命令与离线构建；`--dry-run` 不开启监听、不配对、不连接电视：

```sh
python "<技能目录>/scripts/root_flow.py" --help
python "<技能目录>/scripts/root_flow.py" --tv 192.0.2.10 --local-ip 192.0.2.20 --dry-run
```

需要网络执行时，完整阅读 [过程说明](references/PROCESS.md)，依据当前阶段选择以下模式。

### 默认 probe

```sh
python "<技能目录>/scripts/root_flow.py" --tv 192.0.2.10 --local-ip 192.0.2.20 --key-file .local/webos-client-key --pair
```

已有配对文件时复用该文件并省略 `--pair`。首次配对请用户在电视上允许。`probe` 会写入带随机标记的无害探测文件，不覆盖启动缓存，不产生 root shell。`DOWNLOAD_ACCEPTED` 只说明下载服务接受请求。

工具采用 `ssap://system.launcher/launch`、应用 `com.webos.app.tinybrowser` 和 `params.contentTarget`；页面通过 ServiceBridge 调用 downloadmanager。不要换回上游未在此设备成功使用的 `launchWebApp`，也不要把返回 `Invalid input parameter` 的 SlopBro `jsserver/run` 描述为成功路径。

### 一次 root 验证或 SSH

仅需验证启动进程身份时选 `stage`：

```sh
python "<技能目录>/scripts/root_flow.py" --tv 192.0.2.10 --local-ip 192.0.2.20 --key-file .local/webos-client-key --mode stage --acknowledge-cache-overwrite
```

需要可登录通道时直接选 `ssh`，不必先执行一轮 `stage`。提前准备用户自己的 Ed25519 公钥和与电视兼容的 Dropbear ELF；已有密钥不要覆盖，私钥始终留在电脑。历史兼容文件的官方来源与 SHA-256 见 [验证记录](references/VERIFICATION.md)。技能不附带服务器二进制，也不自动选择或下载替代文件。

```sh
python "<技能目录>/scripts/root_flow.py" --tv 192.0.2.10 --local-ip 192.0.2.20 --key-file .local/webos-client-key --mode ssh --acknowledge-cache-overwrite --ssh-pubkey /path/to/tv-key.pub --dropbear /path/to/compatible-dropbear --ssh-port 2222
```

执行 `stage` / `ssh` 的实际投递前，先给同一命令添加 `--dry-run` 验证输入。已有原始缓存备份时可加 `--restore-cache /path/to/original-volatile.cache`；没有备份时须明确只能移除本次载荷，不能恢复未知旧内容。

保持工具进程与电脑局域网连接，确认本轮收到 `DOWNLOAD_ACCEPTED` 后，请用户现场彻底断电再开机。遥控器电源可能只是待机，不能据此认定重启完成。工具不会自动重启；未经用户另行授权，不安装永久启动服务或改变电视电源设置。默认等待 600 秒；使用工具可管理的后台会话并持续给出阶段进展，不要退出临时服务后再让用户重启。

一次只进行一轮投递。出现拒绝、超时、缓存隔离/恢复错误或身份不符时，保留脱敏阶段结果，按恢复说明判断原因；不要因无画面变化或回调缺失反复覆盖缓存，不自动转为其他提权方案。

## 以新证据确认结果

| 观察结果 | 可以得出的结论 |
| --- | --- |
| `DOWNLOAD_ACCEPTED` | 下载请求被接受；尚未证明 root |
| `BOOT_ROOT_OK uid=0(root)` | 本次启动载荷以 root 身份执行 |
| `SSH_PROCESS_STARTED port=2222` | 载荷报告 SSH 进程启动；尚未证明可登录 |
| 新 SSH 连接中的 `id` 返回 `uid=0(root)` | 该连接已具备 root 身份 |

SSH 模式成功回调后，用用户自己的私钥进行独立验证：

```sh
ssh -i /path/to/tv-key -p 2222 root@192.0.2.10 id
```

按用户已有可信记录或现场取得的信息核对 SSH 主机身份。不要用关闭主机身份校验或删除冲突记录来绕过问题。2323 端口开放、界面无变化和下载成功均不能替代 `uid=0` 证据。

报告型号/固件、执行到的阶段、root 与 SSH 各自证据、缓存清理/恢复结果及剩余不确定性。保留用户现有公钥和 SSH 配置；本工具的 SSH 不保证跨后续重启持续运行。完成后确认缓存已清理或恢复，再结束临时服务。公开分享仅使用脱敏摘要，不发布私钥、配对文件、回调令牌、网络地址或原始日志。

技能及资源采用 AGPL-3.0-or-later，来源与修改见 [NOTICE.md](NOTICE.md)，许可证见 [LICENSE](LICENSE)。
