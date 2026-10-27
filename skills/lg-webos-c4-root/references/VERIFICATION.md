# 验证记录

## 历史现场范围

| 项目 | 记录 |
| --- | --- |
| 设备型号 | LG OLED42C4PCA.ACNQLJD |
| 软件版本 | 43.21.96 |
| 系统显示 | webOS 26 / 11.2.0-3711 |
| 测试日期 | 2026-10-23 |
| 触发流程 | `downloadmanager` → 可写分区 `volatile.cache` → 彻底断电后开机 |
| root 命令执行 | 历史现场输出包含 `uid=0(root) gid=0(root)` |
| SSH | 历史现场中 Dropbear 启动成功，监听 2222；随后供电视控制器使用 |

型号与固件是兼容性信息，不是电视序列号。此表只记录这一台设备，没有外推到所有 C4、全部地区版本或其他 webOS 型号。

## 脱敏证据摘录

以下是历史现场记录的人工摘录，移除了电脑与电视地址、回调凭据、密钥内容、SSH 主机指纹、进程编号和原始路径上下文：

```text
root command identity:
uid=0(root) gid=0(root)

SSH server bootstrap:
dropbear_rc=0
TCP listen port: 2222
```

摘录用于说明当时观测到了什么；它不是新的测试执行结果，也不是针对所有软件版本的认证。原始现场日志不随公开仓库分发。

## 已尝试但未作为成功路径的方案

- SlopBro 的 `jsserver/run` 在本次目标上返回 `Invalid input parameter`，未通过该入口取得 root。
- 一度尝试启动 2323 端口的 telnet。端口及其通道没有形成可靠的最终接入方式，不能据此宣称当前仓库提供通用 telnet root。
- 初期 Dropbear 路径缺失时，启动失败；之后准备了兼容服务器文件，才观测到成功启动与 2222 监听。

这些是本次现场过程中的结果，不代表相关项目对其他版本的总体兼容性结论。

## 历史 SSH 服务器来源

成功使用的服务器文件来自 [webOS Homebrew Channel 0.7.3 官方发布包](https://github.com/webosbrew/webos-homebrew-channel/releases/tag/v0.7.3) 数据归档中的 `usr/palm/services/org.webosbrew.hbchannel.service/bin/dropbear`。当前保留文件的哈希与历史成功记录一致：

```text
SHA-256: 8f5b03abd1075b843eba4b204de380cd30f7cb2940090f7c13276b54aab70f20
```

这里记录的是公共服务器二进制的文件哈希，不包含电视 SSH 主机指纹或个人密钥。仓库不附带该二进制，不要求安装 Homebrew Channel，也没有据此验证所有设备的兼容性。

## 本次公开整理的验证边界

公开工具使用参数化地址、运行时随机凭据和个人 SSH 公钥，去掉了原现场环境的固定值。此版本只进行了离线检查与模拟测试，**没有为了发布而再次修改或重启真实电视**。

离线测试可以验证代码如何构造请求、处理回调、生成载荷及执行清理条件；电视的服务权限、启动顺序、服务器二进制兼容性和实际 SSH 登录仍需要在新设备上分别验证。历史 root 成功不能自动证明整理后的每一行代码已经完成真机回归。
