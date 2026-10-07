# 待办

## 一次遍历提取 API

固实归档逐个 `Open` 为二次方量级（见 README 故障排查）。新增按链序逐个交付文件流的方法，内部只跑一遍解码链。涉及公开 API，需同步根 README 与本目录文档。

## 文件名编码集成夹具（阻塞中）

`WithFilenameEncoding` 当前仅有合成字节单测，无真实 GBK 文件名 RAR4 夹具。已实测两条路，均走不通：

1. 本机无官方 `rar`、无 CJK locale。后用官方 rar 5.50 tarball（外部获取，仅作打包工具使用）配合 `localedef -i zh_CN -f GBK` 自编译 locale 补齐环境。
2. 即使补齐，rar 5.50 与 6.24 对非 ASCII 名恒写 `LHD_UNICODE`（`0x0200`）扩展：`LC_ALL=C` 下扩展内容为按字节误转的乱码（官方 `rar l` 同样显示乱码，`unrar t` 仍通过）；`LC_ALL=zh_CN.GBK` 下扩展正确，缺省读出即中文，根本走不到 ANSI 分支。5.5/6.24 均无 `-sc` 类开关可压制扩展；7.23 已整个移除 `-ma` 开关（`Unknown option: ma4`），连 RAR4 都建不出，版本升级此路不通。

因此纯 ANSI（无 `0x0200`）夹具用现有工具链无法产出，`decodeANSIName` 的覆盖维持合成字节单测。若未来发现可产出的版本/开关，夹具命名 `t4gbk.rar`，测试用 `WithFilenameEncoding(EncodingGBK)` 断言中文名，`unrar t` 通过后再与 golden 逐字节对比。
