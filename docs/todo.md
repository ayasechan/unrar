# 待办

## 注释（comment）支持

现状：`Reader.Comment` 字段已存在但扫描器从不赋值，恒为空；`File` 无注释字段。归档注释与文件注释在扫描阶段均被跳过。

- RAR4：MAIN 头标志 `0x0002` 表示归档注释存在，注释存于 `0x75` 注释头；FILE 头标志 `0x08` 表示该文件有注释。需在扫描器中解析并分别填入 `Reader.Comment` 与新增的 `File` 字段。
- RAR5：注释为 SERVICE 服务数据，当前解压跳过。需确认归档注释与文件注释在服务块中的位置与编码后，再接入扫描器。
- 待确认：注释文本编码（官方 `rar` 按何种编码写入/展示）、头加密（`-hp`）下注释是否可见、超长注释的内存上限（参考现有 1MB 分块约束，不得无界分配）。
- 公开 API 变更（`File` 新增字段）须同步根 README；夹具须用官方 `rar` 构建含注释归档并做 golden 对比。

## 一次遍历提取 API

固实归档逐个 `Open` 为二次方量级（见 README 故障排查）。新增按链序逐个交付文件流的方法，内部只跑一遍解码链。涉及公开 API，需同步根 README 与本目录文档。

## 文件名编码集成夹具（阻塞中）

`WithFilenameEncoding` 当前仅有合成字节单测，无真实 GBK 文件名 RAR4 夹具。已实测两条路，均走不通：

1. 本机无官方 `rar`、无 CJK locale。后用官方 rar 5.50 tarball（外部获取，仅作打包工具使用）配合 `localedef -i zh_CN -f GBK` 自编译 locale 补齐环境。
2. 即使补齐，rar 5.50 与 6.24 对非 ASCII 名恒写 `LHD_UNICODE`（`0x0200`）扩展：`LC_ALL=C` 下扩展内容为按字节误转的乱码（官方 `rar l` 同样显示乱码，`unrar t` 仍通过）；`LC_ALL=zh_CN.GBK` 下扩展正确，缺省读出即中文，根本走不到 ANSI 分支。5.5/6.24 均无 `-sc` 类开关可压制扩展；7.23 已整个移除 `-ma` 开关（`Unknown option: ma4`），连 RAR4 都建不出，版本升级此路不通。

因此纯 ANSI（无 `0x0200`）夹具用现有工具链无法产出，`decodeANSIName` 的覆盖维持合成字节单测。若未来发现可产出的版本/开关，夹具命名 `t4gbk.rar`，测试用 `WithFilenameEncoding(EncodingGBK)` 断言中文名，`unrar t` 通过后再与 golden 逐字节对比。
