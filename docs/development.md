# 开发指南

## 构建与检查

要求 Go 1.27.1 及以上版本（与 `mise.toml` 一致）。

```sh
go vet ./...
gofmt -l .            # 除 tmp/ 外须无输出
go test ./...         # 全量测试
```

## 测试

```sh
go test ./...                                              # 全量
go test -run 'TestVolumes|TestMissingVolume' .             # 分卷
go test -count=1 -run 'TestDecrypt|TestWrongPassword' .     # 加密
go test -count=1 -run 'TestRecover' .                       # 恢复
go test -run=NONE -bench=. -benchtime=1x .                  # 基准冒烟
```

破坏输入不变式由 `TestCorruptNeverPanics` 覆盖：随机破坏夹具只允许报错，不允许 panic。

## Fuzz

```sh
go test -run=NONE -fuzz=FuzzReader -fuzztime=60s .
```

- 语料来自 `testdata/` 各格式首卷，崩溃输入自动落入 `testdata/fuzz/FuzzReader/` 作为回归种子提交。
- 解码循环须有确定性终止条件；新增解码分支后应先跑至少 60 秒 fuzz。

## 夹具生成规范

`testdata/` 下 `.rar`/`.rev` 以官方 `rar` 构建，`golden*` 为期望原文。构建须满足：

1. **干净环境**：用户 `~/.rarrc` 可能预设开关（如 `-v2g` 会压制分卷、`-m0` 会改变压缩方法），构建时须隔离。做法示例：`HOME` 指向空目录，或逐项确认生效开关。
2. **全显式开关**：格式（`-ma4`/`-ma5`）、方法（`-m0`…`-m5`）、固实（非固实必须显式 `-s-`，因 `rar a` 默认建固实归档）、分卷（`-v`）、口令（`-p`/`-hp`）全部显式给出，不依赖默认值。
3. **内容对照**：每个夹具须经官方 `unrar t` 验证通过，再与 golden 逐字节对比后提交。
   注释夹具例外：注释是元数据，以测试内联期望值（`Reader.Comment` 直接断言）代替 golden 文件。
4. **体量控制**：优先小尺寸内容；大字典、多压缩块等边界用专用小夹具覆盖，不提交超大文件。

工具链（仅作打包/验证工具，不入仓库）：官方 Linux 构建如 https://www.win-rar.com/fileadmin/winrar-versions/rarlinux-x64-624.tar.gz（6.24，保留 `-ma4` 可建 RAR4；注意 7.x 已移除 RAR4 创建）。

参考实现（仅作格式对照，不引用、不入仓库）：UnRAR 源码 https://www.rarlab.com/rar/unrarsrc-7.3.1.tar.gz。

## 编码约定

- 公开 API 变更须同步更新根 `README.md`（用户视角）与本目录文档（实现视角）。
- 新增哨兵错误须在根 README 错误表中登记语义。
- 内部包禁止引用根包；`internal/` 包之间保持单向依赖。
- 内存分配一律设上限，超限返回 `ErrUnsupported`，禁止无界分配。
- 口令与密钥字节用完即清零；错误信息与日志永不回显口令。

## 提交前检查

1. `go vet ./...` 通过。
2. `gofmt -l .`（除 `tmp/` 外）无输出。
3. `go test ./...` 全量通过。
4. 文档同步重写：删除已废弃章节，不保留历史过程记录；术语与根 README 保持一致。
5. 确认未引用 `tmp/` 内任何内容，且 `tmp/` 不在提交范围内。
