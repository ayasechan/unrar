# AGENTS.md — github.com/ayasechan/unrar

纯 Go RAR4/RAR5 只读解压库（不支持创建）。公开 API、错误语义、支持矩阵以根 `README.md` 为准；`docs/` 为实现视角（`architecture.md` 必读），不写用户教程。

## 布局

- 根包承载全部公开 API 与格式装配：`rar.go`（`Reader`/`File`/`VolumeSet`/`RevSet`/`Option`）、`rar4.go`/`rar5.go`/`scan.go`（扫描）、`unpack29.go`/`unpack50.go` + `chain29.go`/`chain50.go` + `copystr.go`（解包装配）、`crypt.go`（加解密编排）、`recover.go`（恢复编排）。
- `internal/` 为无归档上下文的纯算法（`bitio`/`huff`/`rarvm`/`ppm`/`rarcrypt`/`blake2s`/`rs8`/`rs16`/`vint`/`volumes`）；禁止引用根包，包之间保持单向依赖；归档逻辑只放根包。

## 命令

- 工具链为 mise pin 的 Go 1.27.1（`go.mod` 一致），直接用 `go`。
- 顺序：`go vet ./...` → `gofmt -l .`（排除 `tmp/`，须无输出）→ `go test ./...`（全量慢，主包 15s+，优先聚焦）。
- 聚焦：`go test -count=1 -run 'TestVolumes|TestMissingVolume' .`；加密加 `-run 'TestDecrypt|TestWrongPassword'`；恢复加 `-run 'TestRecover'`（`-count=1` 不可省，防缓存掩盖）。
- Fuzz：`go test -run=NONE -fuzz=FuzzReader -fuzztime=60s .`；新增解码分支后至少跑 60s；解码循环必须有确定性终止条件。
- 基准冒烟：`go test -run=NONE -bench=. -benchtime=1x .`。

## 测试与夹具

- 不变式：损坏输入只允许报错，永不 panic（`TestCorruptNeverPanics` 覆盖；fuzz 内用 `io.CopyN(..., 4<<20)` 限读防炸弹拖慢）。
- `testdata/` 下 `.rar`/`.rev` 用官方 `rar` 构建，`golden*` 为期望原文；提交前须过 `unrar t` 再与 golden 逐字节对比；优先小尺寸，大字典/多压缩块用专用小夹具，不提交超大文件。
- 构建须干净 `HOME` 隔离（用户 `~/.rarrc` 的 `-v2g` 会压制分卷、`-m0` 会改方法），且全显式开关：`-ma4`/`-ma5`、`-m0`…`-m5`、非固实显式 `-s-`（`rar a` 默认固实）、分卷 `-v`、口令 `-p`/`-hp`。
- RAR4 夹具只能用 rar 5.x 构建（rar 7.x 已移除 RAR4 创建，仅能解压）；fuzz 崩溃语料自动落入 `testdata/fuzz/FuzzReader/`，作为回归种子提交。

## 硬约束

- `tmp/` 为本地参照（官方源码、工具链解包，已在 `.gitignore`），代码与文档禁止引用其内部任何内容，且不在提交范围内。
- 改公开 API 须同步根 `README.md`（用户视角）与 `docs/`（实现视角）；新增哨兵错误须在根 README 错误表登记语义；文档同步重写，不保留废弃章节与历史过程，术语与根 README 一致。
- 口令与密钥字节用完即清零；错误信息与日志永不回显口令；`errors.Is` 判定哨兵错误（无口令 `ErrEncrypted`、错口令 `ErrWrongPassword`、未加密损坏 `ErrChecksum`，无校验位时的解密失败按口令错误报告）。
- 所有内存分配必须设上限，超限返回 `ErrUnsupported`：RAR4 字典 8MB、RAR5 字典 1GB、PPM 模型 256MB、位流缓冲 32KB、`.rev` 重建 1MB 分块流式；解压输出为流式，库不设总输出上限，调用方用 `io.LimitReader` 防炸弹。
- 分卷须以首卷打开（新式 `.part01.rar`、旧式 `.rar`，旧式 `.r00` 起须与首卷同目录）；缺卷报 `ErrMissingVolume`（携带期望卷名），不做猜测性跳过。
- `File.Open` 每次返回独立流、并发安全；固实链复用窗口/表/OldDist、位流每文件重起，固实归档打开靠后文件从链首顺序解码、慢是预期；落盘前必须过 `SafeName`，符号链接按普通文件内容解出、库不跟随。
