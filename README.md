# unrar — 纯 Go 的 RAR4/RAR5 只读解压库

`unrar` 以纯 Go 实现 RAR4 与 RAR5 归档的读取与解压，不依赖 cgo，不创建压缩包。公开 API 对齐标准库 `archive/zip` 的使用习惯。

## 安装

要求 Go 1.27.1 及以上版本（与 `mise.toml`  pin 的工具链一致）。

```sh
go get github.com/ayasechan/unrar
```

## 快速开始

```go
import rar "github.com/ayasechan/unrar"

r, err := rar.OpenReader("archive.part01.rar")
if err != nil {
    // ...
}
defer r.Close()

for _, f := range r.File {
    if f.IsDir {
        continue
    }
    rc, err := f.Open()
    if err != nil {
        // ...
    }
    _, err = io.Copy(dst, rc)
    rc.Close()
    if err != nil {
        // ...
    }
}
```

多分卷归档只需打开首卷，其余卷按命名规则自动枚举；非文件场景（内存数据、对象存储）使用 `NewReader` 注入自定义卷集合，见下文。

## API 说明

### 打开归档

- `rar.OpenReader(name string, opts ...Option) (*Reader, error)`：打开本地归档首卷。单卷传递本卷路径；多分卷传递第一卷路径（新式 `.part01.rar` 或旧式 `.rar`），其余卷按命名规则自动枚举。
- `rar.NewReader(vs VolumeSet, opts ...Option) (*Reader, error)`：以自定义卷集合打开，用于内存数据、对象存储等非文件场景。调用方实现 `VolumeSet` 的三个方法即可（首卷名、卷名列表、按名打开）。

### 读取条目

- `Reader.File []*File`：归档内全部条目（含目录），顺序与归档内一致。
- `Reader.Version`：`4` 或 `5`，表示检出的归档格式版本。
- `Reader.Comment`：归档注释（无注释时为空）。
- `File` 字段：`Name`（归档内原样路径）、`UnpackedSize`、`Modified`、`Mode`、`IsDir`、`Encrypted`、`Solid`。`FileInfo()` 提供 `fs.FileInfo` 视图。
- `File.Open() (io.ReadCloser, error)`：打开条目的解压数据流。每次调用返回独立流，可并发使用；调用方负责 `Close`。目录条目返回空流。固实归档中靠后的文件需从链首顺序解码，打开延迟较高，此为格式固有约束。

### 口令

```go
// 固定口令。
r, _ := rar.OpenReader("enc.rar", rar.WithPassword("secret"))

// 按文件回调口令，适用于多口令或交互式输入；返回空字符串表示无口令。
r, _ := rar.OpenReader("enc.rar", rar.WithPasswordReader(func(file string) (string, error) {
    return promptPassword(file)
}))
```

未提供口令而条目加密时，`Open` 返回 `ErrEncrypted`；口令错误返回 `ErrWrongPassword`。口令字节在使用后清零，不会出现在错误信息与日志中。

### 缺卷恢复

```go
// 自动发现首卷同目录下的 .rev 文件并在内存中重建缺失或损坏卷。
r, _ := rar.OpenReader("a.part01.rar", rar.WithRecovery(true))
```

如需自行提供恢复卷，实现三方法 `RevSet` 接口后使用 `WithRevs(rs)`。可恢复的缺卷数不得超过可用的有效恢复卷数，否则返回 `ErrNeedRecovery`。

## 错误语义

所有哨兵错误使用 `errors.Is` 判定：

| 错误 | 含义 |
| --- | --- |
| `ErrUnsupported` | 不支持的特性：RAR 1.5/2.0 算法、未知压缩方法或过滤器、超限字典、非法路径落盘等 |
| `ErrEncrypted` | 条目已加密但未提供口令 |
| `ErrWrongPassword` | 口令错误 |
| `ErrMissingVolume` | 缺卷，错误中携带期望的卷名 |
| `ErrNeedRecovery` | 损坏超出恢复能力（缺卷数多于有效恢复卷数，或恢复卷不可用） |
| `ErrChecksum` | 数据损坏（CRC32/BLAKE2 校验失败） |

口令错误与未加密数据损坏的区分：前者返回 `ErrWrongPassword`，后者返回 `ErrChecksum`。无口令校验位且口令错误时，解密失败同样表现为校验失败，此时按口令错误报告。

## 安全落盘

`File.Name` 保持归档内原样，不可直接拼接为本地路径。落盘前使用 `SafeName`：

```go
name, err := f.SafeName()
if err != nil {
    // 绝对路径或 .. 逃逸，拒绝写入。
}
```

符号链接条目按普通文件内容原样解出，库不跟随链接；是否还原链接语义由调用方决定。

## 支持矩阵

| 能力 | RAR4 | RAR5 |
| --- | --- | --- |
| stored（`m0`） | 支持 | 支持 |
| 压缩数据 | 支持（unpack29） | 支持（unpack50） |
| 文本压缩 | 支持（PPMd） | 不适用（该格式无此分支） |
| 可执行/多媒体过滤器 | 支持 E8、E8E9、Itanium、Delta、RGB、Audio 六种标准过滤器 | 支持 Delta、E8、E8E9、ARM |
| 数据加密（`-p`） | 支持（AES-128） | 支持（AES-256） |
| 头加密（`-hp`） | 支持 | 支持 |
| 多分卷（含跨卷、固实跨卷、加密跨卷） | 支持 | 支持 |
| `.rev` 缺卷重建 | 支持 | 支持 |

明确不支持：创建压缩包；RAR 1.5/2.0 时代算法；嵌入式恢复记录的原地修复（缺卷场景由 `.rev` 覆盖）；RAR5 中未定义的过滤器类型（按计数丢弃对应数据段并计入长度，与参考行为一致）。

## 资源限制

- RAR4 滑动字典上限 8MB，RAR5 上限 1GB（协议最大值），PPM 模型内存上限 256MB；超出返回 `ErrUnsupported`，不会无界分配。
- `.rev` 重建以 1MB 分块流式进行，不一次性载入整卷。
- 解压输出为流式，库本身不设总输出上限；调用方如需防解压炸弹，应在 `io.Copy` 处自行限流（例如 `io.LimitReader`）。
- 损坏输入一律返回错误，不会 panic。

## 故障排查

- 打开多分卷只看到部分文件：确认是否以首卷打开（新式首卷为 `.part01.rar`，旧式为 `.rar`），并检查后续卷是否缺失，缺失时错误会指明期望卷名。
- `ErrWrongPassword` 与 `ErrChecksum` 的区分：前者表示口令不正确（或无口令校验位时的数据损坏），后者表示未加密数据的损坏。
- 固实归档中随机打开靠后的文件速度较慢：固实链须从链首顺序解码，这是格式固有约束。
- 旧式分卷（`.r00` 起）须与首卷 `.rar` 置于同一目录。

## 面向开发者

架构、格式细节、测试与夹具规范见 `docs/` 目录。
