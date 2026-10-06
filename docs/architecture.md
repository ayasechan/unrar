# 架构

## 包结构

根包 `github.com/ayasechan/unrar` 承载全部公开 API 与格式装配逻辑；`internal/` 下各包职责单一，仅承载无归档上下文的纯算法：

| 包 | 职责 |
| --- | --- |
| 根包 | `Reader`/`File`/`VolumeSet`/`RevSet`/`Option`，RAR4/RAR5 扫描器（`rar4.go`/`rar5.go`/`scan.go`），解包器装配（`unpack29.go`/`unpack50.go`、`chain29.go`/`chain50.go`、`copystr.go`），加解密编排（`crypt.go`），恢复编排（`recover.go`） |
| `internal/bitio` | MSB 优先滑动位流（32KB 缓冲，半满压缩，尾部零垫） |
| `internal/huff` | Huffman 解码表，快慢双路解码 |
| `internal/rarvm` | RAR3 六种标准过滤器（E8/E8E9/Itanium/Delta/RGB/Audio，以字节码长度与 CRC32 识别类型） |
| `internal/ppm` | PPMd 阶模型、子分配器（偏移式 arena） |
| `internal/rarcrypt` | SHA-1（含 RAR2.9 变体）、KDF3、PBKDF2-HMAC-SHA256、AES-CBC、口令编码 |
| `internal/blake2s` | BLAKE2s-256（标准库缺失，自实现，RFC 向量验证） |
| `internal/rs8` | GF(256) Reed-Solomon 纠删（RAR4 恢复卷） |
| `internal/rs16` | GF(2^16) Cauchy 矩阵 RS（RAR5 恢复卷） |
| `internal/vint` | RAR5 小端 7bit 续位可变长整数 |
| `internal/volumes` | 新旧分卷命名推导与反查 |

## 核心类型

- `Reader`：已打开的归档。持有文件表（`File`）、卷句柄、口令配置、KDF 缓存。`Close` 释放卷句柄并清零口令内存。
- `File`：归档条目描述（名称、大小、时间、模式、目录/加密/solid 标记）与内部数据描述（含各卷分段表）。`Open` 每次返回独立的数据流。
- `VolumeSet`：卷集合抽象（首卷名、卷名列表、按名打开），默认实现基于本地文件，测试与对象存储可注入内存实现。
- `RevSet`：恢复卷集合抽象，与 `VolumeSet` 对称。
- `Option`：`WithPassword`（固定口令）、`WithPasswordReader`（按文件回调）、`WithRecovery`（自动发现 `.rev`）、`WithRevs`（显式提供）。

## 解压流水线

```
卷枚举 -> 头解析 -> 跨卷拼接 -> 解密 -> 解压 -> 过滤器 -> 校验 -> 输出
```

1. **卷枚举**：首卷名推导全卷名；缺卷报 `ErrMissingVolume`（携带期望卷名），不做猜测性跳过。
2. **头解析**：签名定版本后逐块解析并校验（RAR4 CRC16、RAR5 CRC32），建立文件表与分段表（卷序号，卷内偏移，长度）。头加密时先派生密钥再解密解析。
3. **跨卷拼接**：文件 PACK 流按分段表跨卷顺序读，对解包器呈现连续字节流。
4. **解密**：RAR4 AES-128-CBC，RAR5 PBKDF2 派生后 AES-256-CBC；CBC 跨卷连续。
5. **解压**：stored 直拷；RAR4 unpack29；RAR5 unpack50；PPMd 文本分支。固实链复用解包器状态（窗口、表、OldDist 常驻），位流每文件重起。
6. **过滤器**：RAR4 走标准过滤器程序；RAR5 走原生 Delta/E8/E8E9/ARM 实现。
7. **校验输出**：CRC32 与可选 BLAKE2s（含 RAR5 HMAC 变体）；流式输出，不一次性进内存。

## 并发与内存模型

- `Reader` 的文件表只读共享；每个 `File.Open` 创建独立解码器（含窗口、位流、解密器），并发安全。
- 口令派生结果按（算法，口令，salt）缓存于 `Reader`，IV 等 per-file 参数不进缓存。
- 内存上限定量：RAR4 字典 8MB，RAR5 字典 1GB，PPM 模型 256MB，位流缓冲 32KB，恢复重建 1MB 分块；超限返回 `ErrUnsupported`。

## 错误设计

全部哨兵错误使用 `errors.Is` 判定，语义见根 README 错误表。映射原则：无口令报 `ErrEncrypted`；有口令校验位时错口令报 `ErrWrongPassword`；无校验位时解密失败按口令错误报告；未加密数据损坏报 `ErrChecksum`；分卷续头 CRC 取末卷值，中续卷存本卷 pack 段 CRC。
