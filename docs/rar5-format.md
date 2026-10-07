# RAR5 数据结构

签名 8 字节：52 61 72 21 1A 07 01 00。

## 自描述头（除 CRC 外全为 vint，小端 7bit 续位）

vint 最多 10 字节（64 位）。

HEAD_CRC u32le（从 HEAD_SIZE 起之后所有头字节的 CRC32），HEAD_SIZE vint（不含 CRC 的头总长；
协议常见编码 3 字节内约 2MB，本实现单个头上限 8MB 即 `maxHeader5`，超限报 `ErrChecksum`），
TYPE vint，FLAGS vint，
EXTRA_SIZE vint（有 extra 标志时），DATA_SIZE vint（有 data 标志时）。
之后是各类型私有字段，然后 extra 区，最后是数据区（DATA_SIZE 字节，CRC 与头长均不计入）。

HEAD 通用 FLAGS：0x01 有 extra，0x02 有 data，0x04 未知块可跳过（不认识时按头长/数据长跳过，
不报错、不保留；本实现不检查该位，一律跳过），0x08 数据续自上卷，0x10 数据续到下卷，0x20 依赖前一文件块（子块），
0x40 宿主变更时保留子块。

## 块类型

1 MAIN：归档属性。私有 ArcFlags：0x01 分卷，0x02 卷号字段存在（首卷除外），0x04 solid，
0x08 恢复记录存在，0x10 锁定。extra 可带定位器（Locator，快速定位服务块，本库未用，
全卷扫描）与元数据（Metadata，原名与创建时间），未知记录跳过。
2 FILE：文件/目录头。通用 FLAGS 见上；私有 FLAGS：0x01 目录，0x02 有 MTIME，
0x04 有 DATA_CRC32，0x08 解压大小未知（该标志下 UNP_SIZE 字段仍在但须忽略，解到压缩流尾为止）。
字段按序：FLAGS vint，UNP_SIZE vint，ATTR vint，MTIME（fhflUtime 置位时），
DATA_CRC32（fhflCRC32 置位时），压缩信息 vint，HOST_OS vint（0 Windows，1 Unix），
NAME_LEN vint + NAME（UTF-8）。

压缩信息：低 6 位为算法版本（0 可解，1 需 RAR 7.0+，本库仅支持 0，其余报 `ErrUnsupported`）；
0x40 为 solid 位（仅 FILE 可置，SERVICE 永不置）；8~10 位（零基 7~9）为压缩方法
（0 store，1~5 各级压缩）；11~15 位（零基 10~14）为字典（128KB×2^N；
本库 unpVer==0 只取其中低 4 位，v1 扩展位另计，见 `rar5.go`）。
3 SERVICE：与 FILE 同数据结构，存放附属信息。已用名：CMT 归档注释，QO 快速打开数据，
ACL（NTFS 权限），STM（NTFS 流），RR（恢复记录）。名为 `CMT` 的是归档注释
（位于 MAIN 之后、文件头之前）：体字段与 FILE 同布局，
数据为 UTF-8（实测官方打包含尾零；读取时截首个 NUL），按文件流同管线单次解出
（stored，或主算法且 unpVer==0；带 DATA_CRC32 则校验 CRC32，有 BLAKE2s 时并校验），
上限 16MB（0x1000000 字节），任何解码失败均留空；非 CMT 服务块（含 QO 缓存）解析后丢弃，
不进文件表（`.rev` 恢复与 SERVICE 无关，见 volumes-recovery-crypto.md）。
4 ENCRYPTION：头加密参数。版本（仅 0，即 AES-256），标志（0x01 含口令校验值），
KDF 轮数对数（1B），salt（16B），校验值（12B，有标志时）。其后每头前置 16B IV，
头数据按 16B 对齐加密。
5 ENDARC：卷尾。私有标志 0x01 表示分卷且非末卷。归档后可跟第三方数据（如签名），不读取。

## Extra 记录

每条为 SIZE vint + TYPE vint + 数据。已用类型：0x01 文件加密（版本/标志/KDF 轮数对数 1B/
salt/IV/校验；0x02 置位时校验码经 key 调制，校验走 MAC 双轨，见 decode-flow.md），
0x02 文件哈希（0x00，32B 摘要），0x03 高精度时间，0x04 文件版本，0x05 重定向（链接目标），
0x06 Unix 属主，0x07 服务数据（仅 SERVICE）。本库仅解析 0x01~0x03，
其余按 SIZE 跳过；未知 TYPE 不可报错。

## 校验

- 明文卷每个头有 HEAD_CRC32，错则该卷报 `ErrChecksum` 损坏；头加密（CRYPT 后）卷的读头失败
  不报 `ErrChecksum`：无口令报 `ErrEncrypted`，有口令时预检命中报 `ErrWrongPassword`，
  无预检位时错密码解密失败（含 HEAD_CRC 错）报 `ErrEncrypted`。
- 每个文件数据有 CRC32；可选 BLAKE2s-256（extra/标志指示），解密后校验，
  错密码同样表现为校验失败，需映射为 ErrWrongPassword。
- 字典大小由 FILE 压缩信息位域（11~15 位，128KB×2^N；v1 扩展至 64G）给出；
  本实现上限 1GB，超限报 ErrUnsupported（窗口复用/流式仍适用）。

## 解压相关注意

- 单一主压缩算法：Huffman 表 + LZ 窗口拷贝，store 只是 method 0。
- solid 与跨卷语义同 RAR4：按序、拼接。
- 头加密时从 ENCRYPTION 块之后全加密流，需先派生密钥再解析。

参考：官方 RAR 5.0 格式说明 https://www.rarlab.com/technote.htm。
