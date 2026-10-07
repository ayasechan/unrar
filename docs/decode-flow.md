# 统一解压流水线

```
卷枚举 -> 头解析 -> 跨卷拼接 -> 解密 -> 解压 -> 过滤器 -> 校验 -> 输出
```

## 1. 卷枚举

首卷路径推导全卷名（见 volumes-recovery-crypto.md），缺卷即报
ErrMissingVolume（带缺失卷名），不做猜测性跳过。

## 2. 头解析

- 先判签名定版本：7 字节尾 0x00 为 RAR4，8 字节尾 01 00 为 RAR5。
- RAR4 按固定块头循环；RAR5 按 vint 自描述头循环，未知块按 SIZE 跳过。
- 头加密时：先读 ENCRYPTION 参数、派生密钥、解密后再解析（错密码在校验处暴露）。
- 建文件表：name、unpacked 大小、mtime、属性、是否目录/solid/跨卷/加密、
  数据在各卷的 (卷号, 偏移, 长度) 分段表。
- CMT 注释块（RAR4 NEW_SUB / RAR5 SERVICE，名 `CMT`）截留为内部描述，不进文件表
  （首个胜出）；`checkVolumes` 通过后 `finishComment` 解出，任何失败留空。

## 3. 跨卷拼接

文件 PACK 流按分段表跨卷顺序读，对解包器呈现连续字节流。
solid 文件必须从 solid 链起点按序解，随机 Open 需内部顺序推进（或报错提示按序）。

## 4. 解密

- RAR4：AES-128-CBC，salt 在文件头，口令派生后按块解密。
- RAR5：PBKDF2-HMAC-SHA256 派生 + AES-256-CBC。
- 口令来源：WithPassword 固定值或 WithPasswordReader 回调；失败清零口令内存。

## 5. 解压

- store：直接拷贝。
- RAR4：unpack29 解包器（LZSS + Huffman）；1.5/2.0 时代算法不支持，遇到返回 `ErrUnsupported`。
  method 决定压缩强度（解包侧主要是表规模差异）。
- RAR5：Huffman 解码 literal/match 长度 + LZ 窗口拷贝，字典上限 1GB，
  窗口内存复用，超限报 ErrUnsupported 而非 OOM。
- PPM：文本压缩分支，大表，同样限内存。
- 注释走同管线单次解出：stored，或 RAR4-unpack29（unpVer==29）/ RAR5-主算法（unpVer==0），
  全新解包状态（不复用固实链），CRC/BLAKE2 照常校验，上限 16MB（0x1000000 字节），
  任何失败留空、不向 `OpenReader` 抛错。

## 6. 过滤器

RAR4 仅执行 6 种标准过滤器（E8/E8E9/Itanium/Delta/RGB/Audio），以字节码长度与 CRC32
识别类型后走原生实现；RAR5 走原生 Delta/E8/E8E9/ARM 实现。内存占用固定，不做系统调用。

## 7. 校验与输出

- RAR4：CRC32；RAR5：CRC32 + 可选 BLAKE2sp（含 HMAC 变体，见 architecture.md 错误设计）。
- 校验错按 architecture.md 的映射原则报告为 ErrWrongPassword 或 ErrChecksum。
- 输出为流式；每个 File.Open 使用独立 decoder，并发安全；大文件不一次性进内存。
- 落盘相关的路径清理与链接策略见根 README，属调用方职责。

## 实现要点

- RAR4 头 CRC16 = 头部余下字节标准 CRC32 的低 16 位。
- RAR5 小文件的 mtime 可能在 HTIME extra（Unix ns），须走查 extra。
- v29 pack 流每文件独立分段；固实连续的是窗口/表/OldDist 状态，
  位流每文件重起。固实链 Open 从链首顺序解，前置输出丢弃（仍验 CRC）；
  单次代价与链首至目标的字节数成正比，逐个打开 N 个文件为二次方量级；
  不缓存解码结果（流式输出无界），调用方按归档顺序读即与总量成正比。
- `rar a` 默认建固实归档，非固实夹具须显式 `-s-`。
- v29 过滤器全是 6 种标准过滤器，以字节码（长度，CRC32）识别类型；
  Delta/RGB/Audio 的 SrcData 跨通道单调推进（非按通道分步）；
  VM 码尾字节按零垫读出，边界检查须与参考行为一致放宽。
- PPM：堆内统一用偏移链接，0 表空；单状态 OneState 在 union 起点 +2，
  不在 Stats 槽位 +4；SEE2D 按 [行][列] 分开寻址；
  GET_SHORT16 为无符号动作（逻辑右移）；UpdateModel 主分支不写回局部 successor；
  glue 哨兵禁入堆（空链接存 0，-1 只活在 Go 变量）。
- RAR5 压缩块自描述（BlockFlags/BlockSize/BlockBitSize/校验和），
  表与块头按位流位置推进（ReadBorder 联动）；过滤器仅 D/E 两系（Delta/E8/E8E9/ARM），
  E8 的 Offset 按 16M 取模（与 RAR3 不同）；AUDIO/RGB/ITANIUM 在 RAR5 无实现
  （未知类型数据按计数丢弃，与参考一致）。
- 加密：RAR4 口令→UTF-16LE 裸字节（非 BMP 截断低 16 位）+ salt，
  SHA-1-rar29 变体（写回仅长口令触发，短口令等价标准 SHA-1，已与对照实现差分验证），
  0x40000 轮，AES-128-CBC；MAIN 恒明文（口令位 0x80），其后每头独立 salt+cipher；
  RAR5 口令→UTF-8，PBKDF2-HMAC-SHA256（Key/V1/V2 三段连续，源码内三组向量验证），
  AES-256-CBC，头加密每头独立 IV；校验走 MAC（对算出值做 HMAC 再比，不是反过来）；
  同 salt 多文件共享 KDF 但 IV 绝不进缓存；错口令有预检报 ErrWrongPassword，
  无预检靠校验失败映射。
- 分卷：每卷签名后起读；ENDARC 下卷位逐卷记录，
  末卷置位则报缺卷（含期望卷名）；首卷校验（RAR4 FirstVolume/RAR5 VolNumber）；
  续头 CRC 取末（中续为本卷 pack 段 CRC）；RAR5-7.12 多卷省略 HASHMAC 置位但仍存
  MAC 值，校验 plain/MAC 双轨（皆不可伪造）；CBC 跨卷连续。
- 夹具生成规范见 development.md。
