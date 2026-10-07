# RAR5 数据结构

签名 8 字节：52 61 72 21 1A 07 01 00。

## 自描述头（除 CRC 外全为 vint，小端 7bit 续位）

HEAD_CRC u32le（本字段之后所有头字节的 CRC32），HEAD_SIZE vint（不含 CRC 的头总长），
TYPE vint，FLAGS vint，EXTRA_SIZE vint（有 extra 标志时），DATA_SIZE vint（有 data 标志时）。
之后是各类型私有字段，然后 extra 区，最后是数据区（DATA_SIZE 字节）。

HEAD 通用 FLAGS：0x01 有 extra，0x02 有 data，0x04 未知块也需保留。

## 块类型

1 MAIN：归档属性（卷号、solid、字典、恢复记录、头加密标记）。
2 FILE：文件/目录头。通用 FLAGS 见上；私有 FLAGS：0x01 目录，0x02 有 MTIME，
0x04 有 DATA_CRC32，0x08 解压大小未知。
字段按序：FLAGS vint，UNP_SIZE vint，ATTR vint，MTIME（fhflUtime 置位时），
DATA_CRC32（fhflCRC32 置位时），压缩算法 vint（0 store，其余为 RAR5 主算法变体），
HOST_OS vint，NAME_LEN vint + NAME（UTF-8）。
3 SERVICE：注释、恢复记录等服务数据。名为 `CMT` 的是归档注释：体字段与 FILE 同布局，
数据为 UTF-8（创建时含尾零，读取时截首个 NUL），按文件流同管线单次解出
（stored，或主算法且 unpVer==0；带 DATA_CRC32 则校验 CRC32，有 BLAKE2s 时并校验），
上限 16MB（0x1000000 字节），任何解码失败均留空；非 CMT 服务块解析后丢弃，
不进文件表（`.rev` 恢复与 SERVICE 无关，见 volumes-recovery-crypto.md）。
4 ENCRYPTION：加密参数（版本、PBKDF2 轮数、salt），头加密时整个后续头被加密。
5 ENDARC：卷尾（下卷标记、卷号链）。

## Extra 记录

每条为 SIZE vint + TYPE vint + 数据。常见：时间戳细化、UNIX owner/group、
重定向/链接目标。未知 TYPE 必须按 SIZE 跳过，不可报错。

## 校验

- 每个头有 HEAD_CRC32，错则该卷损坏。
- 每个文件数据有 CRC32；可选 BLAKE2s-256（extra/标志指示），解密后校验，
  错密码同样表现为校验失败，需映射为 ErrWrongPassword。
- 字典大小由 MAIN extra 给出（RAR5 协议 128K~4G，7.0 扩展至 64G）；
  本实现上限 1GB，超限报 ErrUnsupported（窗口复用/流式仍适用）。

## 解压相关注意

- 单一主压缩算法：Huffman 表 + LZ 窗口拷贝，store 只是 method 0。
- solid 与跨卷语义同 RAR4：按序、拼接。
- 头加密时从 ENCRYPTION 块之后全加密流，需先派生密钥再解析。
