# RAR5 数据结构

签名 8 字节：52 61 72 21 1A 07 01 00。

## 自描述头（除 CRC 外全为 vint，小端 7bit 续位）

HEAD_CRC u32le（本字段之后所有头字节的 CRC32），HEAD_SIZE vint（不含 CRC 的头总长），
TYPE vint，FLAGS vint，EXTRA_SIZE vint（有 extra 标志时），DATA_SIZE vint（有 data 标志时）。
之后是各类型私有字段，然后 extra 区，最后是数据区（DATA_SIZE 字节）。

HEAD 通用 FLAGS：0x01 有 extra，0x02 有 data，0x04 未知块也需保留。

## 块类型

1 MAIN：归档属性（卷号、solid、字典、恢复记录、头加密标记）。
2 FILE：文件/目录头。私有 FLAGS：0x01 目录，0x02 有数据（否则只是目录/占位），
0x04 solid 续流依赖，0x08 跨卷续（split-before），0x10 跨卷延（split-after），
0x20 加密数据，0x40 扩展时间，0x80 UNIX 属性/owner 等。
字段按序：FLAGS vint，UNP_SIZE vint，ATTR vint，MTIME（unix 时间，有标志时），
DATA_CRC32（有数据时），压缩算法 vint（0 store，其余为 RAR5 主算法变体），
HOST_OS vint，NAME_LEN vint + NAME（UTF-8）。
3 SERVICE：注释、恢复记录等服务数据；解压跳过，但恢复流程要用。
4 ENCRYPTION：加密参数（版本、PBKDF2 轮数、salt），头加密时整个后续头被加密。
5 ENDARC：卷尾（下卷标记、卷号链）。

## Extra 记录

每条为 SIZE vint + TYPE vint + 数据。常见：时间戳细化、UNIX owner/group、
重定向/链接目标。未知 TYPE 必须按 SIZE 跳过，不可报错。

## 校验

- 每个头有 HEAD_CRC32，错则该卷损坏。
- 每个文件数据有 CRC32；可选 BLAKE2s-256（extra/标志指示），解密后校验，
  错密码同样表现为校验失败，需映射为 ErrWrongPassword。
- 字典大小由 MAIN extra 给出（64K~4G），实现必须限内存（窗口复用/流式）。

## 解压相关注意

- 单一主压缩算法：Huffman 表 + LZ 窗口拷贝，store 只是 method 0。
- solid 与跨卷语义同 RAR4：按序、拼接。
- 头加密时从 ENCRYPTION 块之后全加密流，需先派生密钥再解析。
