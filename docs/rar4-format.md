# RAR4 数据结构

签名 7 字节：`52 61 72 21 1A 07 00`。

## 通用块头前缀

HEAD_CRC u16le（不含自身的 HEAD 校验），HEAD_TYPE u8，HEAD_FLAGS u16le，
HEAD_SIZE u16le（含 CRC 的 HEAD 总长），LONG_BLOCK 置位时再跟 ADD_SIZE u32le。

HEAD_FLAGS 通用位：0x8000 LONG_BLOCK（块后跟 ADD_SIZE 字节数据），
0x4000 有附加区，其余为各块私有位。

## 块类型

0x72 MARK，0x73 MAIN（卷/solid/注释/恢复记录/头加密标记），0x74 FILE，
0x75 CMT，0x76 AV，0x77 SUB，0x78 RR（嵌入式恢复记录，XOR，512B 扇区），
0x79 SIGN，0x7A NEW_SUB，0x7B ENDARC（下卷/末卷标记）。

## MAIN_HEAD 要点

标志：0x0001 分卷，0x0002 注释，0x0004 锁定，0x0008 solid，
0x0010 新命名（partN），0x0020 鉴权，0x0040 恢复记录存在，
0x0080 头加密（后续块需先解密才可见），0x0100 首卷。

## FILE_HEAD 字段（按序）

PACK_SIZE u32le（等于 ADD_SIZE；跨卷时为本卷残留部分），UNP_SIZE u32le，
HOST_OS u8，FILE_CRC u32le（IEEE CRC32），FTIME u32le（DOS 时间，有扩展时间则覆盖），
UNP_VER u8（15/20/29，对应 1.5/2.0/2.9+ 解包算法），METHOD u8
（0x30 store，0x31 fastest，0x32 fast，0x33 normal，0x34 good，0x35 best），
NAME_SIZE u16le，ATTR u32le，大文件时有 HIGH_PACK/HIGH_UNP，加密时有 SALT 8B，
再有扩展时间，最后 NAME（flag 高位为 1 时 UTF-16LE，否则 ANSI）。

文件私有标志：0x01 接上卷（split-before），0x02 续到下卷（split-after），
0x04 加密，0x08 注释，0x10 solid（必须按序解，依赖之前字典状态）。
目录：METHOD 0x30 且 UNP_SIZE 0，加 DOS 目录属性位。

## 解压相关注意

- solid 文件必须从 solid 链起点按序解，不可随机跳。
- 跨卷文件 PACK 流分布在多卷，需拼接后再送解包器。
- 头加密时文件名/大小不可见，错密码表现为校验失败。
