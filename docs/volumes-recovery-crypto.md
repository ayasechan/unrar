# 分卷、恢复、加密

## 1. 分卷命名与拼接

- 旧式（RAR4）：首卷 `.rar`，后续 `.r00 .r01 ...`（编号十进制递增）。
- 新式（RAR4/RAR5）：`name.part01.rar name.part02.rar ...`（零填充宽度按实际位数）。
- 枚举规则：给定首卷名，按同目录同前缀扫描两种序列；`VolumeSet` 接口抽象该过程，
  默认实现走本地文件，测试/对象存储可注入内存实现。
- 文件分段表：每个 FILE 头的 PACK 流记录 (卷序号, 卷内偏移, 长度)；
  split-before/after 标志决定是否向前后卷延续；ENDARC 链校验卷序号连续。
- 注释跨卷走独立的 `cmtPending` 装配（与文件分段同机制；暂无跨卷注释夹具）。
- 缺卷：ErrMissingVolume；卷 CRC 错：先尝试恢复（见下），无恢复数据则 ErrChecksum。

## 2. 恢复：嵌入式 rr 与 .rev 卷

- RAR4/RAR5 嵌入式恢复记录：格式上存在（RAR4 基于 XOR，RAR5 为 Reed-Solomon 纠错码），
  但本库不支持其修复，扫描阶段直接跳过；缺卷/损坏恢复一律走 `.rev` 恢复卷（见下）。
- `.rev` 恢复卷：独立文件，`rar rc` 语义是“用 rev 重建缺失/损坏的卷”；
  本库 `WithRecovery` 开启时：缺一卷且有足够 rev 即重建该卷（内存或落盘由调用方选），
  再走正常解压；rev 不足则报 ErrNeedRecovery（带需要哪个卷）。
- 实现位置：`internal/rs8`（GF(256)，RAR4 恢复卷）与 `internal/rs16`（GF(2^16) Cauchy 矩阵，RAR5 恢复卷）负责纠删编解码，`recover.go` 负责卷发现、校验与重建编排。

## 3. 加密

- RAR4：文件数据 AES-128-CBC；salt 8B 存于文件头；`-hp` 头加密时块头整体加密，
  未解密前看不到文件名。密钥派生用口令 + salt 的哈希链。
- RAR5：PBKDF2-HMAC-SHA256（轮数存于 ENCRYPTION 块）派生，再 AES-256-CBC；
  头加密同样覆盖后续全部头部；校验码（CRC32/BLAKE2s）同时作为密码正确性判据。
- API：WithPassword / WithPasswordReader（按文件回调，支持重试/多密码）；
  内存中的口令字节用完即清零；日志与错误信息永不回显口令；
  密码错误统一 ErrWrongPassword，不泄露是“无此文件”还是“密码错”（头加密时）。
- 性能：PBKDF2 轮数可能很大，派生结果按（算法，口令，salt，轮数）缓存，避免每文件重复计算。
- 注释经同一 `cryptStream`：`-p` 归档的 CMT 通常明文故可见（自身置加密位时按解码失败留空）；
  `-hp` 无口令时整卷打不开（`ErrEncrypted`），有口令才解出注释。

## 4. 安全与限额

- 路径穿越拒绝（`SafeName`）、链接不跟随；解压输出由调用方限流（库本身不设总输出上限）。
- 字典与窗口内存设上限，超限返回 `ErrUnsupported`，不做无界分配；注释解出上限 16MB（0x1000000 字节），失败留空。
