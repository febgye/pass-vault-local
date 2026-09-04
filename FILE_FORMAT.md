# `.lvault` 文件格式 v2

当前写入版本为 v2。读取器继续接受 v1；v1 条目的附件集合按空集合处理，下一次保存时升级为 v2。

顶层是 UTF-8 JSON，但除最小解密参数外全部内容处于 AES-256-GCM 密文中。

```json
{
  "magic": "LIQUID_VAULT_NATIVE",
    "version": 2,  "kdf": {
    "algorithm": "argon2id",
    "salt": "base64-16-bytes",
    "memoryKiB": 65536,
    "iterations": 3,
    "parallelism": 1
  },
  "cipher": {
    "nonce": "base64-12-bytes",
    "ciphertext": "base64",
    "tag": "base64-16-bytes"
  }
}
```

## 外层 AAD

```text
LIQUID_VAULT_NATIVE|2|algorithm|salt|memoryKiB|iterations|parallelism
```

因此攻击者不能在不触发认证失败的情况下修改 KDF 参数。

## 加密容器

外层明文解开后包含 `vaultId`、修订号、时间戳和加密条目数组。条目数组包含 ID、两个 AES-GCM 密文以及附件密文数组：

- `meta`：类型、标题、账号、网址、标签、参与者、强度和时间戳。
- `secret`：密码或正文。
- `attachments`：附件文件名、类型、大小、时间和独立 AES-GCM 密文。

条目 AAD：

```text
v2|entry-guid|meta
v2|entry-guid|secret
```

外层加密隐藏条目数量；内层分条加密允许程序解锁目录时只读取元数据，不提前解密密码和正文。

## 兼容策略

- 原生文件版本与旧网页备份版本独立。
- 读取器只接受明确的版本 1 或 2，不猜测或降级；v1 缺少附件字段时按空集合处理。
- 未来升级必须通过新版本号和显式迁移器完成。
- v5 JSON 只作为旧网页版本的导入格式，不作为原生程序的日常存储格式。
