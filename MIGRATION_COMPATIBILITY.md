# 旧版迁移兼容基线

原生迁移器以以下经过安全修复和复核的 HTML 版本作为兼容基线：

```text
文件：多功能加密保险库_安全修复版_20260714.html
SHA-256：45d8a91d17e2433b205013dd38a85737a223216241ae97c1246f7ea3204e6fcf
备份格式：LIQUID_VAULT_BACKUP v5
条目格式：per-item-v4
```

迁移器实现了该版本使用的 PBKDF2-SHA-256、HKDF-SHA-256、AES-256-GCM、AAD 和 HMAC-SHA-256 规范。迁移时只读取用户主动导出的 v5 JSON，不访问或修改浏览器 IndexedDB。

Windows 实机验收必须使用该 HTML 实际导出的备份进行一次端到端迁移；自测项目同时包含独立生成的 v5 兼容样本，用于发现算法和规范化回归。
