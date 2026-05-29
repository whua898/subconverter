# Subconverter v2rayN 订阅处理问题说明

## 问题现象

使用多个 v2rayN 格式订阅源合并时，v2ray target 返回空响应。

## 根本原因

subconverter 的订阅解析逻辑（subparser.cpp#L3298-3375）：
1. 首先尝试解析为 SSD/Clash/Surge/Singbox 配置
2. 然后 Base64 解码
3. 按行解析节点链接（vmess:// vless:// trojan:// 等）

**但 v2rayN 格式订阅本身就是 Base64 编码的节点链接集合，再次解码会得到正确格式。**

## 关键发现

之前测试中：
- `/v2rayn` 订阅源 Content-Length: 584
- 解码后前 200 字符显示：`hy...` (hysteria2:// 开头)

这说明：
1. 订阅源确实返回了 Base64 编码的内容
2. 内容解码后是 `hysteria2://` 格式
3. subconverter 应该能解析这个格式

## 真正的问题

可能有两个：

### 问题 1：订阅源只包含 Hysteria2 节点

如果订阅源的 `/v2rayn` 端点只返回 Hysteria2 节点（没有 VMess/VLESS），那么 `target=v2ray` 自然返回空，因为 v2ray target 只输出 VMess/VLESS 节点。

### 问题 2：多个订阅源合并问题

URL 中使用 `|` 分隔多个订阅源时，subconverter 需要能正确处理。

## 解决方案

### 方案 1：使用 mixed target 代替 v2ray target

如果订阅源包含多种协议，使用 `target=mixed` 可以输出所有协议类型。

### 方案 2：检查订阅源内容

需要确认订阅源 `/v2rayn` 实际返回了哪些协议类型的节点。

### 方案 3：使用原始订阅格式

尝试使用不带 `/v2rayn` 后缀的 URL（原始订阅格式），看 subconverter 是否能正确解析。

## 测试建议

1. 查看订阅源返回的完整内容（解码后）
2. 确认包含哪些协议类型（VMess/VLESS/Trojan/SS/Hysteria2 等）
3. 根据实际协议类型选择合适的 target
