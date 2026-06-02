# 🚀 Subconverter 全格式兼容自动化运维 SOP (V5.0)

## 🎯 核心目标 (全格式激活 & 路径解析修复)
1. **稳固 IPv6 成果**：确保 `subexport.cpp` 修复逻辑永久生效，所有格式中的 IPv6 必须带 `[...]`。
2. **解决 0 字节故障**：修复次级格式 (Surge, Mellow, Loon 等) 输出为 0 字节的问题，重点解决容器内 `fetchFile` 对 `base/` 路径的解析故障。
3. **消除 HTTP 400**：修复 Sing-box/Mihomo 等现代格式的生成失败问题，确保 `isInScope` 安全检查不再误杀合法路径。

## ⚠️ 核心禁令 (CLINE 避坑金律)
1. **Windows 语法约束 (PowerShell)**：本地严禁 `head/tail/grep`，必须用 `| Select-Object -First 20`。调用 `gh` 必须使用绝对路径：`& 'D:\Program Files\GitHub CLI\gh.exe'`。
2. **基础设施锁定**：严禁修改 `Docker-compose.yml`。固定端口 `15051`、镜像源 `ghcr.io`。
3. **禁止盲目猜路径**：必须执行 `docker inspect subconverter` 反查容器在 VPS 上的真实工作目录。
4. **禁止“抢跑”部署**：Git Push 后必须轮询 Actions 直至 `success`。**禁止**在未通过 CI 时动 VPS。
5. **拒绝虚假成功**：必须审计全格式输出。若次级格式仍为 0 字节或 400，视为任务未完成。
6. **禁止写文档**：禁止产生任何辅助说明性 .md 文件，直接执行。

---

## 🏗️ 环境声明
- **后端服务**：VPS `35.212.140.13` (映射 15051)。
- **核心源码点**：`src/generator/config/subexport.cpp` (节点逻辑), `src/utils/file.cpp` (路径解析), `src/handler/interfaces.cpp` (接口逻辑)。

---

## 🔄 全自动闭环流程 (Workflow)

### 第1阶段：全格式审计诊断 (Full Audit Diagnose)
1. **全目标测试**：循环请求 target=v2ray, clash, singbox, surge, mellow 等 16 种格式。
2. **路径安全审计**：执行 `ssh` 检查容器内文件权限及 `Base/` 目录挂载状态。
3. **源码排查**：重点检查 `file.cpp` 中的 `isInScope` 函数，定位为什么容器 CWD 与绝对路径匹配失效。

### 第2阶段：自适应修复与预检 (Fix & Pre-check)
- **动作**：修正路径解析逻辑。确保 `fetchFile` 能在容器化环境下正确读取本地 `base/*.conf` 模板。
- **预检**：修改后必须在本地执行终端命令检查语法，严禁带语法错误推送。

### 第3阶段：推送与【状态轮询】 (CI Monitoring)
- **动作**：执行 `git push`。
- **轮询 (Blocking)**：每 60 秒执行 `& 'D:\Program Files\GitHub CLI\gh.exe' run list --limit 1` 直至 `success`。

### 第4阶段：精准强力部署 (Strong CD)
- **动作**：进入反查路径，执行 `ssh ... "docker rm -f subconverter && docker compose up -d"`。
- **确认**：执行 `docker ps` 确认新镜像 ID 已上线且端口正常。

### 第5阶段：全业务最终验收 (Final QA)
- **硬性指标**：
    1. **节点数对齐**：主流格式 (V2Ray/Clash) 节点总数必须 = **24**。
    2. **IPv6 校验**：所有输出链接必须匹配 `@[IPv6_Address]:Port`。
    3. **格式激活**：Surge/Mellow/Sing-box 不再返回 0 字节或 400 错误。
- **结果判定**：全格式正常输出则结束；否则回滚并重入第 1 阶段。

---

## 📊 终端实时输出要求
1. `[AUDIT]` 列出所有 target 的输出字节数统计表。
2. `[DIAGNOSE]` 解释为何 `isInScope` 或路径解析在容器内失效。
3. `[CI/WAIT]` 展示编译等待状态。
4. `[RESULT]` 最终验证：输出“全格式 16 种 Target 激活，24 节点全量转换成功”。