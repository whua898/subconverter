# 🚀 Subconverter 业务闭环自动化运维 SOP (V3.7 动态格式版)

## 🎯 核心目标
解决订阅源转换异常问题。当前重点修复 JSON 源 `https://whua-bp.8dy.xx.kg/sub/normal/wh898?app=xray#%F0%9F%92%A6%20BPB%20Normal` 无法正确转换为 **用户指定格式**（如 V2Ray, Clash, Sing-Box 等）的故障。

## ⚠️ 核心禁令 (严禁踩坑)
1. **基础设施锁定**：严禁修改 `Docker-compose.yml`。锁定宿主机端口 `15051`、镜像源 `ghcr.io`，禁止改动部署架构。
2. **禁止“抢跑”部署**：Git Push 后必须轮询 GitHub Actions 直至 `success`。严禁在编译未完成时执行 SSH 部署。
3. **禁止误认环境**：后端服务不在本地！所有测试和日志抓取必须针对远程 VPS (`35.212.140.13`)。
4. **禁止虚假成功**：API 返回 200 不代表成功。必须根据 `target` 格式校验内容（如 v2ray 需 Base64 解码，clash 需 YAML 校验），节点数 = 0 则视为失败。
5. **禁止写文档**：不准创建任何说明文档，直接执行终端命令。

---

## 🏗️ 系统架构声明
- **后端服务**：VPS `35.212.140.13` (端口映射 15051:25500)。
- **构建中心**：GitHub Actions (编译耗时约 5-8 分钟)。
- **自适应格式**：支持 target=v2ray, clash, singbox, surge4 等标准 subconverter 格式。

---

## 🔄 全自动闭环流程 (Workflow)

### 第1阶段：动态功能诊断 (Deep Diagnose)
- **模拟请求**：使用 `curl` 请求远程接口。**注意：`target` 参数应根据实际测试需求动态调整（默认当前测试 v2ray）**。
  `curl -L "http://35.212.140.13:15051/sub?target=${TARGET:-v2ray}&url=https%3A%2F%2Fwhua-bp.8dy.xx.kg%2Fsub%2Fnormal%2Fwh898%3Fapp%3Dxray%23%25F0%259F%2592%25A6%2520BPB%2520Normal"`
- **日志分析**：执行 `ssh root@35.212.140.13 "docker logs --tail 50 subconverter"`。
- **排查重点**：针对特定 target 的解析报错。

### 第2阶段：自适应修复 (Adaptive Fix)
- **修复路径**：优先修改 `pref.ini` 或 `base/` 规则；最后才修改 `src/` 源码。

### 第3阶段：推送与【状态轮询】 (CI Monitoring)
- **动作**：执行 `git push`。
- **阻塞轮询 (必须执行)**：每 60 秒执行 `gh run list --limit 1`。只有 `conclusion` 为 `success` 时才允许通过。

### 第4阶段：强力更新部署 (Strong CD)
- **动作**：必须先执行 `docker rm -f subconverter` 解决冲突，再执行 `docker compose up -d`。
- **验证**：确认 `docker ps` 中容器状态为 `Up` 且端口映射正确。

### 第5阶段：格式自适应验收 (Final QA)
- **内容校验**：
    - 若 `target=v2ray`: 校验是否为 Base64 并解码。
    - 若 `target=clash`: 校验是否为合法 YAML 且包含 `proxies` 字段。
    - 若 `target=singbox`: 校验是否为合法 JSON。
- **硬性指标**：节点数量统计必须 > 0。
- **结果判定**：验证通过则任务结束；否则自动重回第 1 阶段。

---

## 📊 终端实时输出要求
1. `[TEST]` 当前测试的目标格式（Target: v2ray/clash...）。
2. `[DIAGNOSE]` 远程日志中关于该格式解析失败的具体报错。
3. `[CI/WAIT]` 动态输出 Actions 编译进度。
4. `[RESULT]` 最终验证的节点数量及格式合法性报告。