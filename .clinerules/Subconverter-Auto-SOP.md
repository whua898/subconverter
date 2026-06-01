# 🚀 Subconverter 远程闭环运维终极指令 (SOP) V2.1

## ⚠️ 核心禁令 (CRITICAL CONSTRAINTS)
- **严禁编写文档**：禁止创建任何 .md 说明文档或配置指南，把时间花在执行上。
- **禁止本地运行**：后端服务仅在远程 VPS！严禁寻找 localhost 或本地 subconverter 进程。
- **跳过授权检查**：默认系统已完成 SSH 和 Git 授权。若命令遇阻直接报错，严禁教用户配置。
- **禁止盲目报喜**：执行部署命令后，必须通过命令输出确认无 `Error` 或 `Conflict`，否则视为任务失败。
- **自适应修复优先级**：配置(pref.ini) > 规则(base/) > 脚本(*.py/*.ps1) > 源码(src/)。

---

## 🏗️ 系统架构声明 (System Architecture)
- **本地环境**：代码/配置修改、Git 推送。
- **远程 VPS**：IP `35.212.140.13`，用户 `root`。运行 Docker 版 subconverter。
- **构建中心**：GitHub Actions (仓库 `whua898/subconverter`)。
- **验证地址**：`http://35.212.140.13:25500/sub?target=v2ray&url=...`

---

## 🔄 全自动闭环流程 (Workflow)

### 第1阶段：深度诊断 (Remote Diagnose)
1. **API 测试**：请求远程接口，获取返回内容。
2. **日志抓取**：必须执行 `ssh root@35.212.140.13 "docker logs --tail 50 subconverter"`。
3. **定位原因**：分析日志。若是 `Invalid subscription` 或 `0 nodes`，优先检查正则过滤和配置文件。

### 第2阶段：代码与配置修正 (Adaptive Fix)
- **动作**：AI 根据诊断结果，自主决定修改哪个文件。
- **要求**：若修改了 C++ 源码，必须确保变量作用域正确且符合项目既有函数规范。

### 第3阶段：推送与监控 (CI Monitoring)
- **动作**：`git add .` -> `git commit` -> `git push`。
- **轮询**：每 30 秒检查一次 GitHub Actions 状态，成功后方可执行部署。

### 第4阶段：强力部署 (Strong CD)
- **防冲突逻辑**：为了避免容器名冲突，部署命令必须包含强制删除动作。
- **命令模版**：
  `ssh root@35.212.140.13 "docker rm -f subconverter && cd /root/dockers/subconverter && docker compose up -d"`
- **状态二次确认**：部署后必须执行 `ssh root@35.212.140.13 "docker ps"`，确认容器状态为 `Up` 且镜像 ID 已更新。

### 第5阶段：终极验证 (Final Verification)
- **动作**：重新请求远程 API。
- **成功标准**：响应为合法 Base64 编码，且节点数量统计 > 0。

---

## 📊 终端实时输出要求 (Terminal Output)
Cline 必须在终端实时输出以下标识的状态：
1. `[DIAGNOSE]` 远程 API 响应及 Docker 日志关键报错。
2. `[DECISION]` 修复计划（说明为什么要改这个文件）。
3. `[CI/WAIT]` GitHub Actions 的实时进度。
4. `[DEPLOY]` 输出 `docker ps` 的结果，证明新容器已跑起来。
5. `[RESULT]` 最终转换节点统计，确认是否解决问题。