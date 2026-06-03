# 🚀 Subconverter 全自动修改·验证通用流水线（V6.0）

## 🔥 部署前的第一条规则（CLINE 常见犯错点）
**当前运行环境是 cmd.exe，不是 PowerShell。**
cmd 和 PowerShell 语法不一样，混用会报错。记住三点：
1. `gh` 直接打名字，不要加 `&` 和引号
2. 别用 `head`/`tail`/`grep`/`sed`——Windows 没有
3. 不确定的命令用 `python -c "..."` 代替

---

## 🎯 核心目标
1. **全格式目标激活**：所有 18 种 target 均可正常输出
2. **IPv6 强制加括号**：`@[::1]:Port` 格式，各格式统一
3. **消除 400 / 0 字节**：路径解析修复，容器内外一致

## ⚠️ CLINE 避坑金律（严厉警告）

### 禁令 1：禁止用 PowerShell 语法调用 `gh`
```
# ✅ 正确（cmd 语法）
gh run list --limit 1
gh run view <ID> --log

# ❌ 错误（PowerShell 语法，cmd 不认识）
& 'D:\Program Files\GitHub CLI\gh.exe' run list
```
**依据**：`where gh` 确认过在 PATH 中，cmd 下直接用名字调用就行。

### 禁令 2：禁止 Unix 管道命令（Windows 没有）
```
# ✅ 正确
python -c "..."         # 用 Python 处理
command 2>&1            # 直接看输出

# ❌ 错误（Windows 不存在这些命令）
command 2>&1 | tail -30
command 2>&1 | head -c 200
command | grep xxx
command | sed 's/a/b/g'
command | awk '{print $1}'
```
**依据**：Windows 无 `head`/`tail`/`grep`/`sed`/`awk`。需要用 Python 代替。

### 禁令 3：禁止"抢跑"部署
Git Push 后**必须**轮询至 `success` 再动 VPS。CI failure 时部署旧镜像等于没改。

**轮询命令**：
```
gh run list --limit 1
# 看到 "completed success" 才能继续
# 看到 "failure" 先 gh run view <ID> --log 查原因
```

### 禁令 4：禁止盲目猜路径
每次 VPS 部署前必查：
```
ssh root@IP "docker inspect subconverter --format '{{.Config.WorkingDir}}'"
ssh root@IP "docker inspect subconverter --format '{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}'"
```

### 禁令 5：禁止跳过语法检查
任何 .cpp 修改必须做两步检查：
1. 括号匹配：`python -c "c=open('文件').read(); print(c.count('{')==c.count('}'))"`
2. 结构完整性：提取修改区域的 `{` `}` 是否成对

### 禁令 6：禁止写临时文档
本 SOP 是唯一文档。禁止生成 `*.md` 辅助文件。

---

## 🏗️ 环境常量

| 项目 | 值 |
|------|-----|
| VPS | `35.212.140.13` |
| 端口 | `15051` |
| 镜像源 | `ghcr.io/whua898/subconverter:latest` |
| Compose 路径 | `/root/dockers/subconverter/` |
| 容器内 base | `/base` |
| 核心文件 | `src/handler/interfaces.cpp` |
| | `src/generator/config/subexport.cpp` |
| | `src/utils/file.cpp` |

---

## 🔄 全自动 6 阶段流水线

### 第 1 阶段：代码修改 & 预检
```
[修改] → [括号匹配检查] → [结构完整性检查] → [通过则继续]
```

**预检命令模板**（Python，兼容 Windows）：
```python
# 1. 括号匹配
c = open('src/handler/interfaces.cpp', 'rb').read().decode('utf-8')
print(f'{{}}: {c.count("{{")} == {c.count("}}")} 匹配={c.count("{{")==c.count("}}")}')

# 2. 修改区域结构检查（按需定制）
# 例如 UAMatchList：数 { 和 } 条目是否一致
```

### 第 2 阶段：Git 推送
```
git add <文件>
git commit -m "说明"
git push origin master
```

### 第 3 阶段：CI 状态轮询（阻塞）
```
# 首次查询
gh run list --limit 1
# → in_progress, 等待

# 循环轮询（每 60-120 秒一次）
python -c "import time; time.sleep(120)"
gh run list --limit 1

# 直到看到 "completed success" 或 "completed failure"
# failure → gh run view <ID> --log 诊断
```

### 第 4 阶段：VPS 部署
```
# 1. 拉取新镜像并重启
ssh root@35.212.140.13 \
  "cd /root/dockers/subconverter && \
   docker compose pull && \
   docker compose up -d"

# 2. 确认新容器上线
ssh root@35.212.140.13 \
  "docker ps --filter name=subconverter --format '{{.ID}} {{.Image}} {{.CreatedAt}}'"

# 3. 确认版本
ssh root@35.212.140.13 "curl -s http://localhost:15051/version"
```

### 第 5 阶段：逐项验收
每次修改不同，按功能点测试。通用模板（VPS 内部执行避免网络干扰）：
```
# 测试各个 target=auto 的 UA 匹配
ssh root@IP "curl -s -H 'User-Agent: Stash/2.0' 'http://localhost:15051/sub?target=auto&url=SS_LINK'"
ssh root@IP "curl -s -H 'User-Agent: SFA/1.0.0' 'http://localhost:15051/sub?target=auto&url=SS_LINK'"

# 兜底测试（未知 UA → 200，不再是 400）
ssh root@IP "curl -s -H 'User-Agent: Random/1.0' 'http://localhost:15051/sub?target=auto&url=SS_LINK'"
```

### 第 6 阶段：回滚方案
如果验收失败：
```
# 回退 git 版本
git revert HEAD --no-edit
git push origin master

# 等 CI success 后 VPS 重新 pull
ssh root@IP "cd /root/dockers/subconverter && docker compose pull && docker compose up -d"
```

---

## 📋 速查卡（常见操作）

| 操作 | 命令 |
|------|------|
| 查最新 CI 状态 | `gh run list --limit 1` |
| 查 CI 日志 | `gh run view <ID> --log` |
| 容器版本 | `ssh root@IP "curl -s http://localhost:15051/version"` |
| 容器状态 | `ssh root@IP "docker ps --filter name=subconverter"` |
| 反查工作目录 | `ssh root@IP "docker inspect subconverter --format '{{.Config.WorkingDir}}'"` |
| 反查 compose 目录 | `ssh root@IP "docker inspect subconverter --format '{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}'"` |
| 语法预检 | `python -c "c=open('文件','rb').read(); print(c.count(b'{')==c.count(b'}'))"` |