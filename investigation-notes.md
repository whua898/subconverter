# subconverter 项目调研笔记（骨架）

> 目的：快速记录对仓库的深入研究结果，包含总体概览、模块地图、构建/运行说明、配置点、风险与后续建议，作为后续问题排查和开发的基础文档。

## 调研摘要（1 段话）

（在此填入一句话描述项目目的与主要功能）

## 本次调研进度

- [x] 读取顶层文档：`README.md`, `README-cn.md`, `README-docker.md`
- [x] 阅读构建脚本：`CMakeLists.txt`, `cmake/` 下自定义模块
- [x] 查看程序入口：`src/main.cpp`, `src/version.h`
- [x] 列出关键目录：`src/`, `scripts/`, `base/`, `config/`, `include/`
- [ ] 深入审查 `src/` 各子模块实现（尚需完成）
- [ ] 在本机构建并运行（需要确认环境并允许安装依赖）

## 项目总体概览

- 项目名称：subconverter
- 主要用途：在不同代理订阅/配置格式间做转换（Clash/Surge/Quantumult/SS/SSR/V2Ray 等），并提供 HTTP API 服务。
- 主要运行方式：构建为可执行二进制，启动后监听 HTTP（默认 25500），提供 `/sub`、`/getprofile`、`/render`、`/refreshrules` 等接口。

## 关键组件（模块地图）

请在此填写各文件/目录的简短职责（示例）：

- `CMakeLists.txt`：构建入口，声明依赖（libcurl、RapidJSON、toml11、yaml-cpp、PCRE2、QuickJS、LibCron 等）。
- `src/main.cpp`：程序入口，解析命令行、读取 pref 配置、注册 HTTP 路由、启动服务器。
- `src/handler/`：HTTP 处理器、上传、请求解析与主业务流程入口。
- `src/generator/`：配置生成器与模板渲染逻辑。
- `src/parser/`：订阅与节点解析。
- `src/script/`：定时任务、JS 运行（QuickJS）桥接（脚本过滤、排序等）。
- `src/server/`：内置 HTTP server（这里使用 httplib 实现）。
- `base/`：模板、默认规则、示例配置与 profiles。
- `config/`：大量预置配置样例（INI/TOML/YML）。
- `include/`：第三方头文件（inja、jpcre2、quickjspp、httplib 等）。

## 构建（PowerShell 示例）

说明：Windows 下需要安装 CMake、Visual Studio (MSVC) 或其他兼容编译工具；或使用 WSL/Docker。

1) 在仓库根执行：

```powershell
mkdir build; cd build; cmake .. -DCMAKE_BUILD_TYPE=Release; cmake --build . --config Release
```

预期：生成 `subconverter` 可执行文件。
风险：若缺少第三方依赖（yaml-cpp、PCRE2、QuickJS 等）会导致 CMake 报错或链接失败。可通过包管理或编译第三方库解决，或使用 Docker 镜像。

2) 运行（示例）：

```powershell
# 假设可执行位于 build\Release\subconverter.exe
.\build\Release\subconverter.exe --help
# 或启动服务
.\build\Release\subconverter.exe
curl http://127.0.0.1:25500/version
```

3) Docker 运行（参考 `README-docker.md`）：

```powershell
docker run -d --restart=always -p 25500:25500 asdlokj1qpi23/subconverter:latest
curl http://localhost:25500/version
```

## 主要配置点（示例）

- `pref.toml` / `pref.yml` / `pref.ini`（全局偏好，程序启动读取）
- `base/` 下模板与规则（`all_base.tpl`, `clash_provider_test.yml` 等）
- `config/` 下的多套 INI/TOML/YML 示例（profiles、rules、snippets）
- `generate.ini`, `gistconf.ini`（自动上传 Gist 的 token 配置）
- HTTP API 参数（`/sub?target=&url=&config=` 等）中的 `token`, `upload`, `emoji`, `sort_script`, `filter_script`（JS）等

## 常见故障 & 风险点

1. CMake 未找到依赖（yaml-cpp、PCRE2、QuickJS、libcurl 等）。
2. 运行时缺少动态库（DLL）或运行目录不正确导致模板/配置文件找不到。`main.cpp` 有一段 `setcd` 逻辑，会切换到 `pref` 所在目录。注意运行时工作目录。
3. 脚本（`update_rules.py`）或在线拉取规则需要网络、可能需要 Python 依赖与 API token。
4. 使用 JS 脚本（`filter_script` / `sort_script`）会通过 QuickJS 执行，JS 错误会影响输出。注意安全问题（远程脚本）。
5. 正则表达式与 PCRE2 相关逻辑（`regexp.cpp`）可能导致性能或兼容问题。

## 自动化检查（已执行/可复现命令）

建议在本地按此顺序检查：

- 列出顶层文件：`Get-ChildItem -File -Path .\ | Select-Object Name`
- 搜索入口：`git grep -n "int main"` 或 `Select-String -Path .\src\**\*.cpp -Pattern "int main"`
- 查找 CMake 依赖：`Select-String -Path .\CMakeLists.txt -Pattern "find_package" -List`
- 列出 `base/` 和 `config/` 内容：`Get-ChildItem -Path .\base -Recurse -File`

## 开放问题（需要进一步验证或询问作者）

- 是否有 CI/CD 流水线具体的构建依赖配置（例如在 Actions 中使用的包源）？
- 在生产部署中是否推荐静态构建或使用发布的 Docker 镜像？
- 运行时是否必须提供 `pref.*`（即是否支持无配置以默认行为运行）？

## 后续建议（优先级）

1. (高) 本地完整构建一次并贴出 CMake / 链接错误日志以定位依赖缺失。
2. (中) 逐步走读 `src/generator`, `src/handler`, `src/parser`，记录每个模块的 API 与职责，并补充到本文件。
3. (中) 在受控网络环境运行 `update_rules.py` 与服务端，检查 runtime 行为与默认配置。
4. (低) 将常用命令加入 `scripts/` 或 `Makefile` 以简化贡献者上手成本。

---

© 调研输出  — 可在此基础上继续填充更详细的代码片段、调用链和示例。
