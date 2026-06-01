@echo off
chcp 65001 >nul
echo ==========================================
echo Subconverter Auto Cycle 环境配置
echo ==========================================
echo.

set /p pat_input="请输入 GitHub PAT (留空跳过 CI 监控): "
if not "%pat_input%"=="" (
    setx GITHUB_PAT "%pat_input%"
    echo [✓] GitHub PAT 已设置到系统环境变量
echo.
echo 请重新打开终端以使环境变量生效
echo 或手动执行: set GITHUB_PAT=%pat_input%
)

echo.
echo 配置完成！
echo.
pause