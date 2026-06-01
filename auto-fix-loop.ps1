# 全自动循环修正和验证脚本
# 流程：发现问题 -> 修改代码 -> 推送GitHub -> 等待编译 -> Docker更新 -> 验证 -> 循环

param(
    [string]$CommitMessage = "fix: 扩展JSON格式订阅解析，支持所有协议类型",
    [string]$Branch = "master",
    [switch]$AutoLoop = $true
)

$ErrorActionPreference = "Stop"
$ProjectRoot = "D:\Users\wh898\PycharmProjects\subconverter"
$GitHubRepo = "whua898/subconverter"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  全自动循环修正和验证流程启动" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

function Log-Step {
    param([string]$Message, [string]$Color = "White")
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

function Test-GitStatus {
    Set-Location $ProjectRoot
    $status = git status --porcelain
    if ($status) {
        return $true
    }
    return $false
}

function Push-ToGitHub {
    param([string]$Message)
    
    Log-Step "正在推送代码到 GitHub..." "Yellow"
    Set-Location $ProjectRoot
    
    git add -A
    git commit -m $Message
    git push origin $Branch
    
    if ($LASTEXITCODE -eq 0) {
        Log-Step "✓ 代码已成功推送到 GitHub" "Green"
        return $true
    } else {
        Log-Step "✗ 推送失败" "Red"
        return $false
    }
}

function Wait-GitHubActions {
    Log-Step "正在等待 GitHub Actions 编译完成..." "Yellow"
    
    # 使用 GitHub API 检查 workflow 状态
    $maxWaitTime = 1800  # 30分钟
    $checkInterval = 30  # 每30秒检查一次
    $elapsed = 0
    
    while ($elapsed -lt $maxWaitTime) {
        try {
            # 获取最新的 workflow runs
            $apiUrl = "https://api.github.com/repos/$GitHubRepo/actions/workflows/build.yml/runs?per_page=1"
            $response = Invoke-RestMethod -Uri $apiUrl -Headers @{
                "Accept" = "application/vnd.github.v3+json"
            } -ErrorAction SilentlyContinue
            
            if ($response.workflow_runs -and $response.workflow_runs.Count -gt 0) {
                $latestRun = $response.workflow_runs[0]
                $status = $latestRun.status
                $conclusion = $latestRun.conclusion
                
                Log-Step "编译状态: $status ($conclusion)" "Gray"
                
                if ($status -eq "completed") {
                    if ($conclusion -eq "success") {
                        Log-Step "✓ GitHub Actions 编译成功！" "Green"
                        return $true
                    } else {
                        Log-Step "✗ GitHub Actions 编译失败: $conclusion" "Red"
                        return $false
                    }
                }
            }
        } catch {
            Log-Step "检查编译状态时出错: $_" "Yellow"
        }
        
        Start-Sleep -Seconds $checkInterval
        $elapsed += $checkInterval
    }
    
    Log-Step " 等待超时" "Red"
    return $false
}

function Update-DockerContainer {
    param(
        [string]$ContainerName = "subconverter",
        [string]$ImageName = "ghcr.io/whua898/subconverter:latest"
    )
    
    Log-Step "正在更新 Docker 容器..." "Yellow"
    
    try {
        # 拉取最新镜像
        Write-Host "docker pull $ImageName"
        docker pull $ImageName
        
        # 停止并删除旧容器
        Write-Host "docker stop $ContainerName"
        docker stop $ContainerName 2>$null
        
        Write-Host "docker rm $ContainerName"
        docker rm $ContainerName 2>$null
        
        # 启动新容器（根据您的实际配置调整）
        Write-Host "docker run -d --name $ContainerName --restart unless-stopped -p 25500:25500 $ImageName"
        docker run -d --name $ContainerName --restart unless-stopped -p 25500:25500 $ImageName
        
        Start-Sleep -Seconds 5
        
        # 检查容器状态
        $containerStatus = docker inspect --format='{{.State.Running}}' $ContainerName 2>$null
        if ($containerStatus -eq "True") {
            Log-Step "✓ Docker 容器更新成功并正在运行" "Green"
            return $true
        } else {
            Log-Step "✗ Docker 容器启动失败" "Red"
            return $false
        }
    } catch {
        Log-Step "✗ Docker 更新失败: $_" "Red"
        return $false
    }
}

function Test-SubscriptionConversion {
    param(
        [string]$BackendUrl = "http://localhost:25500",
        [string]$TestUrl = "https://whua-bp.8dy.xx.kg/sub/normal/wh898?app=xray"
    )
    
    Log-Step "正在测试订阅转换功能..." "Yellow"
    
    try {
        # 测试 V2Ray target
        $convertUrl = "$BackendUrl/sub?target=v2ray&url=$([System.Web.HttpUtility]::UrlEncode($TestUrl))"
        $response = Invoke-WebRequest -Uri $convertUrl -Method GET -TimeoutSec 30 -UseBasicParsing
        
        $contentLength = [int]($response.Headers.'Content-Length' -join '')
        
        if ($contentLength -eq 0) {
            Log-Step "✗ 转换返回空响应 (Content-Length: 0)" "Red"
            return $false
        }
        
        # 尝试解码 Base64 内容
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($response.Content))
            $lines = ($decoded -split "`n" | Where-Object { $_.Trim() -ne "" })
            
            # 统计协议类型
            $vmessCount = ($lines | Where-Object { $_ -match "^vmess://" }).Count
            $vlessCount = ($lines | Where-Object { $_ -match "^vless://" }).Count
            $trojanCount = ($lines | Where-Object { $_ -match "^trojan://" }).Count
            $ssCount = ($lines | Where-Object { $_ -match "^ss://" }).Count
            $ssrCount = ($lines | Where-Object { $_ -match "^ssr://" }).Count
            $hysteria2Count = ($lines | Where-Object { $_ -match "^hysteria2://" }).Count
            $tuicCount = ($lines | Where-Object { $_ -match "^tuic://" }).Count
            
            Log-Step "✓ 订阅转换测试成功！" "Green"
            Log-Step "  节点总数: $($lines.Count)" "Gray"
            Log-Step "  VMess: $vmessCount | VLESS: $vlessCount | Trojan: $trojanCount" "Gray"
            Log-Step "  SS: $ssCount | SSR: $ssrCount | Hysteria2: $hysteria2Count | TUIC: $tuicCount" "Gray"
            
            # 如果所有协议都是0，说明转换仍有问题
            if (($vmessCount + $vlessCount + $trojanCount + $ssCount + $ssrCount + $hysteria2Count + $tuicCount) -eq 0) {
                Log-Step "⚠ 警告: 未检测到任何节点，可能仍有问题" "Yellow"
                return $false
            }
            
            return $true
        } catch {
            Log-Step " Base64 解码失败: $_" "Red"
            return $false
        }
    } catch {
        Log-Step "✗ 订阅转换测试失败: $_" "Red"
        return $false
    }
}

# ==================== 主流程 ====================

try {
    # 1. 检查是否有未提交的更改
    if (Test-GitStatus) {
        Log-Step "检测到未提交的更改" "Yellow"
        
        # 2. 推送到 GitHub
        if (-not (Push-ToGitHub -Message $CommitMessage)) {
            Log-Step "流程中断：推送失败" "Red"
            exit 1
        }
    } else {
        Log-Step "没有未提交的更改，跳过推送步骤" "Gray"
    }
    
    # 3. 等待 GitHub Actions 编译完成
    if (-not (Wait-GitHubActions)) {
        Log-Step "流程中断：编译失败" "Red"
        exit 1
    }
    
    # 4. 更新 Docker 容器
    if (-not (Update-DockerContainer)) {
        Log-Step "流程中断：Docker 更新失败" "Red"
        exit 1
    }
    
    # 5. 验证转换功能
    $testResult = Test-SubscriptionConversion
    
    if ($testResult) {
        Log-Step "==========================================" -ForegroundColor Green
        Log-Step "  ✓ 所有验证通过！流程完成" -ForegroundColor Green
        Log-Step "==========================================" -ForegroundColor Green
        
        if (-not $AutoLoop) {
            exit 0
        }
    } else {
        Log-Step "==========================================" -ForegroundColor Red
        Log-Step "  ✗ 验证失败，需要继续修复" -ForegroundColor Red
        Log-Step "==========================================" -ForegroundColor Red
        
        if ($AutoLoop) {
            Log-Step "自动循环模式：等待5秒后重试..." "Yellow"
            Start-Sleep -Seconds 5
            # 这里可以添加自动重新检测和修复的逻辑
        } else {
            exit 1
        }
    }
    
} catch {
    Log-Step "发生错误: $_" "Red"
    exit 1
}

Write-Host ""
Write-Host "提示: 如需持续循环验证，请使用 -AutoLoop 参数" -ForegroundColor Cyan
Write-Host "示例: .\auto-fix-loop.ps1 -AutoLoop" -ForegroundColor Gray
