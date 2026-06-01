# 完整的全自动循环修正验证脚本
# 实现：发现问题 -> 修改 -> 推送 -> 等待编译 -> Docker更新 -> 验证 -> 循环

param(
    [string]$CommitMessage = "fix: 扩展JSON格式订阅解析，支持所有协议类型",
    [string]$Branch = "master",
    [int]$MaxRetries = 3,
    [switch]$AutoCommit = $true
)

$ErrorActionPreference = "Continue"
$ProjectRoot = "D:\Users\wh898\PycharmProjects\subconverter"
$GitHubRepo = "whua898/subconverter"
$BackendUrl = "http://localhost:25500"
$TestSubscriptionUrl = "https://whua-bp.8dy.xx.kg/sub/normal/wh898?app=xray"

Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     全自动循环修正和验证系统 v1.0                    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

function Log {
    param([string]$Message, [string]$Type = "INFO")
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $icon = switch ($Type) {
        "INFO" { "ℹ" }
        "SUCCESS" { "✓" }
        "ERROR" { "✗" }
        "WARNING" { "⚠" }
        "STEP" { "▶" }
        default { "•" }
    }
    
    $color = switch ($Type) {
        "INFO" { "White" }
        "SUCCESS" { "Green" }
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "STEP" { "Cyan" }
        default { "Gray" }
    }
    
    Write-Host "[$timestamp] $icon $Message" -ForegroundColor $color
}

function Step-GitCommitAndPush {
    Log "检查 Git 状态..." "STEP"
    Set-Location $ProjectRoot
    
    $status = git status --porcelain
    if (-not $status) {
        Log "没有未提交的更改，跳过推送" "INFO"
        return $true
    }
    
    if (-not $AutoCommit) {
        Log "检测到更改但未启用自动提交，请手动提交" "WARNING"
        return $false
    }
    
    Log "提交并推送更改到 GitHub..." "STEP"
    git add -A
    git commit -m $CommitMessage
    
    if ($LASTEXITCODE -ne 0) {
        Log "Git commit 失败" "ERROR"
        return $false
    }
    
    git push origin $Branch
    if ($LASTEXITCODE -ne 0) {
        Log "Git push 失败" "ERROR"
        return $false
    }
    
    Log "代码已成功推送到 GitHub" "SUCCESS"
    return $true
}

function Step-WaitForBuild {
    Log "等待 GitHub Actions 编译完成..." "STEP"
    
    $maxWait = 1800  # 30分钟
    $checkInterval = 30
    $elapsed = 0
    
    while ($elapsed -lt $maxWait) {
        try {
            $apiUrl = "https://api.github.com/repos/$GitHubRepo/actions/workflows/build.yml/runs?per_page=1"
            $headers = @{
                "Accept" = "application/vnd.github.v3+json"
            }
            $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop
            
            if ($response.workflow_runs -and $response.workflow_runs.Count -gt 0) {
                $run = $response.workflow_runs[0]
                $status = $run.status
                $conclusion = $run.conclusion
                
                Log "编译状态: $status / $conclusion" "INFO"
                
                if ($status -eq "completed") {
                    if ($conclusion -eq "success") {
                        Log "GitHub Actions 编译成功！" "SUCCESS"
                        return $true
                    } else {
                        Log "GitHub Actions 编译失败: $conclusion" "ERROR"
                        return $false
                    }
                }
            }
        } catch {
            Log "检查编译状态时出错: $_" "WARNING"
        }
        
        Start-Sleep -Seconds $checkInterval
        $elapsed += $checkInterval
    }
    
    Log "等待编译超时（30分钟）" "ERROR"
    return $false
}

function Step-UpdateDocker {
    Log "更新 Docker 容器..." "STEP"
    
    try {
        $imageName = "ghcr.io/whua898/subconverter:latest"
        $containerName = "subconverter"
        
        # 拉取最新镜像
        Log "拉取最新镜像..." "INFO"
        docker pull $imageName
        
        # 停止旧容器
        Log "停止旧容器..." "INFO"
        docker stop $containerName 2>$null
        docker rm $containerName 2>$null
        
        # 启动新容器
        Log "启动新容器..." "INFO"
        docker run -d --name $containerName `
            --restart unless-stopped `
            -p 25500:25500 `
            $imageName
        
        Start-Sleep -Seconds 5
        
        # 验证容器运行状态
        $isRunning = docker inspect --format='{{.State.Running}}' $containerName 2>$null
        if ($isRunning -eq "True") {
            Log "Docker 容器更新成功并正在运行" "SUCCESS"
            return $true
        } else {
            Log "Docker 容器启动失败" "ERROR"
            return $false
        }
    } catch {
        Log "Docker 更新失败: $_" "ERROR"
        return $false
    }
}

function Step-TestConversion {
    Log "测试订阅转换功能..." "STEP"
    
    try {
        $target = "v2ray"
        $encodedUrl = [System.Web.HttpUtility]::UrlEncode($TestSubscriptionUrl)
        $testUrl = "$BackendUrl/sub?target=$target&url=$encodedUrl"
        
        $response = Invoke-WebRequest -Uri $testUrl -Method GET -TimeoutSec 30 -UseBasicParsing
        $contentLength = [int]($response.Headers.'Content-Length' -join '')
        
        if ($contentLength -eq 0) {
            Log "转换返回空响应" "ERROR"
            return @{Success=$false; Details="Empty response"}
        }
        
        # 解码并统计
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($response.Content))
        $lines = ($decoded -split "`n" | Where-Object { $_.Trim() -ne "" })
        
        $protocols = @{
            VMess = ($lines | Where-Object { $_ -match "^vmess://" }).Count
            VLESS = ($lines | Where-Object { $_ -match "^vless://" }).Count
            Trojan = ($lines | Where-Object { $_ -match "^trojan://" }).Count
            SS = ($lines | Where-Object { $_ -match "^ss://" }).Count
            SSR = ($lines | Where-Object { $_ -match "^ssr://" }).Count
            Hysteria2 = ($lines | Where-Object { $_ -match "^hysteria2://" }).Count
            TUIC = ($lines | Where-Object { $_ -match "^tuic://" }).Count
        }
        
        $totalNodes = $lines.Count
        $totalProtocols = ($protocols.Values | Measure-Object -Sum).Sum
        
        Log "转换成功！总节点数: $totalNodes" "SUCCESS"
        Log "  VMess: $($protocols.VMess) | VLESS: $($protocols.VLESS) | Trojan: $($protocols.Trojan)" "INFO"
        Log "  SS: $($protocols.SS) | SSR: $($protocols.SSR) | Hysteria2: $($protocols.Hysteria2) | TUIC: $($protocols.TUIC)" "INFO"
        
        if ($totalProtocols -eq 0) {
            Log "未检测到任何节点，可能仍有问题" "WARNING"
            return @{Success=$false; Details="No nodes detected"; Protocols=$protocols}
        }
        
        return @{Success=$true; Count=$totalNodes; Protocols=$protocols}
        
    } catch {
        Log "转换测试失败: $_" "ERROR"
        return @{Success=$false; Details=$_}
    }
}

function Step-DetailedTest {
    Log "执行详细测试..." "STEP"
    
    $targets = @("v2ray", "mixed", "clash", "singbox")
    $results = @{}
    
    foreach ($target in $targets) {
        Log "测试 target=$target..." "INFO"
        
        try {
            $encodedUrl = [System.Web.HttpUtility]::UrlEncode($TestSubscriptionUrl)
            $testUrl = "$BackendUrl/sub?target=$target&url=$encodedUrl"
            
            $response = Invoke-WebRequest -Uri $testUrl -Method GET -TimeoutSec 30 -UseBasicParsing
            $contentLength = [int]($response.Headers.'Content-Length' -join '')
            
            if ($contentLength -gt 0) {
                $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($response.Content))
                $lines = ($decoded -split "`n" | Where-Object { $_.Trim() -ne "" })
                $results[$target] = @{Success=$true; Count=$lines.Count}
                Log "  $target: $($lines.Count) 个节点" "SUCCESS"
            } else {
                $results[$target] = @{Success=$false; Count=0}
                Log "  $target: 空响应" "ERROR"
            }
        } catch {
            $results[$target] = @{Success=$false; Count=0}
            Log "  $target: 测试失败" "ERROR"
        }
    }
    
    return $results
}

# ==================== 主循环 ====================

$currentRetry = 0
$success = $false

while ($currentRetry -lt $MaxRetries -and -not $success) {
    $currentRetry++
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  第 $currentRetry/$MaxRetries 次迭代                                   ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        # 步骤 1: Git 提交和推送
        if (-not (Step-GitCommitAndPush)) {
            Log "Git 操作失败，等待后重试..." "WARNING"
            Start-Sleep -Seconds 10
            continue
        }
        
        # 步骤 2: 等待编译
        if (-not (Step-WaitForBuild)) {
            Log "编译失败或超时，等待后重试..." "WARNING"
            Start-Sleep -Seconds 30
            continue
        }
        
        # 步骤 3: 更新 Docker
        if (-not (Step-UpdateDocker)) {
            Log "Docker 更新失败，等待后重试..." "WARNING"
            Start-Sleep -Seconds 30
            continue
        }
        
        # 步骤 4: 基础测试
        $testResult = Step-TestConversion
        if (-not $testResult.Success) {
            Log "基础测试失败，等待后重试..." "WARNING"
            Start-Sleep -Seconds 30
            continue
        }
        
        # 步骤 5: 详细测试
        $detailedResults = Step-DetailedTest
        $allPassed = $true
        foreach ($target in $detailedResults.Keys) {
            if (-not $detailedResults[$target].Success) {
                $allPassed = $false
                break
            }
        }
        
        if ($allPassed) {
            $success = $true
            Log "所有测试通过！" "SUCCESS"
        } else {
            Log "部分测试失败，继续下一次迭代..." "WARNING"
            Start-Sleep -Seconds 30
        }
        
    } catch {
        Log "发生异常: $_" "ERROR"
        Start-Sleep -Seconds 30
    }
}

# ==================== 最终结果 ====================

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor $(if($success){"Green"}else{"Red"})
if ($success) {
    Write-Host "║  ✓ 所有验证通过！流程成功完成                    ║" -ForegroundColor Green
} else {
    Write-Host "║   达到最大重试次数，流程结束                    ║" -ForegroundColor Red
}
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor $(if($success){"Green"}else{"Red"})

exit $(if($success){0}else{1})
