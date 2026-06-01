# 详细验证订阅转换功能
# 测试 JSON 格式订阅能否正确转换为传统 URI 格式

param(
    [string]$BackendUrl = "http://localhost:25500",
    [string]$TestSubscriptionUrl = "https://whua-bp.8dy.xx.kg/sub/normal/wh898?app=xray"
)

$ErrorActionPreference = "Continue"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  订阅转换功能验证测试" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

function Test-ProtocolConversion {
    param(
        [string]$Target,
        [string]$Url,
        [string]$ProtocolName
    )
    
    Write-Host "`n[$ProtocolName] 测试 target=$Target" -ForegroundColor Yellow
    
    try {
        $convertUrl = "$BackendUrl/sub?target=$Target&url=$([System.Web.HttpUtility]::UrlEncode($Url))"
        $response = Invoke-WebRequest -Uri $convertUrl -Method GET -TimeoutSec 30 -UseBasicParsing
        
        $contentLength = [int]($response.Headers.'Content-Length' -join '')
        Write-Host "  Content-Length: $contentLength" -ForegroundColor Gray
        
        if ($contentLength -eq 0) {
            Write-Host "  ✗ 空响应" -ForegroundColor Red
            return @{Success=$false; Count=0; Protocols=@{}}
        }
        
        # 解码 Base64
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($response.Content))
            $lines = ($decoded -split "`n" | Where-Object { $_.Trim() -ne "" })
            
            # 统计各协议类型
            $protocols = @{
                VMess = ($lines | Where-Object { $_ -match "^vmess://" }).Count
                VLESS = ($lines | Where-Object { $_ -match "^vless://" }).Count
                Trojan = ($lines | Where-Object { $_ -match "^trojan://" }).Count
                SS = ($lines | Where-Object { $_ -match "^ss://" }).Count
                SSR = ($lines | Where-Object { $_ -match "^ssr://" }).Count
                Hysteria2 = ($lines | Where-Object { $_ -match "^hysteria2://" }).Count
                TUIC = ($lines | Where-Object { $_ -match "^tuic://" }).Count
            }
            
            $totalCount = $lines.Count
            
            Write-Host "  ✓ 总节点数: $totalCount" -ForegroundColor Green
            Write-Host "    VMess: $($protocols.VMess) | VLESS: $($protocols.VLESS) | Trojan: $($protocols.Trojan)" -ForegroundColor Gray
            Write-Host "    SS: $($protocols.SS) | SSR: $($protocols.SSR) | Hysteria2: $($protocols.Hysteria2) | TUIC: $($protocols.TUIC)" -ForegroundColor Gray
            
            # 显示前3个节点示例
            if ($lines.Count -gt 0) {
                Write-Host "  示例节点:" -ForegroundColor Gray
                $lines | Select-Object -First 3 | ForEach-Object {
                    $prefix = $_.Substring(0, [Math]::Min(60, $_.Length))
                    Write-Host "    - $prefix..." -ForegroundColor DarkGray
                }
            }
            
            return @{Success=$true; Count=$totalCount; Protocols=$protocols}
            
        } catch {
            Write-Host "  ✗ Base64 解码失败: $_" -ForegroundColor Red
            return @{Success=$false; Count=0; Protocols=@{}}
        }
        
    } catch {
        Write-Host "  ✗ 请求失败: $_" -ForegroundColor Red
        return @{Success=$false; Count=0; Protocols=@{}}
    }
}

# ==================== 主测试流程 ====================

Write-Host "测试后端: $BackendUrl" -ForegroundColor Cyan
Write-Host "测试订阅: $TestSubscriptionUrl" -ForegroundColor Cyan
Write-Host ""

# 测试不同 target
$testResults = @{}

# 1. 测试 V2Ray target (应该支持所有协议)
$testResults["v2ray"] = Test-ProtocolConversion -Target "v2ray" -Url $TestSubscriptionUrl -ProtocolName "V2Ray"

# 2. 测试 mixed target (应该输出所有协议)
$testResults["mixed"] = Test-ProtocolConversion -Target "mixed" -Url $TestSubscriptionUrl -ProtocolName "Mixed"

# 3. 测试 Clash target
$testResults["clash"] = Test-ProtocolConversion -Target "clash" -Url $TestSubscriptionUrl -ProtocolName "Clash"

# 4. 测试 Singbox target
$testResults["singbox"] = Test-ProtocolConversion -Target "singbox" -Url $TestSubscriptionUrl -ProtocolName "Singbox"

# ==================== 汇总结果 ====================

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  测试结果汇总" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$totalNodes = 0
$allSuccess = $true

foreach ($target in $testResults.Keys) {
    $result = $testResults[$target]
    $status = if ($result.Success) { "✓" } else { "✗" }
    $color = if ($result.Success) { "Green" } else { "Red" }
    
    Write-Host "$status $target`: $($result.Count) 个节点" -ForegroundColor $color
    
    if (-not $result.Success) {
        $allSuccess = $false
    }
    
    $totalNodes += $result.Count
}

Write-Host ""
Write-Host "总测试节点数: $totalNodes" -ForegroundColor Cyan

if ($allSuccess) {
    Write-Host "`n✓ 所有测试通过！" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n✗ 部分测试失败，需要修复" -ForegroundColor Red
    exit 1
}
