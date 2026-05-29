# subconverter v2rayN 问题诊断脚本
# 用于诊断 v2rayN target 返回空响应的问题

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "subconverter v2rayN 问题诊断工具" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 配置
$subconverterUrl = "https://subconverter.8dy.xx.kg"
$testSubscriptionUrl = "http://35.212.140.13:28038/56ff8aef-19a9-4043-8d4c-d38361c8f651/v2rayn"  # 您的实际订阅地址

Write-Host "[1/5] 检查 subconverter 服务是否运行..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "$subconverterUrl/version" -Method GET -TimeoutSec 5
    Write-Host "✅ subconverter 服务正在运行" -ForegroundColor Green
    Write-Host "   版本信息: $($response.Content)" -ForegroundColor Gray
} catch {
    Write-Host "❌ 无法连接到 subconverter 服务: $_" -ForegroundColor Red
    Write-Host "   请确保 subconverter 正在运行且在端口 25500 上监听" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[2/5] 测试 clash target（应该正常工作）..." -ForegroundColor Yellow
try {
    $clashUrl = "$subconverterUrl/sub?target=clash&url=$testSubscriptionUrl"
    $clashResponse = Invoke-WebRequest -Uri $clashUrl -Method GET -TimeoutSec 30
    Write-Host "✅ Clash target 工作正常" -ForegroundColor Green
    Write-Host "   Content-Length: $($clashResponse.Headers.'Content-Length')" -ForegroundColor Gray
    Write-Host "   Status Code: $($clashResponse.StatusCode)" -ForegroundColor Gray
} catch {
    Write-Host "⚠️  Clash target 也失败了: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[3/5] 测试 v2rayN target..." -ForegroundColor Yellow
try {
    $v2rayUrl = "$subconverterUrl/sub?target=v2ray&url=$testSubscriptionUrl"
    $v2rayResponse = Invoke-WebRequest -Uri $v2rayUrl -Method GET -TimeoutSec 30
    $contentLength = [int]($v2rayResponse.Headers.'Content-Length' -join '')
    
    if ($contentLength -eq 0) {
        Write-Host "❌ v2rayN target 返回空响应 (Content-Length: 0)" -ForegroundColor Red
    } else {
        Write-Host "✅ v2rayN target 工作正常" -ForegroundColor Green
        Write-Host "   Content-Length: $contentLength" -ForegroundColor Gray
        
        # 尝试解码并显示前几个节点
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($v2rayResponse.Content))
            $lines = $decoded -split "`n" | Where-Object { $_.Trim() -ne "" }
            Write-Host "   节点数量: $($lines.Count)" -ForegroundColor Gray
            if ($lines.Count -gt 0) {
                Write-Host "   第一个节点类型: $($lines[0].Substring(0, [Math]::Min(20, $lines[0].Length)))" -ForegroundColor Gray
            }
        } catch {
            Write-Host "   (无法解码 Base64 内容)" -ForegroundColor Gray
        }
    }
    Write-Host "   Status Code: $($v2rayResponse.StatusCode)" -ForegroundColor Gray
} catch {
    Write-Host "❌ v2rayN target 请求失败: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "[4/5] 测试 mixed target（包含所有类型）..." -ForegroundColor Yellow
try {
    $mixedUrl = "$subconverterUrl/sub?target=mixed&url=$testSubscriptionUrl"
    $mixedResponse = Invoke-WebRequest -Uri $mixedUrl -Method GET -TimeoutSec 30
    $contentLength = [int]($mixedResponse.Headers.'Content-Length' -join '')
    
    Write-Host "✅ Mixed target 响应" -ForegroundColor Green
    Write-Host "   Content-Length: $contentLength" -ForegroundColor Gray
    
    if ($contentLength -gt 0) {
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($mixedResponse.Content))
            $lines = $decoded -split "`n" | Where-Object { $_.Trim() -ne "" }
            Write-Host "   总节点数量: $($lines.Count)" -ForegroundColor Gray
            
            # 统计各种协议类型
            $vmessCount = ($lines | Where-Object { $_ -match "^vmess://" }).Count
            $vlessCount = ($lines | Where-Object { $_ -match "^vless://" }).Count
            $trojanCount = ($lines | Where-Object { $_ -match "^trojan://" }).Count
            $ssCount = ($lines | Where-Object { $_ -match "^ss://" }).Count
            $ssrCount = ($lines | Where-Object { $_ -match "^ssr://" }).Count
            
            Write-Host "   协议分布:" -ForegroundColor Gray
            Write-Host "     - VMess: $vmessCount" -ForegroundColor Gray
            Write-Host "     - VLESS: $vlessCount" -ForegroundColor Gray
            Write-Host "     - Trojan: $trojanCount" -ForegroundColor Gray
            Write-Host "     - SS: $ssCount" -ForegroundColor Gray
            Write-Host "     - SSR: $ssrCount" -ForegroundColor Gray
            
            if ($vmessCount -eq 0 -and $vlessCount -eq 0) {
                Write-Host ""
                Write-Host "⚠️  警告：订阅源中没有 VMess 或 VLESS 节点！" -ForegroundColor Yellow
                Write-Host "   这就是 v2rayN target 返回空的原因。" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "   (无法解码内容)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "⚠️  Mixed target 请求失败: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[5/5] 检查 Docker 容器状态..." -ForegroundColor Yellow
try {
    $container = docker ps --filter "ancestor=ghcr.io/whua898/subconverter" --format "{{.ID}}\t{{.Image}}\t{{.Status}}" 2>$null
    if ($container) {
        Write-Host "✅ 找到 subconverter Docker 容器:" -ForegroundColor Green
        Write-Host "   $container" -ForegroundColor Gray
    } else {
        Write-Host "⚠️  未找到运行中的 subconverter Docker 容器" -ForegroundColor Yellow
        Write-Host "   您可能使用其他方式运行 subconverter" -ForegroundColor Gray
    }
} catch {
    Write-Host "⚠️  无法检查 Docker 状态: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "诊断建议：" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. 如果 mixed target 显示有 VMess/VLESS 节点，但 v2rayN 返回空：" -ForegroundColor White
Write-Host "   → 可能是代码问题，需要检查 subconverter 版本" -ForegroundColor Gray
Write-Host ""
Write-Host "2. 如果 mixed target 也显示没有 VMess/VLESS 节点：" -ForegroundColor White
Write-Host "   → 订阅源本身就没有这些节点，这是正常的" -ForegroundColor Gray
Write-Host "   → 尝试换一个包含 VMess 节点的订阅源测试" -ForegroundColor Gray
Write-Host ""
Write-Host "3. 如果所有 target 都失败：" -ForegroundColor White
Write-Host "   → 检查订阅 URL 是否正确" -ForegroundColor Gray
Write-Host "   → 检查网络连接和代理设置" -ForegroundColor Gray
Write-Host ""
Write-Host "4. 查看 subconverter 日志获取更多信息：" -ForegroundColor White
Write-Host "   docker logs <container_id> 2>&1 | Select-String 'v2ray'" -ForegroundColor Gray
Write-Host ""
