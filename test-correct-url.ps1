# 使用正确的原始订阅 URL 测试

$baseUrl = "https://subconverter.8dy.xx.kg"
$originalSub = "http://35.212.140.13:28038/56ff8aef-19a9-4043-8d4c-d38361c8f651/"

Write-Host "使用原始订阅源测试..." -ForegroundColor Cyan
Write-Host "订阅 URL: $originalSub" -ForegroundColor Gray
Write-Host ""

# 测试 1: Clash target
Write-Host "[1] Clash target:" -ForegroundColor Yellow
try {
    $clashUrl = "$baseUrl/sub?target=clash&url=$originalSub"
    $clashResponse = Invoke-WebRequest -Uri $clashUrl -UseBasicParsing -Method GET
    $clashLength = [int]($clashResponse.Headers.'Content-Length' -join '')
    Write-Host "  Content-Length: $clashLength" -ForegroundColor Gray
    if ($clashLength -gt 1000) {
        Write-Host "  ✅ 正常" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  可能有问题" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ❌ 失败: $_" -ForegroundColor Red
}

Write-Host ""

# 测试 2: V2Ray target
Write-Host "[2] V2Ray target:" -ForegroundColor Yellow
try {
    $v2rayUrl = "$baseUrl/sub?target=v2ray&url=$originalSub"
    $v2rayResponse = Invoke-WebRequest -Uri $v2rayUrl -UseBasicParsing -Method GET
    $v2rayLength = [int]($v2rayResponse.Headers.'Content-Length' -join '')
    
    if ($v2rayLength -eq 0) {
        Write-Host "  ❌ Content-Length: 0 (空响应)" -ForegroundColor Red
    } else {
        Write-Host "  ✅ Content-Length: $v2rayLength" -ForegroundColor Green
        
        # 尝试解码并统计
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($v2rayResponse.Content))
            $lines = ($decoded -split "`n" | Where-Object { $_.Trim() -ne "" })
            Write-Host "  📊 节点数: $($lines.Count)" -ForegroundColor Gray
            
            # 显示前3个节点类型
            $lines | Select-Object -First 3 | ForEach-Object {
                $prefix = $_.Substring(0, [Math]::Min(15, $_.Length))
                Write-Host "    - $prefix..." -ForegroundColor Gray
            }
        } catch {}
    }
} catch {
    Write-Host "  ❌ 失败: $_" -ForegroundColor Red
}

Write-Host ""

# 测试 3: Mixed target（关键测试）
Write-Host "[3] Mixed target（协议分布）:" -ForegroundColor Yellow
try {
    $mixedUrl = "$baseUrl/sub?target=mixed&url=$originalSub"
    $mixedResponse = Invoke-WebRequest -Uri $mixedUrl -UseBasicParsing -Method GET
    $mixedLength = [int]($mixedResponse.Headers.'Content-Length' -join '')
    Write-Host "  Content-Length: $mixedLength" -ForegroundColor Gray
    
    if ($mixedLength -gt 0) {
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($mixedResponse.Content))
            $lines = ($decoded -split "`n" | Where-Object { $_.Trim() -ne "" })
            Write-Host "  总节点数: $($lines.Count)" -ForegroundColor Gray
            
            $vmess = ($lines | Where-Object { $_ -match "^vmess://" }).Count
            $vless = ($lines | Where-Object { $_ -match "^vless://" }).Count
            $trojan = ($lines | Where-Object { $_ -match "^trojan://" }).Count
            $ss = ($lines | Where-Object { $_ -match "^ss://" }).Count
            $ssr = ($lines | Where-Object { $_ -match "^ssr://" }).Count
            
            Write-Host "  协议分布:" -ForegroundColor Gray
            Write-Host "    VMess: $vmess" -ForegroundColor $(if($vmess -gt 0){"Green"}else{"Red"})
            Write-Host "    VLESS: $vless" -ForegroundColor $(if($vless -gt 0){"Green"}else{"Yellow"})
            Write-Host "    Trojan: $trojan" -ForegroundColor Gray
            Write-Host "    SS: $ss" -ForegroundColor Gray
            Write-Host "    SSR: $ssr" -ForegroundColor Gray
            
            if ($vmess -eq 0 -and $vless -eq 0) {
                Write-Host ""
                Write-Host "  ️  原始订阅中没有 VMess/VLESS 节点" -ForegroundColor Yellow
            } else {
                Write-Host ""
                Write-Host "  ✅ 找到了 VMess/VLESS 节点！" -ForegroundColor Green
                Write-Host "  → 现在 v2ray target 应该可以正常工作了" -ForegroundColor Green
            }
        } catch {
            Write-Host "  无法解码内容" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "  ❌ 失败: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "测试完成！" -ForegroundColor Cyan
Write-Host ""
Write-Host "建议：" -ForegroundColor Cyan
Write-Host "如果原始订阅可以正常解析，说明之前的问题是 URL 格式错误。" -ForegroundColor Gray
Write-Host "在您的订阅转换工具中，将订阅链接改为：" -ForegroundColor Gray
Write-Host "  $originalSub" -ForegroundColor Yellow
Write-Host ""
