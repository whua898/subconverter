# 快速测试 subconverter.8dy.xx.kg

$baseUrl = "https://subconverter.8dy.xx.kg"
$subscription = "http://35.212.140.13:28038/56ff8aef-19a9-4043-8d4c-d38361c8f651/v2rayn"

Write-Host "测试远程 subconverter 服务..." -ForegroundColor Cyan
Write-Host ""

# 测试 1: 版本信息
Write-Host "[1] 版本信息:" -ForegroundColor Yellow
try {
    $version = Invoke-RestMethod -Uri "$baseUrl/version" -UseBasicParsing
    Write-Host "  ✅ $version" -ForegroundColor Green
} catch {
    Write-Host "  ❌ 失败: $_" -ForegroundColor Red
}

Write-Host ""

# 测试 2: Clash target
Write-Host "[2] Clash target:" -ForegroundColor Yellow
try {
    $clashUrl = "$baseUrl/sub?target=clash&url=$subscription"
    $clashResponse = Invoke-WebRequest -Uri $clashUrl -UseBasicParsing -Method GET
    $clashLength = [int]($clashResponse.Headers.'Content-Length' -join '')
    Write-Host "  ✅ Content-Length: $clashLength" -ForegroundColor Green
} catch {
    Write-Host "  ❌ 失败: $_" -ForegroundColor Red
}

Write-Host ""

# 测试 3: V2Ray target
Write-Host "[3] V2Ray target:" -ForegroundColor Yellow
try {
    $v2rayUrl = "$baseUrl/sub?target=v2ray&url=$subscription"
    $v2rayResponse = Invoke-WebRequest -Uri $v2rayUrl -UseBasicParsing -Method GET
    $v2rayLength = [int]($v2rayResponse.Headers.'Content-Length' -join '')
    if ($v2rayLength -eq 0) {
        Write-Host "  ❌ Content-Length: 0 (空响应!)" -ForegroundColor Red
    } else {
        Write-Host "  ✅ Content-Length: $v2rayLength" -ForegroundColor Green
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($v2rayResponse.Content))
            $lines = ($decoded -split "`n" | Where-Object { $_.Trim() -ne "" })
            Write-Host "  📊 节点数: $($lines.Count)" -ForegroundColor Gray
        } catch {}
    }
} catch {
    Write-Host "  ❌ 失败: $_" -ForegroundColor Red
}

Write-Host ""

# 测试 4: Mixed target（关键测试）
Write-Host "[4] Mixed target（检查是否有 VMess 节点）:" -ForegroundColor Yellow
try {
    $mixedUrl = "$baseUrl/sub?target=mixed&url=$subscription"
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
            
            Write-Host "  协议分布:" -ForegroundColor Gray
            Write-Host "    VMess: $vmess" -ForegroundColor $(if($vmess -gt 0){"Green"}else{"Red"})
            Write-Host "    VLESS: $vless" -ForegroundColor $(if($vless -gt 0){"Green"}else{"Yellow"})
            Write-Host "    Trojan: $trojan" -ForegroundColor Gray
            Write-Host "    SS: $ss" -ForegroundColor Gray
            
            if ($vmess -eq 0 -and $vless -eq 0) {
                Write-Host ""
                Write-Host "  ️  订阅源中没有 VMess/VLESS 节点！" -ForegroundColor Yellow
                Write-Host "  → 这就是 v2ray target 返回空的原因" -ForegroundColor Yellow
            } else {
                Write-Host ""
                Write-Host "  ✅ 有 VMess/VLESS 节点，但 v2ray target 返回空" -ForegroundColor Green
                Write-Host "  → 这是 subconverter 的 BUG！" -ForegroundColor Red
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
