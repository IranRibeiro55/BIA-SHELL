#Requires -Version 5.1
<#
  BIA Shell - Assistente para TI e Suporte
  Copyright (c) 2024-2025 Iran Ribeiro. Todos os direitos reservados.

  Projeto: https://github.com/IranRibeiro55/BIA-SHELL
  Uso, copia e distribuicao sujeitos ao arquivo LICENSE deste repositorio.
  Nao remova este cabecalho. Autor: Iran Ribeiro.
#>
# BIA Shell v8 - CoreSafe (PowerShell)
# Animacoes, transicoes, novas funcionalidades, loading em telas

$script:BIA_Version = '8.0'
$ErrorActionPreference = 'Continue'
$script:WorkDir = Join-Path $env:TEMP 'BIA'
if (-not (Test-Path $script:WorkDir)) { New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null }

$uiPath = Join-Path $PSScriptRoot 'BIA-UI.ps1'
$langPath = Join-Path $PSScriptRoot 'BIA-Lang.ps1'
if (-not (Test-Path $uiPath)) {
    Write-Host '[ BIA ] Erro: BIA-UI.ps1 nao encontrado em:' -ForegroundColor Red
    Write-Host "  $uiPath" -ForegroundColor Yellow
    Write-Host '  Mantenha BIA-Shell.ps1, BIA-UI.ps1 e BIA-Lang.ps1 na mesma pasta.' -ForegroundColor Gray
    exit 1
}
if (-not (Test-Path $langPath)) {
    Write-Host '[ BIA ] Erro: BIA-Lang.ps1 nao encontrado em:' -ForegroundColor Red
    Write-Host "  $langPath" -ForegroundColor Yellow
    Write-Host '  Mantenha BIA-Shell.ps1, BIA-UI.ps1 e BIA-Lang.ps1 na mesma pasta.' -ForegroundColor Gray
    exit 1
}
. $uiPath
$script:BIA_Lang = 'pt'
. $langPath

function Show-BIALanguageSelection {
    Clear-Host
    $w = 70
    $line = '=' * $w
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
    $msg = Get-BIAStr 'lang_choose'
    $pad = [Math]::Max(0, ($w - [Math]::Min($msg.Length, $w)) / 2)
    Write-Host (' ' * [int]$pad) -NoNewline
    Write-Host $msg -ForegroundColor White
    Write-Host ''
    Write-Host "  [1] $(Get-BIAStr 'lang_1')     [2] $(Get-BIAStr 'lang_2')     [3] $(Get-BIAStr 'lang_3')" -ForegroundColor Cyan
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    $r = (Read-Host (Get-BIAStr 'lang_prompt')).Trim()
    if ($r -eq '2') { $script:BIA_Lang = 'en' }
    elseif ($r -eq '3') { $script:BIA_Lang = 'es' }
    else { $script:BIA_Lang = 'pt' }
}
Show-BIALanguageSelection

function Invoke-BIAVersionCheck {
    try {
        $r = Invoke-RestMethod -Uri 'https://api.github.com/repos/IranRibeiro55/BIA-SHELL/releases/latest' -TimeoutSec 5 -ErrorAction Stop
        $latest = ($r.tag_name -replace '^v', '').Trim()
        $cur = $script:BIA_Version
        if ($latest -and $cur -and ([version]$latest) -gt ([version]$cur)) {
            Write-Host ''
            Write-Host "  [ BIA ] $((Get-BIAStr 'new_version') -f $latest, $cur, $r.html_url)" -ForegroundColor $BIA_Theme.Warning
            Write-Host ''
        }
    } catch { }
}

# ---- IP rapido para o header ----
function Get-BIAPrimaryIP {
    try {
        $addr = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' -and $_.IPAddress } | Select-Object -First 1
        if ($addr) { return $addr.IPAddress }
    } catch {
        $m = (ipconfig 2>$null) | Select-String -Pattern 'IPv4' | Select-Object -First 1
        if ($m -match '(\d+\.\d+\.\d+\.\d+)') { return $Matches[1] }
    }
    return ''
}

# ---- Dashboard inicial (usuario, maquina, AD, RAM, disco, IP) ----
function Get-BIAWelcomeData {
    $h = @{}
    $h['Usuario'] = $env:USERNAME
    $h['Computador'] = $env:COMPUTERNAME
    if ($env:USERDNSDOMAIN) { $h['Dominio AD'] = $env:USERDNSDOMAIN } else { $h['Dominio AD'] = (Get-BIAStr 'no_ad') }
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        $h['SO'] = $os.Caption.Trim()
        $h['Versao'] = "$($os.Version) ($($os.OSArchitecture))"
        $boot = $os.ConvertToDateTime($os.LastBootUpTime)
        $uptime = (Get-Date) - $boot
        $h['Uptime'] = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
    }
    $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs) {
        $h['Fabricante'] = $cs.Manufacturer
        $h['Modelo'] = $cs.Model
    }
    $mem = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($mem) {
        $totalGB = [math]::Round($mem.TotalVisibleMemorySize / 1MB, 2)
        $freeGB = [math]::Round($mem.FreePhysicalMemory / 1MB, 2)
        $usedGB = [math]::Round(($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / 1MB, 2)
        $h['RAM'] = "$(Get-BIAStr 'ram_total'): ${totalGB} GB  |  $(Get-BIAStr 'ram_free'): ${freeGB} GB  |  $(Get-BIAStr 'ram_used'): ${usedGB} GB"
    }
    $disks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    $diskLines = @()
    foreach ($d in $disks) {
        $total = [math]::Round($d.Size / 1GB, 1)
        $free = [math]::Round($d.FreeSpace / 1GB, 1)
        $pct = if ($d.Size -gt 0) { [math]::Round(($d.FreeSpace / $d.Size) * 100, 0) } else { 0 }
        $label = if ($d.VolumeName) { "$($d.DeviceID) $($d.VolumeName)" } else { $d.DeviceID }
        $diskLines += "  ${label}: ${free} GB $(Get-BIAStr 'disk_free_of') ${total} GB ($pct% $(Get-BIAStr 'disk_free_pct'))"
    }
    $h['Disco'] = if ($diskLines.Count -gt 0) { $diskLines -join "`n  " } else { 'N/A' }
    $ips = @()
    try {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' -and $_.IPAddress } | ForEach-Object { $ips += $_.IPAddress }
    } catch {
        $ipout = (ipconfig 2>$null) | Select-String -Pattern 'IPv4'
        foreach ($m in $ipout) { if ($m -match '(\d+\.\d+\.\d+\.\d+)') { $ips += $Matches[1] } }
    }
    if ($ips.Count -gt 0) {
        $ipDisplay = ($ips | Select-Object -First 3) -join ', '
        if ($ips.Count -gt 3) { $ipDisplay += " (+$($ips.Count - 3) $(Get-BIAStr 'ip_more'))" }
        $h['IP(s)'] = $ipDisplay
    } else { $h['IP(s)'] = 'N/A' }
    $h['Data/Hora'] = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'
    if ($ips.Count -gt 0) { $script:BIA_PrimaryIP = $ips[0] } else { $script:BIA_PrimaryIP = '' }
    return $h
}

function Get-BIAGreeting {
    $h = (Get-Date).Hour
    if ($h -ge 5 -and $h -lt 12) { return (Get-BIAStr 'greeting_morning') }
    if ($h -ge 12 -and $h -lt 18) { return (Get-BIAStr 'greeting_afternoon') }
    return (Get-BIAStr 'greeting_evening')
}

function Get-BIAAgentTip {
    $tips = @('tip_1','tip_2','tip_3','tip_4','tip_5','tip_6','tip_7')
    Get-BIAStr $tips[(Get-Random -Maximum $tips.Count)]
}

function Show-BIAHomeScreen {
    Get-BIAWelcomeData | Out-Null
    Write-BIAHeader -IP $script:BIA_PrimaryIP
    Show-BIAWelcomeDashboard
    Write-Host ''
    $saudacao = Get-BIAGreeting
    $nome = $env:USERNAME
    $pad = [Math]::Max(0, ($ScreenWidth - ($saudacao.Length + $nome.Length + 4)) / 2)
    Write-Host (' ' * [int]$pad) -NoNewline
    Show-BIATyping -Text "$saudacao, " -DelayMs 40 -NoNewline
    Write-Host $nome -NoNewline -ForegroundColor $BIA_Theme.Success
    Show-BIATyping -Text '!' -DelayMs 80
    Write-Host ''
    $pad2 = [Math]::Max(0, ($ScreenWidth - 42) / 2)
    Write-Host (' ' * [int]$pad2) -NoNewline
    Show-BIATyping -Text (Get-BIAStr 'help_prompt') -DelayMs 25 -NoNewline -Color Accent
    Write-Host ''
    Read-Host
}

function Show-BIAWelcomeDashboard {
    $data = Get-BIAWelcomeData
    $na = Get-BIAStr 'N/A'
    $n = { param($k) if ($data.ContainsKey($k) -and $data[$k]) { $data[$k] } else { $na } }
    $lines = @()
    $lines += "  $((Get-BIAStr 'lbl_user').PadRight(12)): $(& $n 'Usuario')"
    $lines += "  $((Get-BIAStr 'lbl_computer').PadRight(12)): $(& $n 'Computador')"
    $lines += "  $((Get-BIAStr 'lbl_domain').PadRight(12)): $(& $n 'Dominio AD')"
    $lines += "  $((Get-BIAStr 'lbl_os').PadRight(12)): $(& $n 'SO')"
    $lines += "  $((Get-BIAStr 'lbl_version').PadRight(12)): $(& $n 'Versao')"
    $lines += "  $((Get-BIAStr 'lbl_uptime').PadRight(12)): $(& $n 'Uptime')"
    $lines += "  $((Get-BIAStr 'lbl_manufacturer').PadRight(12)): $(& $n 'Fabricante')"
    $lines += "  $((Get-BIAStr 'lbl_model').PadRight(12)): $(& $n 'Modelo')"
    $lines += "  $((Get-BIAStr 'lbl_ram').PadRight(12)): $(& $n 'RAM')"
    $lines += "  $((Get-BIAStr 'lbl_disk').PadRight(12)):"
    $discoVal = & $n 'Disco'
    if ($discoVal -and $discoVal -ne $na) { foreach ($dl in ($discoVal -split "`n")) { $lines += $dl } } else { $lines += "  ($na)" }
    $lines += "  $((Get-BIAStr 'lbl_ip').PadRight(12)): $(& $n 'IP(s)')"
    $lines += "  $((Get-BIAStr 'lbl_datetime').PadRight(12)): $(& $n 'Data/Hora')"
    Write-BIAInfoPanel -Title (Get-BIAStr 'dashboard_title') -Lines $lines
}

# ---- Menu principal ----
function Show-MainMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -IP $script:BIA_PrimaryIP
    Write-BIABox -Title (Get-BIAStr 'main_title') -Lines @(
        (Get-BIAStr 'main_1'), (Get-BIAStr 'main_2'), (Get-BIAStr 'main_3'), (Get-BIAStr 'main_4'), (Get-BIAStr 'main_5'),
        (Get-BIAStr 'main_6'), (Get-BIAStr 'main_7'), (Get-BIAStr 'main_8'), (Get-BIAStr 'main_9'), (Get-BIAStr 'main_10'),
        (Get-BIAStr 'main_11'), (Get-BIAStr 'main_12'), (Get-BIAStr 'main_R'), (Get-BIAStr 'main_S'), (Get-BIAStr 'main_0')
    )
    Write-Host ''
    $tip = Get-BIAAgentTip
    Write-Host "  " -NoNewline
    Write-Host $tip -ForegroundColor $BIA_Theme.Muted
    Write-Host ''
    $prompts = @((Get-BIAStr 'prompt_what'), (Get-BIAStr 'prompt_what_now'), (Get-BIAStr 'prompt_help'), (Get-BIAStr 'prompt_option'))
    $prompt = $prompts[(Get-Random -Maximum $prompts.Count)]
    $op = (Read-Host "  $prompt").Trim().ToUpper()
    switch ($op) {
        '1' { Show-BIATransition -Title (Get-BIAStr 'title_user') -Milliseconds 500; Show-UserMenu }
        '2' { Show-BIATransition -Title (Get-BIAStr 'title_ti') -Milliseconds 500; Show-TIMenu }
        '3' { Show-BIATransition -Title (Get-BIAStr 'title_ad') -Milliseconds 500; Show-ADMenu }
        '4' { Show-BIATransition -Title (Get-BIAStr 'title_network') -Milliseconds 500; Show-NetMenu }
        '5' { Show-BIATransition -Title (Get-BIAStr 'title_utils') -Milliseconds 500; Show-UtilsMenu }
        '6' { Show-BIATransition -Title (Get-BIAStr 'title_playbooks') -Milliseconds 500; Show-PlaybooksMenu }
        '7' { Show-BIATransition -Title (Get-BIAStr 'title_sysinfo') -Milliseconds 500; Show-SysInfoMenu }
        '8' { Show-BIATransition -Title (Get-BIAStr 'title_health') -Milliseconds 500; Show-HealthMenu }
        '9' { Show-BIATransition -Title (Get-BIAStr 'title_printers') -Milliseconds 400; Show-PrintersMenu }
        '10' { Show-BIATransition -Title (Get-BIAStr 'title_azure') -Milliseconds 400; Show-AzureMenu }
        '11' { Show-BIATransition -Title (Get-BIAStr 'title_install') -Milliseconds 400; Show-InstallAppsMenu }
        '12' { Show-BIATransition -Title (Get-BIAStr 'title_tools') -Milliseconds 400; Show-ToolsMenu }
        'R' { Write-Host ''; $padR = [Math]::Max(0, ($ScreenWidth - 22) / 2); Write-Host (' ' * [int]$padR) -NoNewline; Show-BIATyping -Text (Get-BIAStr 'returning') -DelayMs 30 -Color Accent; Start-Sleep -Milliseconds 400; Show-BIAHomeScreen; Show-MainMenu }
        'S' { Show-BIAAbout; Invoke-BIAPause; Show-MainMenu }
        '0' { Exit-BIA }
        default { Show-MainMenu }
    }
}

function Show-BIAAbout {
    Write-BIAHeader -IP $script:BIA_PrimaryIP
    $pad = [Math]::Max(0, ($ScreenWidth - 28) / 2)
    Write-Host (' ' * [int]$pad) -NoNewline
    Show-BIATyping -Text (Get-BIAStr 'about_title') -DelayMs 25 -Color Title
    Write-Host ''
    Write-BIABox -Title (Get-BIAStr 'about_title') -Lines @(
        (Get-BIAStr 'about_line1'), (Get-BIAStr 'about_line2'), '  ',
        (Get-BIAStr 'about_dev'), (Get-BIAStr 'about_github'), '  ',
        (Get-BIAStr 'about_footer')
    )
    Write-Host ''
    $pad2 = [Math]::Max(0, ($ScreenWidth - 45) / 2)
    Write-Host (' ' * [int]$pad2) -NoNewline
    Show-BIATyping -Text (Get-BIAStr 'about_thanks') -DelayMs 20 -Color Muted
    Write-Host ''
}

# ---------- USUARIO ----------
function Show-UserMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'user_subtitle') -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        (Get-BIAStr 'user_1'), (Get-BIAStr 'user_2'), (Get-BIAStr 'user_3'), (Get-BIAStr 'user_4'), (Get-BIAStr 'user_5'),
        (Get-BIAStr 'user_6'), (Get-BIAStr 'user_7'), (Get-BIAStr 'user_8'), (Get-BIAStr 'user_9'), (Get-BIAStr 'user_a'),
        (Get-BIAStr 'user_0')
    )
    $op = (Read-Host "  $(Get-BIAStr 'choice')").Trim().ToLower()
    switch ($op) {
        '1' { Invoke-UserClean; Invoke-BIAPause; Show-UserMenu }
        '2' { Invoke-UserNet; Invoke-BIAPause; Show-UserMenu }
        '3' { Show-BIALoadingShort -Message (Get-BIAStr 'msg_getting_ipconfig') -Steps 8; ipconfig /all | More; Invoke-BIAPause; Show-UserMenu }
        '4' { Show-BIALoadingShort -Message 'Flush DNS...' -Steps 5; ipconfig /flushdns | Out-Null; Write-BIAMessage (Get-BIAStr 'msg_dns_cleaned') Success; Invoke-BIAPause; Show-UserMenu }
        '5' { Start-Process 'control.exe' -ArgumentList '/name Microsoft.WindowsUpdate'; Write-BIAMessage (Get-BIAStr 'msg_opening_wu') Info; Start-Sleep -Seconds 2; Show-UserMenu }
        '6' { & chkdsk C: /F /R; Write-BIAMessage (Get-BIAStr 'msg_restart_required') Warning; Invoke-BIAPause; Show-UserMenu }
        '7' { Start-Process explorer -ArgumentList $env:USERPROFILE; Write-BIAMessage (Get-BIAStr 'msg_opening_folder') Info; Show-UserMenu }
        '8' { Start-Process explorer -ArgumentList 'shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}'; Write-BIAMessage (Get-BIAStr 'msg_opening_pc') Info; Show-UserMenu }
        '9' { Invoke-UserCache; Invoke-BIAPause; Show-UserMenu }
        'a' { Write-Host "  $(Get-BIAStr 'msg_docs_desktop')" -ForegroundColor $BIA_Theme.Menu; $r = (Read-Host).Trim(); if ($r -eq '1') { Start-Process "$env:USERPROFILE\Documents" }; if ($r -eq '2') { Start-Process "$env:USERPROFILE\Desktop" }; if ($r -eq '3') { Start-Process "$env:USERPROFILE\Downloads" }; Show-UserMenu }
        '0' { Show-MainMenu }
        default { Show-UserMenu }
    }
}

function Invoke-UserClean {
    Write-BIAMessage (Get-BIAStr 'msg_cleanup_temp') Info
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_cleaning_temp') -TotalSteps 6
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_cleaning_wintemp') -TotalSteps 6
    Remove-Item -Path 'C:\Windows\Temp\*' -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAMessage (Get-BIAStr 'msg_done') Success
}

function Invoke-UserNet {
    Write-BIAMessage 'Teste basico: ping 8.8.8.8' Info
    ping -n 4 8.8.8.8
    ping -n 4 www.google.com
    Write-BIAMessage 'Renovando IP + flush DNS...' Info
    Write-BIAProgressBar -Message 'Flush DNS' -TotalSteps 3
    ipconfig /flushdns | Out-Null
    Write-BIAProgressBar -Message 'Release IP' -TotalSteps 3
    ipconfig /release | Out-Null
    Write-BIAProgressBar -Message 'Renew IP' -TotalSteps 5
    ipconfig /renew | Out-Null
    Write-BIAMessage 'Concluido.' Success
}

function Invoke-UserCache {
    Write-BIAMessage (Get-BIAStr 'msg_cache_reset') Info
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_closing_teams') -TotalSteps 3
    Stop-Process -Name 'Teams' -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_cache_teams') -TotalSteps 4
    Remove-Item -Path "$env:APPDATA\Microsoft\Teams" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Office\16.0\Wef" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_cache_edge') -TotalSteps 3
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_cache_chrome') -TotalSteps 3
    Remove-Item -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAMessage (Get-BIAStr 'msg_ok') Success
}

# ---------- TI ----------
function Show-TIMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'title_ti') -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        (Get-BIAStr 'ti_1'), (Get-BIAStr 'ti_2'), (Get-BIAStr 'ti_3'), (Get-BIAStr 'ti_4'), (Get-BIAStr 'ti_5'), (Get-BIAStr 'ti_6'), (Get-BIAStr 'ti_7'), (Get-BIAStr 'ti_8'), (Get-BIAStr 'ti_9'),
        (Get-BIAStr 'ti_a'), (Get-BIAStr 'ti_b'), (Get-BIAStr 'ti_c'), (Get-BIAStr 'ti_d'), (Get-BIAStr 'ti_e'), (Get-BIAStr 'ti_f'), (Get-BIAStr 'ti_g'), (Get-BIAStr 'ti_h'), (Get-BIAStr 'ti_i'),
        (Get-BIAStr 'ti_j'), (Get-BIAStr 'ti_k'), (Get-BIAStr 'ti_l'), (Get-BIAStr 'ti_m'), (Get-BIAStr 'ti_n'), (Get-BIAStr 'ti_o'), (Get-BIAStr 'ti_p'), (Get-BIAStr 'ti_q'), (Get-BIAStr 'ti_r'), (Get-BIAStr 'ti_s'), (Get-BIAStr 'ti_t'), (Get-BIAStr 'ti_0')
    )
    $op = (Read-Host "  $(Get-BIAStr 'msg_prompt_choice')").Trim().ToLower()
    switch ($op) {
        '1' { Show-BIASpinner -Message (Get-BIAStr 'msg_gpo_apply') -ScriptBlock { & gpupdate /force 2>&1 | Out-Null }; Invoke-BIAPause; Show-TIMenu }
        '2' { Start-Process eventvwr.msc; Write-BIAMessage (Get-BIAStr 'msg_opening_ev') Info; Start-Sleep -Seconds 2; Show-TIMenu }
        '3' { Start-Process services.msc; Write-BIAMessage (Get-BIAStr 'msg_opening_services') Info; Start-Sleep -Seconds 2; Show-TIMenu }
        '4' { Start-Process perfmon; Write-BIAMessage (Get-BIAStr 'msg_opening_perfmon') Info; Start-Sleep -Seconds 2; Show-TIMenu }
        '5' { Start-Process taskmgr; Write-BIAMessage (Get-BIAStr 'msg_opening_taskmgr') Info; Start-Sleep -Seconds 2; Show-TIMenu }
        '6' { Show-BIALoadingShort -Message (Get-BIAStr 'msg_listing_processes') -Steps 10; Get-Process | Format-Table Id, ProcessName, CPU, WorkingSet64 -AutoSize | Out-String | More; Invoke-BIAPause; Show-TIMenu }
        '7' { $name = (Read-Host (Get-BIAStr 'msg_process_name')).Trim(); if ($name) { Stop-Process -Name ($name -replace '\.exe$','') -Force -ErrorAction SilentlyContinue; Write-BIAMessage (Get-BIAStr 'msg_process_killed') Success }; Invoke-BIAPause; Show-TIMenu }
        '8' { $sw = Show-BIASpinner -Message (Get-BIAStr 'msg_listing_software') -ScriptBlock { Get-WmiObject Win32_Product | Select-Object Name, Version }; $sw | Format-Table -AutoSize | Out-String | More; Invoke-BIAPause; Show-TIMenu }
        '9' { Show-TITopProcesses; Invoke-BIAPause; Show-TIMenu }
        'a' { Start-Process mstsc; Write-BIAMessage (Get-BIAStr 'msg_opening_remote') Info; Show-TIMenu }
        'b' { Start-Process compmgmt.msc; Write-BIAMessage (Get-BIAStr 'msg_opening_compmgmt') Info; Show-TIMenu }
        'c' { $pc = (Read-Host (Get-BIAStr 'msg_remote_pc')).Trim(); if ($pc) { Start-Process "compmgmt.msc" -ArgumentList "/computer:$pc"; Write-BIAMessage "$(Get-BIAStr 'msg_opening') $pc" Info }; Show-TIMenu }
        'd' { Start-Process lusrmgr.msc; Write-BIAMessage (Get-BIAStr 'msg_opening_lusrmgr') Info; Show-TIMenu }
        'e' { Show-BIALoadingShort -Message (Get-BIAStr 'msg_listing_updates') -Steps 12; Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID, Description, InstalledOn -AutoSize | Out-String | More; Invoke-BIAPause; Show-TIMenu }
        'f' { Write-BIAMessage (Get-BIAStr 'msg_sfc_confirm') Warning; if ((Read-Host).Trim().ToLower() -match '^[sy]') { sfc /scannow; Invoke-BIAPause }; Show-TIMenu }
        'g' { Invoke-CreateRestorePoint; Invoke-BIAPause; Show-TIMenu }
        'h' { Show-BIALoadingShort -Message 'BitLocker...' -Steps 5; manage-bde -status 2>$null; if ($LASTEXITCODE -ne 0) { Write-BIAMessage (Get-BIAStr 'msg_bitlocker_na') Muted }; Invoke-BIAPause; Show-TIMenu }
        'i' { Show-TIRemotePrintMenu; Show-TIMenu }
        'j' { query session 2>$null; Invoke-BIAPause; Show-TIMenu }
        'k' { whoami /all | More; Invoke-BIAPause; Show-TIMenu }
        'l' { Get-ScheduledTask | Where-Object State -eq Ready | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize; Invoke-BIAPause; Show-TIMenu }
        'm' { Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name, Command, Location | Format-Table -AutoSize -Wrap; Invoke-BIAPause; Show-TIMenu }
        'n' { try { $mp = Get-MpComputerStatus -ErrorAction Stop; Write-Host "  Defender: " -NoNewline; Write-Host $mp.AntivirusEnabled -NoNewline; Write-Host " | $(Get-BIAStr 'msg_last_scan'): " -NoNewline; Write-Host $mp.QuickScanStartTime; $r = (Read-Host (Get-BIAStr 'msg_defender_scan_confirm')).Trim().ToLower(); if ($r -match '^[sy]') { Start-MpScan -ScanType Quick; Write-BIAMessage (Get-BIAStr 'msg_scan_started') Success } } catch { Write-BIAMessage (Get-BIAStr 'msg_defender_na_short') Warning }; Invoke-BIAPause; Show-TIMenu }
        'o' { net share; Invoke-BIAPause; Show-TIMenu }
        'p' { $k = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue; $w = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue; if ($k -or $w) { Write-BIAMessage (Get-BIAStr 'msg_reboot_pending_detect') Warning } else { Write-BIAMessage (Get-BIAStr 'msg_no_reboot_pending_detect') Success }; Invoke-BIAPause; Show-TIMenu }
        'q' { net user; Invoke-BIAPause; Show-TIMenu }
        'r' { Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class PInvoke { [DllImport("user32.dll")] public static extern void LockWorkStation(); }'; [PInvoke]::LockWorkStation(); Write-BIAMessage (Get-BIAStr 'msg_station_locked') Info; Start-Sleep -Seconds 2; Show-TIMenu }
        's' { $port = (Read-Host (Get-BIAStr 'msg_port_prompt')).Trim(); if ($port) { Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; Write-Host "  $(Get-BIAStr 'lbl_port') $port -> PID $($_.OwningProcess) -> $($p.ProcessName)" } }; Invoke-BIAPause; Show-TIMenu }
        't' { Start-Process 'perfmon' -ArgumentList '/rel'; Write-BIAMessage (Get-BIAStr 'msg_opening_reliability_short') Info; Show-TIMenu }
        '0' { Show-MainMenu }
        default { Show-TIMenu }
    }
}

function Invoke-CreateRestorePoint {
    Write-BIAMessage (Get-BIAStr 'msg_restore_creating') Info
    try {
        $null = powershell -NoProfile -Command "Checkpoint-Computer -Description 'BIA Shell' -RestorePointType 'MODIFY_SETTINGS'" 2>$null
        if ($LASTEXITCODE -eq 0) { Write-BIAMessage (Get-BIAStr 'msg_restore_ok') Success } else { throw 'Falha' }
    } catch {
        try {
            wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "BIA", 7 2>$null
            Write-BIAMessage (Get-BIAStr 'msg_restore_wmi_ok') Success
        } catch { Write-BIAMessage (Get-BIAStr 'msg_admin_required') Error }
    }
}

function Show-TIRemotePrintMenu {
    Write-Host (Get-BIAStr 'ti_remote_print_1') (Get-BIAStr 'ti_remote_print_2') -ForegroundColor $BIA_Theme.Menu
    $r = (Read-Host "  $(Get-BIAStr 'msg_prompt_choice')").Trim()
    if ($r -eq '1') { Start-Process msra; Write-BIAMessage (Get-BIAStr 'msg_opening_assist') Info }
    if ($r -eq '2') { Start-Process 'control.exe' -ArgumentList 'printers'; Write-BIAMessage (Get-BIAStr 'msg_opening_printers') Info }
}

function Show-TITopProcesses {
    Show-BIALoadingShort -Message (Get-BIAStr 'msg_cpu_ram') -Steps 12
    Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 |
        Format-Table ProcessName, Id, @{N='CPU(s)';E={[math]::Round($_.CPU,2)}}, @{N='RAM(MB)';E={[math]::Round($_.WorkingSet64/1MB,2)}} -AutoSize
}

# ---------- AD ----------
function Show-ADMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'title_ad') -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        (Get-BIAStr 'ad_1'), (Get-BIAStr 'ad_2'), (Get-BIAStr 'ad_3'), (Get-BIAStr 'ad_4'), (Get-BIAStr 'ad_5'), (Get-BIAStr 'ad_6'), (Get-BIAStr 'ad_7'), (Get-BIAStr 'ad_8'), (Get-BIAStr 'ad_0')
    )
    $op = (Read-Host "  $(Get-BIAStr 'msg_prompt_choice')").Trim()
    switch ($op) {
        '1' { Start-Process dsa.msc; Show-ADMenu }
        '2' { Start-Process gpmc.msc; Show-ADMenu }
        '3' { Start-Process dnsmgmt.msc; Show-ADMenu }
        '4' { Start-Process dhcpmgmt.msc; Show-ADMenu }
        '5' { Show-BIALoadingShort -Message 'repadmin...' -Steps 6; & repadmin /replsummary 2>$null | More; Invoke-BIAPause; Show-ADMenu }
        '6' { Show-BIASpinner -Message 'Sincronizando replicacao...' -ScriptBlock { & repadmin /syncall /AdeP 2>&1 | Out-Null }; Invoke-BIAPause; Show-ADMenu }
        '7' { Show-BIALoadingShort -Message 'dcdiag...' -Steps 8; & dcdiag 2>$null | More; Invoke-BIAPause; Show-ADMenu }
        '8' { Invoke-ADFast; Invoke-BIAPause; Show-ADMenu }
        '0' { Show-MainMenu }
        default { Show-ADMenu }
    }
}

function Invoke-ADFast {
    Write-Host ' === NLTEST ===' -ForegroundColor Cyan
    & nltest /dsgetdc:$env:USERDNSDOMAIN 2>$null
    Write-Host "`n === KLIST ===" -ForegroundColor Cyan
    & klist 2>$null
    Write-Host 'Limpando tickets (sistema)...'
    & klist purge -li 0x3e7 2>$null
    Write-Host "`n === GPRESULT ===" -ForegroundColor Cyan
    & gpresult /r 2>$null
}

# ---------- REDE ----------
function Show-NetMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'title_network') -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        (Get-BIAStr 'net_1'), (Get-BIAStr 'net_2'), (Get-BIAStr 'net_3'), (Get-BIAStr 'net_4'), (Get-BIAStr 'net_5'), (Get-BIAStr 'net_6'),
        (Get-BIAStr 'net_7'), (Get-BIAStr 'net_8'), (Get-BIAStr 'net_9'), (Get-BIAStr 'net_a'), (Get-BIAStr 'net_b'), (Get-BIAStr 'net_c'),
        (Get-BIAStr 'net_d'), (Get-BIAStr 'net_e'), (Get-BIAStr 'net_f'), (Get-BIAStr 'net_0')
    )
    $op = (Read-Host "  $(Get-BIAStr 'msg_prompt_choice')").Trim().ToLower()
    switch ($op) {
        '1' { ping -n 4 8.8.8.8; Invoke-BIAPause; Show-NetMenu }
        '2' { Show-BIALoadingShort -Message (Get-BIAStr 'msg_tracert') -Steps 5; tracert google.com; Invoke-BIAPause; Show-NetMenu }
        '3' { Show-BIALoadingShort -Message (Get-BIAStr 'msg_netstat') -Steps 8; netstat -ano | More; Invoke-BIAPause; Show-NetMenu }
        '4' { Write-BIAProgressBar -Message (Get-BIAStr 'msg_reset_winsock') -TotalSteps 3; netsh winsock reset 2>$null; Write-BIAProgressBar -Message (Get-BIAStr 'msg_reset_ip') -TotalSteps 3; netsh int ip reset 2>$null; Write-BIAMessage (Get-BIAStr 'msg_restart_required') Warning; Invoke-BIAPause; Show-NetMenu }
        '5' { netsh advfirewall set allprofiles state off; Write-BIAMessage (Get-BIAStr 'msg_firewall_off') Warning; Invoke-BIAPause; Show-NetMenu }
        '6' { netsh advfirewall set allprofiles state on; Write-BIAMessage (Get-BIAStr 'msg_firewall_on') Success; Invoke-BIAPause; Show-NetMenu }
        '7' { Write-BIAProgressBar -Message (Get-BIAStr 'msg_clearing_arp') -TotalSteps 3; arp -d * 2>$null; Write-BIAProgressBar -Message (Get-BIAStr 'msg_release_renew') -TotalSteps 5; ipconfig /release 2>$null; ipconfig /renew 2>$null; Invoke-BIAPause; Show-NetMenu }
        '8' { Show-NetPorts; Invoke-BIAPause; Show-NetMenu }
        '9' { $drive = (Read-Host (Get-BIAStr 'msg_drive_letter')).Trim().ToUpper(); $path = (Read-Host (Get-BIAStr 'msg_unc_path')).Trim(); if ($drive -and $path) { & net use "${drive}:" $path 2>$null; Write-BIAMessage "$(Get-BIAStr 'msg_mapped_drive') ${drive}: -> $path" Success }; Invoke-BIAPause; Show-NetMenu }
        'a' { $pc = (Read-Host (Get-BIAStr 'msg_remote_pc')).Trim(); if ($pc) { if ($pc -notlike '\\\\*') { $pc = "\\$pc" }; Start-Process explorer -ArgumentList $pc; Write-BIAMessage "$(Get-BIAStr 'msg_opening') $pc" Info }; Show-NetMenu }
        'b' { $h = (Read-Host (Get-BIAStr 'msg_dns_query_prompt')).Trim(); if ($h) { nslookup $h }; Invoke-BIAPause; Show-NetMenu }
        'c' { $t = (Read-Host (Get-BIAStr 'msg_host_port')).Trim(); $prtStr = (Read-Host (Get-BIAStr 'msg_port_enter')).Trim(); if ($t) { $p = 0; if ($prtStr -and [int]::TryParse($prtStr, [ref]$p) -and $p -gt 0) { Test-NetConnection -ComputerName $t -Port $p } else { Test-NetConnection -ComputerName $t } }; Invoke-BIAPause; Show-NetMenu }
        'd' { route print; Invoke-BIAPause; Show-NetMenu }
        'e' { arp -a; Invoke-BIAPause; Show-NetMenu }
        'f' { ipconfig /displaydns | More; Invoke-BIAPause; Show-NetMenu }
        '0' { Show-MainMenu }
        default { Show-NetMenu }
    }
}

function Show-NetPorts {
    Show-BIALoadingShort -Message (Get-BIAStr 'msg_analyzing_ports') -Steps 10
    $lines = netstat -ano 2>$null
    $lines | Select-String -Pattern 'LISTEN|ESTABLISHED' | Select-Object -First 30
}

# ---------- UTILITARIOS ----------
function Show-UtilsMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'title_utils') -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        (Get-BIAStr 'utils_1'), (Get-BIAStr 'utils_2'), (Get-BIAStr 'utils_3'), (Get-BIAStr 'utils_4'), (Get-BIAStr 'utils_5'),
        (Get-BIAStr 'utils_6'), (Get-BIAStr 'utils_7'), (Get-BIAStr 'utils_8'), (Get-BIAStr 'utils_9'),
        (Get-BIAStr 'utils_a'), (Get-BIAStr 'utils_b'), (Get-BIAStr 'utils_c'), (Get-BIAStr 'utils_d'), (Get-BIAStr 'utils_e'),
        (Get-BIAStr 'utils_f'), (Get-BIAStr 'utils_g'), (Get-BIAStr 'utils_h'), (Get-BIAStr 'utils_0')
    )
    $op = (Read-Host "  $(Get-BIAStr 'msg_prompt_choice')").Trim().ToLower()
    switch ($op) {
        '1' { Start-Process regedit; Show-UtilsMenu }
        '2' { shutdown /s /t 3600 /c 'Desligamento em 1h - BIA'; Write-BIAMessage (Get-BIAStr 'msg_shutdown_1h') Info; Invoke-BIAPause; Show-UtilsMenu }
        '3' { shutdown /s /t 7200 /c 'Desligamento em 2h - BIA'; Write-BIAMessage (Get-BIAStr 'msg_shutdown_2h') Info; Invoke-BIAPause; Show-UtilsMenu }
        '4' { shutdown /a; Write-BIAMessage (Get-BIAStr 'msg_shutdown_cancelled') Success; Invoke-BIAPause; Show-UtilsMenu }
        '5' { Invoke-DiskCleanupLight; Invoke-BIAPause; Show-UtilsMenu }
        '6' { Invoke-OptimizeVolumes; Invoke-BIAPause; Show-UtilsMenu }
        '7' { $out = Join-Path $script:WorkDir "RegBackup_$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"; reg export HKCU $out 2>$null; Write-BIAMessage "$(Get-BIAStr 'msg_backup_saved') $out" Success; Invoke-BIAPause; Show-UtilsMenu }
        '8' { Invoke-StartRemoteTool; Show-UtilsMenu }
        '9' { Write-Host "  $(Get-BIAStr 'msg_shortcuts')" -ForegroundColor $BIA_Theme.Menu; $r = (Read-Host).Trim(); if ($r -eq '1') { Start-Process notepad }; if ($r -eq '2') { Start-Process calc }; if ($r -eq '3') { Start-Process cmd }; if ($r -eq '4') { Start-Process powershell }; Show-UtilsMenu }
        'a' { Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Write-BIAMessage (Get-BIAStr 'msg_recycle_emptied') Success; Invoke-BIAPause; Show-UtilsMenu }
        'b' { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize; Invoke-BIAPause; Show-UtilsMenu }
        'c' { $c = Get-Clipboard -ErrorAction SilentlyContinue; if ($c) { $c | Out-String | ForEach-Object { Write-Host "  $_" } } else { Write-Host "  $(Get-BIAStr 'msg_clipboard_empty')" }; Invoke-BIAPause; Show-UtilsMenu }
        'd' { $f = (Read-Host (Get-BIAStr 'msg_path_prompt')).Trim(); if ($f -and (Test-Path $f)) { Get-FileHash -Path $f -Algorithm SHA256 | Format-List } else { Write-BIAMessage (Get-BIAStr 'msg_file_not_found') Warning }; Invoke-BIAPause; Show-UtilsMenu }
        'e' { $desk = [Environment]::GetFolderPath('Desktop'); Push-Location $desk; powercfg /batteryreport 2>$null; Pop-Location; $out = Join-Path $desk 'battery-report.html'; if (Test-Path $out) { Start-Process $out; Write-BIAMessage "$(Get-BIAStr 'msg_report_saved') $out" Success } else { Write-BIAMessage (Get-BIAStr 'msg_report_generated') Info }; Invoke-BIAPause; Show-UtilsMenu }
        'f' { Show-BIAWindowsActivation; Invoke-BIAPause; Show-UtilsMenu }
        'g' { Write-Host (Get-BIAStr 'msg_panels_menu') -ForegroundColor $BIA_Theme.Menu; $r = (Read-Host).Trim(); if ($r -eq '1') { Start-Process appwiz.cpl }; if ($r -eq '2') { Start-Process ncpa.cpl }; if ($r -eq '3') { Start-Process powercfg.cpl }; if ($r -eq '4') { Start-Process mmsys.cpl }; if ($r -eq '5') { Start-Process timedate.cpl }; if ($r -eq '6') { Start-Process 'control.exe' -ArgumentList '/name', 'Microsoft.CredentialManager' }; Show-UtilsMenu }
        'h' { Invoke-BIAPerformanceOptions; Show-UtilsMenu }
        '0' { Show-MainMenu }
        default { Show-UtilsMenu }
    }
}

function Invoke-BIAPerformanceOptions {
    Write-Host ''
    Write-Host (Get-BIAStr 'perf_1') -ForegroundColor $BIA_Theme.Menu
    Write-Host (Get-BIAStr 'perf_2') -ForegroundColor $BIA_Theme.Menu
    Write-Host (Get-BIAStr 'perf_3') -ForegroundColor $BIA_Theme.Menu
    Write-Host (Get-BIAStr 'perf_0') -ForegroundColor $BIA_Theme.Menu
    Write-Host ''
    $r = (Read-Host "  $(Get-BIAStr 'msg_prompt_choice')").Trim()
    if ($r -eq '1') {
        $perf = "$env:SystemRoot\System32\systempropertiesperformance.exe"
        if (Test-Path $perf) { Start-Process $perf; Write-BIAMessage (Get-BIAStr 'msg_perf_open') Info }
        else {
            Start-Process 'control.exe' -ArgumentList 'sysdm.cpl,,3'
            Write-BIAMessage (Get-BIAStr 'msg_perf_advanced') Info
        }
        return
    }
    if ($r -eq '2') {
        try {
            $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
            if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
            Set-ItemProperty -Path $key -Name 'VisualFXSetting' -Value 1 -Type DWord -Force -ErrorAction Stop
            $desk = 'HKCU:\Control Panel\Desktop'
            $maskAppearance = [byte[]](0x9E, 0x3E, 0x07, 0x80, 0x12, 0x00, 0x00, 0x00)
            Set-ItemProperty -Path $desk -Name 'UserPreferencesMask' -Value $maskAppearance -Type Binary -Force -ErrorAction SilentlyContinue
            Write-BIAMessage (Get-BIAStr 'msg_perf_appearance_ok') Success
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; Start-Process explorer
        } catch {
            Write-BIAMessage (Get-BIAStr 'msg_perf_failed') Warning
        }
        Invoke-BIAPause
        return
    }
    if ($r -eq '3') {
        try {
            $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
            if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
            Set-ItemProperty -Path $key -Name 'VisualFXSetting' -Value 2 -Type DWord -Force -ErrorAction Stop
            $desk = 'HKCU:\Control Panel\Desktop'
            $maskPerformance = [byte[]](0x9E, 0x12, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00)
            Set-ItemProperty -Path $desk -Name 'UserPreferencesMask' -Value $maskPerformance -Type Binary -Force -ErrorAction SilentlyContinue
            Write-BIAMessage (Get-BIAStr 'msg_perf_performance_ok') Success
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; Start-Process explorer
        } catch {
            Write-BIAMessage (Get-BIAStr 'msg_perf_failed') Warning
        }
        Invoke-BIAPause
        return
    }
}

function Invoke-StartRemoteTool {
    $tv = Get-ChildItem -Path 'C:\Program Files\TeamViewer\TeamViewer.exe', 'C:\Program Files (x86)\TeamViewer\TeamViewer.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    $ad = Get-ChildItem -Path 'C:\Program Files (x86)\AnyDesk\AnyDesk.exe', 'C:\Program Files\AnyDesk\AnyDesk.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($tv) { Start-Process $tv.FullName; Write-BIAMessage (Get-BIAStr 'msg_teamviewer') Success }
    elseif ($ad) { Start-Process $ad.FullName; Write-BIAMessage (Get-BIAStr 'msg_anydesk') Success }
    else { Write-BIAMessage (Get-BIAStr 'msg_remote_na') Warning }
}

function Invoke-DiskCleanupLight {
    Write-BIAMessage (Get-BIAStr 'msg_cleanup_prefetch') Info
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_prefetch') -TotalSteps 5
    Remove-Item -Path 'C:\Windows\Prefetch\*' -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_font_cache') -TotalSteps 3
    Remove-Item -Path "$env:LOCALAPPDATA\FontCache\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAMessage (Get-BIAStr 'msg_disk_cleanup_done') Success
}

function Invoke-OptimizeVolumes {
    Write-BIAMessage (Get-BIAStr 'msg_optimizing') Info
    $vols = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter }
    if (-not $vols) { Write-BIAMessage (Get-BIAStr 'msg_done') Warning; return }
    foreach ($v in $vols) {
        Write-BIAProgressBar -Message "Otimizando $($v.DriveLetter):" -TotalSteps 8
        try { Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim -ErrorAction Stop } catch { Write-BIAMessage "Pulando $($v.DriveLetter): $_" Warning }
    }
    Write-BIAMessage (Get-BIAStr 'msg_optimize_done') Success
}

function Show-BIAWindowsActivation {
    $statusText = @{
        0 = (Get-BIAStr 'msg_activation_unlicensed')
        1 = (Get-BIAStr 'msg_activation_licensed')
        2 = 'Periodo de graca (OOB)'
        3 = 'Periodo de tolerancia'
        4 = 'Periodo de graca (nao genuino)'
        5 = 'Notificacao'
        6 = 'Periodo de graca estendido'
    }
    try {
        $products = Get-CimInstance -Namespace root/SoftwareLicensing -ClassName SoftwareLicensingProduct -ErrorAction Stop |
            Where-Object { $_.ApplicationId -match '55c92734-d682-4d71-983e-d6ec3f' -and $_.Description -match 'Windows' }
        if (-not $products) {
            $products = Get-CimInstance -Namespace root/SoftwareLicensing -ClassName SoftwareLicensingProduct -ErrorAction Stop |
                Where-Object { $_.Description -like '*Windows*' } | Select-Object -First 5
        }
        if ($products) {
            foreach ($p in $products) {
                $desc = $p.Description
                $code = [int]$p.LicenseStatus
                $text = $statusText[$code]
                if ($null -eq $text) { $text = "Codigo $code" }
                Write-Host "  Produto: $desc" -ForegroundColor $BIA_Theme.Menu
                $color = if ($code -eq 1) { $BIA_Theme.Success } else { $BIA_Theme.Warning }
                Write-Host "  Status:  $text" -ForegroundColor $color
                Write-Host ''
            }
            return
        }
    } catch { }
    Write-BIAMessage (Get-BIAStr 'msg_activation_checking') Info
    $slmgr = "$env:SystemRoot\System32\slmgr.vbs"
    if (Test-Path $slmgr) {
        & cscript //nologo $slmgr /dli 2>&1 | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-BIAMessage (Get-BIAStr 'msg_activation_failed') Warning
    }
}

# ---------- PLAYBOOKS ----------
function Show-PlaybooksMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'play_subtitle') -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        (Get-BIAStr 'play_1'), (Get-BIAStr 'play_2'), (Get-BIAStr 'play_3'), (Get-BIAStr 'play_4'), (Get-BIAStr 'play_5'),
        (Get-BIAStr 'play_0')
    )
    $op = (Read-Host "  $(Get-BIAStr 'choice')").Trim()
    switch ($op) {
        '1' { Invoke-PlaybookSlow; Invoke-BIAPause; Show-PlaybooksMenu }
        '2' { Invoke-PlaybookNet; Invoke-BIAPause; Show-PlaybooksMenu }
        '3' { Invoke-PlaybookPrint; Invoke-BIAPause; Show-PlaybooksMenu }
        '4' { Invoke-PlaybookNoSound; Invoke-BIAPause; Show-PlaybooksMenu }
        '5' { Invoke-PlaybookRebootCheck; Invoke-BIAPause; Show-PlaybooksMenu }
        '0' { Show-MainMenu }
        default { Show-PlaybooksMenu }
    }
}

function Invoke-PlaybookNoSound {
    Write-BIAMessage 'Verificando audio (dispositivo, servico, volume)...' Info
    Write-BIAProgressBar -Message 'Servico Windows Audio (Audiosrv)' -TotalSteps 4
    $aud = Get-Service -Name Audiosrv -ErrorAction SilentlyContinue
    if ($aud) {
        $st = $aud.Status.ToString()
        Write-Host "    Audiosrv: $st" -ForegroundColor $(if ($aud.Status -eq 'Running') { 'Green' } else { 'Yellow' })
        if ($aud.Status -ne 'Running') {
            Write-BIAMessage 'Iniciando servico de audio...' Info
            Start-Service -Name Audiosrv -ErrorAction SilentlyContinue
        }
    } else { Write-Host '    Audiosrv: N/A' -ForegroundColor DarkGray }
    Write-BIAProgressBar -Message 'Dispositivos de audio' -TotalSteps 4
    Get-WmiObject Win32_SoundDevice -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $($_.Name)" -ForegroundColor $BIA_Theme.Menu }
    Write-BIAMessage (Get-BIAStr 'som_verificar') Info
    Write-BIAMessage (Get-BIAStr 'som_concluido') Success
}

function Invoke-PlaybookRebootCheck {
    Write-BIAMessage 'Verificando pendencia de reinicio e uptime...' Info
    $reboot = $false
    try {
        $null = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop
        $reboot = $true
    } catch { }
    if (-not $reboot) {
        try {
            $null = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop
            $reboot = $true
        } catch { }
    }
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    $uptimeStr = 'N/A'
    if ($os) {
        $boot = $os.ConvertToDateTime($os.LastBootUpTime)
        $uptime = (Get-Date) - $boot
        $uptimeStr = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
        Write-Host "  Ligado desde: $boot" -ForegroundColor $BIA_Theme.Menu
        Write-Host "  Uptime: $uptimeStr" -ForegroundColor $BIA_Theme.Success
    }
    Write-Host ''
    if ($reboot) { Write-BIAMessage (Get-BIAStr 'pendencia_sim') Warning }
    else { Write-BIAMessage (Get-BIAStr 'pendencia_nao') Success }
    Write-BIAMessage ((Get-BIAStr 'uptime_atual') -f $uptimeStr) Info
}

function Invoke-PlaybookSlow {
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_cleaning_temp') -TotalSteps 5
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_cleaning_wintemp') -TotalSteps 5
    Remove-Item -Path 'C:\Windows\Temp\*' -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_flush_dns') -TotalSteps 3
    ipconfig /flushdns 2>$null
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_release_renew') -TotalSteps 6
    ipconfig /release 2>$null; ipconfig /renew 2>$null
    Write-BIAMessage (Get-BIAStr 'msg_pc_optimized') Success
}

function Invoke-PlaybookNet {
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_reset_winsock') -TotalSteps 3
    netsh winsock reset 2>$null
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_reset_ip') -TotalSteps 3
    netsh int ip reset 2>$null
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_flush_dns') -TotalSteps 2
    ipconfig /flushdns 2>$null
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_release_renew') -TotalSteps 4
    ipconfig /release 2>$null; ipconfig /renew 2>$null
    Write-BIAMessage (Get-BIAStr 'msg_net_reset') Success
}

function Invoke-PlaybookPrint {
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_stopping_spooler') -TotalSteps 3
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_clearing_queue') -TotalSteps 4
    Remove-Item -Path 'C:\Windows\System32\spool\PRINTERS\*' -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message (Get-BIAStr 'msg_starting_spooler') -TotalSteps 3
    Start-Service -Name Spooler -ErrorAction SilentlyContinue
    Write-BIAMessage (Get-BIAStr 'msg_spool_cleaned') Success
}

# ---------- SYS INFO ----------
function Show-SysInfoMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'sysinfo_subtitle') -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        (Get-BIAStr 'sysinfo_1'), (Get-BIAStr 'sysinfo_2'), (Get-BIAStr 'sysinfo_3'), (Get-BIAStr 'sysinfo_4'),
        (Get-BIAStr 'sysinfo_5'), (Get-BIAStr 'sysinfo_0')
    )
    $op = (Read-Host "  $(Get-BIAStr 'choice')").Trim()
    switch ($op) {
        '1' { Show-BIALoadingShort -Message (Get-BIAStr 'msg_collecting') -Steps 12; Show-SysSummary; Invoke-BIAPause; Show-SysInfoMenu }
        '2' { Export-SysInfo; Invoke-BIAPause; Show-SysInfoMenu }
        '3' { Show-SysUptime; Invoke-BIAPause; Show-SysInfoMenu }
        '4' { Show-BIALoadingShort -Message (Get-BIAStr 'msg_updating') -Steps 6; Show-BIAWelcomeDashboard; Invoke-BIAPause; Show-SysInfoMenu }
        '5' { Export-BIAOnePageSummary; Invoke-BIAPause; Show-SysInfoMenu }
        '0' { Show-MainMenu }
        default { Show-SysInfoMenu }
    }
}

function Export-BIAOnePageSummary {
    $data = Get-BIAWelcomeData
    $reboot = $false
    try { $null = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop; $reboot = $true } catch { }
    if (-not $reboot) { try { $null = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop; $reboot = $true } catch { } }
    $rebootStr = if ($reboot) { (Get-BIAStr 'yes_str') } else { (Get-BIAStr 'no_str') }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $out = Join-Path $script:WorkDir "Resumo_${env:COMPUTERNAME}_$stamp.txt"
    $lblReboot = Get-BIAStr 'msg_reboot_pending'
    $lines = @(
        "=== BIA Resumo - $env:COMPUTERNAME - $stamp ===",
        "$(Get-BIAStr 'lbl_user'): $($data['Usuario'])",
        "$(Get-BIAStr 'lbl_computer'): $($data['Computador'])",
        "$(Get-BIAStr 'lbl_domain'): $($data['Dominio AD'])",
        "$(Get-BIAStr 'lbl_os'): $($data['SO'])",
        "$(Get-BIAStr 'lbl_version'): $($data['Versao'])",
        "$(Get-BIAStr 'lbl_uptime'): $($data['Uptime'])",
        "$(Get-BIAStr 'lbl_manufacturer'): $($data['Fabricante'])",
        "$(Get-BIAStr 'lbl_model'): $($data['Modelo'])",
        "$(Get-BIAStr 'lbl_ram'): $($data['RAM'])",
        "$(Get-BIAStr 'lbl_disk'): $($data['Disco'])",
        "$(Get-BIAStr 'lbl_ip'): $($data['IP(s)'])",
        "${lblReboot}: $rebootStr",
        "$(Get-BIAStr 'lbl_datetime'): $($data['Data/Hora'])",
        "=== Fim ==="
    )
    $lines | Out-File -FilePath $out -Encoding utf8
    Write-BIAMessage ((Get-BIAStr 'resumo_salvo') -f $out) Success
}

function Show-SysSummary {
    Write-Host ' ----------------- SISTEMA -----------------' -ForegroundColor Cyan
    Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object Caption, Version, BuildNumber, OSArchitecture | Format-List
    Write-Host ' ----------------- HARDWARE ----------------' -ForegroundColor Cyan
    Get-WmiObject Win32_ComputerSystemProduct -ErrorAction SilentlyContinue | Select-Object Name, IdentifyingNumber | Format-List
    Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | Format-List
    Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object Manufacturer, Model, @{N='RAM_GB';E={[math]::Round($_.TotalPhysicalMemory/1GB,2)}} | Format-List
    Write-Host ' ----------------- ARMAZENAMENTO -----------' -ForegroundColor Cyan
    Get-WmiObject Win32_LogicalDisk -ErrorAction SilentlyContinue | Select-Object Name, FileSystem, @{N='Size_GB';E={[math]::Round($_.Size/1GB,2)}}, @{N='Free_GB';E={[math]::Round($_.FreeSpace/1GB,2)}}, VolumeName | Format-Table -AutoSize
    Write-Host ' ----------------- REDE --------------------' -ForegroundColor Cyan
    try {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } | Format-Table InterfaceAlias, IPAddress -AutoSize
    } catch {
        ipconfig | Select-String -Pattern 'IPv4|Adaptador'
    }
    Write-Host ' ----------------- BIOS/BOARD --------------' -ForegroundColor Cyan
    Get-WmiObject Win32_BIOS -ErrorAction SilentlyContinue | Select-Object SMBIOSBIOSVersion, ReleaseDate, Manufacturer | Format-List
    Get-WmiObject Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object Manufacturer, Product, SerialNumber | Format-List
}

function Show-SysUptime {
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $os) { Write-BIAMessage 'WMI indisponivel.' Warning; return }
    $boot = $os.ConvertToDateTime($os.LastBootUpTime)
    $uptime = (Get-Date) - $boot
    Write-Host "  Ligado desde: $boot" -ForegroundColor $BIA_Theme.Menu
    Write-Host "  Uptime: $($uptime.Days) dias, $($uptime.Hours)h $($uptime.Minutes)m" -ForegroundColor $BIA_Theme.Success
}

function Export-SysInfo {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $out = Join-Path $script:WorkDir "SysInfo_${env:COMPUTERNAME}_$stamp.txt"
    Write-BIAMessage "Gerando: $out" Info
    Write-BIAProgressBar -Message 'Coletando SYSTEMINFO' -TotalSteps 6
    $content = @(
        "====== BIA SysInfo - $env:COMPUTERNAME - $stamp ======",
        (systeminfo 2>$null),
        "`n====== OS ======",
        (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue | Format-List * | Out-String),
        "`n====== COMPUTERSYSTEM ======",
        (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue | Format-List * | Out-String),
        "`n====== CPU ======",
        (Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue | Format-List Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | Out-String),
        "`n====== MEMORIA ======",
        (Get-WmiObject Win32_PhysicalMemory -ErrorAction SilentlyContinue | Format-List * | Out-String),
        "`n====== DISK ======",
        (Get-WmiObject Win32_DiskDrive -ErrorAction SilentlyContinue | Format-List Model, InterfaceType, Size, SerialNumber | Out-String),
        "`n====== LOGICALDISK ======",
        (Get-WmiObject Win32_LogicalDisk -ErrorAction SilentlyContinue | Format-List * | Out-String),
        "`n====== REDE ======",
        (ipconfig /all),
        "`n====== BIOS ======",
        (Get-WmiObject Win32_BIOS -ErrorAction SilentlyContinue | Format-List * | Out-String),
        "`n====== BASEBOARD ======",
        (Get-WmiObject Win32_BaseBoard -ErrorAction SilentlyContinue | Format-List * | Out-String)
    )
    $content | Out-File -FilePath $out -Encoding utf8
    Write-BIAMessage "Pacote gerado: $out" Success
}

# ---------- DIAGNOSTICO RAPIDO (Health) ----------
function Show-HealthMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'title_health') -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] Executar diagnostico completo',
        '  [2] Eventos de erro (ultimas 24h)',
        '  [3] Teste de conectividade (multi-host)',
        '  [4] Espaco em disco + memoria',
        '  [0] Voltar'
    )
    $op = (Read-Host "  $(Get-BIAStr 'msg_prompt_choice')").Trim()
    switch ($op) {
        '1' { Invoke-HealthCheckFull; Invoke-BIAPause; Show-HealthMenu }
        '2' { Show-RecentErrors; Invoke-BIAPause; Show-HealthMenu }
        '3' { Invoke-ConnectivityTest; Invoke-BIAPause; Show-HealthMenu }
        '4' { Show-HealthDiskMem; Invoke-BIAPause; Show-HealthMenu }
        '0' { Show-MainMenu }
        default { Show-HealthMenu }
    }
}

function Invoke-HealthCheckFull {
    Write-BIAMessage (Get-BIAStr 'health_start') Info
    Write-BIAProgressBar -Message (Get-BIAStr 'health_disk') -TotalSteps 5
    $vols = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    foreach ($v in $vols) {
        $freePct = if ($v.Size -gt 0) { [math]::Round(($v.FreeSpace / $v.Size) * 100, 1) } else { 0 }
        $status = if ($freePct -lt 10) { (Get-BIAStr 'health_critical') } elseif ($freePct -lt 20) { (Get-BIAStr 'health_warning') } else { (Get-BIAStr 'health_ok') }
        Write-Host "    $($v.DeviceID) $(Get-BIAStr 'health_free'): $freePct% - $status" -ForegroundColor $(if ($freePct -lt 10) { 'Red' } elseif ($freePct -lt 20) { 'Yellow' } else { 'Green' })
    }
    Write-BIAProgressBar -Message (Get-BIAStr 'health_mem') -TotalSteps 5
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        $freeMB = [math]::Round($os.FreePhysicalMemory / 1024, 0)
        $totalMB = [math]::Round($os.TotalVisibleMemorySize / 1024, 0)
        $pct = [math]::Round(($os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)
        Write-Host "    RAM: $freeMB MB $(Get-BIAStr 'disk_free_of') $totalMB MB ($pct% $(Get-BIAStr 'disk_free_pct'))" -ForegroundColor $(if ($pct -lt 15) { 'Yellow' } else { 'Green' })
    }
    Write-BIAProgressBar -Message (Get-BIAStr 'health_network') -TotalSteps 5
    $pingOk = $false
    try { $r = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction Stop; $pingOk = $r } catch { }
    Write-Host "    Internet (8.8.8.8): $(if ($pingOk) { (Get-BIAStr 'health_ok') } else { (Get-BIAStr 'health_fail') })" -ForegroundColor $(if ($pingOk) { 'Green' } else { 'Red' })
    Write-BIAProgressBar -Message (Get-BIAStr 'health_services') -TotalSteps 5
    $svcs = @('Spooler', 'Dhcp', 'Dnscache', 'Winmgmt')
    foreach ($s in $svcs) {
        $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
        $st = if ($svc) { $svc.Status.ToString() } else { 'N/A' }
        Write-Host "    $s : $st" -ForegroundColor $(if ($svc -and $svc.Status -eq 'Running') { 'Green' } else { 'DarkGray' })
    }
    Write-BIAMessage 'Diagnostico concluido.' Success
}

function Show-RecentErrors {
    Show-BIALoadingShort -Message 'Buscando eventos de erro...' -Steps 15
    $since = (Get-Date).AddHours(-24)
    try {
        $evts = Get-WinEvent -FilterHashtable @{ LogName='System'; Level=2; StartTime=$since } -MaxEvents 20 -ErrorAction Stop
        $evts | Format-Table TimeCreated, Id, ProviderName, Message -AutoSize -Wrap | Out-String
    } catch {
        try {
            $evts = Get-WinEvent -LogName System -MaxEvents 30 -ErrorAction Stop | Where-Object { $_.Level -eq 2 -and $_.TimeCreated -ge $since } | Select-Object -First 20
            $evts | Format-Table TimeCreated, Id, ProviderName, Message -AutoSize -Wrap | Out-String
        } catch { Write-BIAMessage 'Nao foi possivel ler eventos. Execute como administrador?' Warning }
    }
    Write-BIAMessage 'Ultimos erros (System, 24h).' Info
}

function Invoke-ConnectivityTest {
    $hosts = @('8.8.8.8', '1.1.1.1', 'www.google.com')
    foreach ($h in $hosts) {
        Write-Host "  Testando $h ... " -NoNewline
        try {
            $r = Test-Connection -ComputerName $h -Count 1 -Quiet -ErrorAction Stop
            Write-Host $(if ($r) { 'OK' } else { 'FALHA' }) -ForegroundColor $(if ($r) { 'Green' } else { 'Red' })
        } catch {
            Write-Host 'FALHA' -ForegroundColor Red
        }
    }
}

function Show-HealthDiskMem {
    Show-BIALoadingShort -Message 'Coletando disco e memoria...' -Steps 8
    Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue | ForEach-Object {
        $freePct = if ($_.Size -gt 0) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 1) } else { 0 }
        Write-Host "  $($_.DeviceID) $($_.VolumeName) - Livre: $freePct%" -ForegroundColor $BIA_Theme.Menu
    }
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        $freeMB = [math]::Round($os.FreePhysicalMemory / 1024, 0)
        Write-Host "  RAM livre: $freeMB MB" -ForegroundColor $BIA_Theme.Menu
    }
}

# ---------- IMPRESSORAS ----------
function Show-PrintersMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'title_printers') -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] Listar impressoras instaladas',
        '  [2] Definir impressora padrao',
        '  [3] Abrir Painel de Impressoras (Windows)',
        '  [4] Adicionar impressora (assistente)',
        '  [5] Remover impressora',
        '  [6] Imprimir pagina de teste',
        '  [7] Reiniciar servico Spooler',
        '  [8] Limpar fila de impressao (playbook)',
        '  [9] Listar trabalhos na fila',
        '  [0] Voltar'
    )
    $op = (Read-Host "  $(Get-BIAStr 'msg_prompt_choice')").Trim()
    switch ($op) {
        '1' { Show-BIALoadingShort -Message (Get-BIAStr 'msg_listing_printers') -Steps 6; Get-Printer -ErrorAction SilentlyContinue | Format-Table Name, DriverName, PortName -AutoSize; Invoke-BIAPause; Show-PrintersMenu }
        '2' { $p = (Read-Host '  Nome da impressora para definir como padrao').Trim(); if ($p) { try { Set-Printer -Name $p -Default $true -ErrorAction Stop; Write-BIAMessage "Padrao: $p" Success } catch { Write-BIAMessage "Erro: $_" Error } }; Invoke-BIAPause; Show-PrintersMenu }
        '3' { Start-Process 'control.exe' -ArgumentList 'printers'; Write-BIAMessage 'Abrindo Painel de Impressoras.' Info; Show-PrintersMenu }
        '4' { Start-Process 'rundll32.exe' -ArgumentList 'printui.dll,PrintUIEntry /il'; Write-BIAMessage 'Assistente Adicionar impressora.' Info; Invoke-BIAPause; Show-PrintersMenu }
        '5' { $p = (Read-Host '  Nome da impressora a remover').Trim(); if ($p) { try { Remove-Printer -Name $p -ErrorAction Stop; Write-BIAMessage "Impressora $p removida." Success } catch { Write-BIAMessage "Erro: $_" Error } }; Invoke-BIAPause; Show-PrintersMenu }
        '6' { $p = (Read-Host '  Nome da impressora para teste').Trim(); if ($p) { try { Import-Module PrintManagement -ErrorAction Stop; Invoke-PrinterTestPage -PrinterName $p -ErrorAction Stop; Write-BIAMessage 'Pagina de teste enviada.' Success } catch { Write-BIAMessage "Use Painel de Impressoras (opcao 3), clique com botao direito na impressora > Imprimir pagina de teste. Erro: $_" Warning } }; Invoke-BIAPause; Show-PrintersMenu }
        '7' { Write-BIAProgressBar -Message 'Reiniciando Spooler' -TotalSteps 4; Restart-Service -Name Spooler -Force -ErrorAction SilentlyContinue; Write-BIAMessage 'Spooler reiniciado.' Success; Invoke-BIAPause; Show-PrintersMenu }
        '8' { Invoke-PlaybookPrint; Invoke-BIAPause; Show-PrintersMenu }
        '9' { Get-Printer -ErrorAction SilentlyContinue | ForEach-Object { $j = Get-PrintJob -PrinterName $_.Name -ErrorAction SilentlyContinue; $c = if ($j) { $j.Count } else { 0 }; Write-Host "  $($_.Name): $c trabalho(s) na fila" -ForegroundColor $BIA_Theme.Menu }; Invoke-BIAPause; Show-PrintersMenu }
        '0' { Show-MainMenu }
        default { Show-PrintersMenu }
    }
}

# ---------- COMANDOS E FERRAMENTAS (CMD / PS) ----------
function Show-ToolsMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'title_tools') -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        (Get-BIAStr 'tools_cat_net'),
        (Get-BIAStr 'tools_1'), (Get-BIAStr 'tools_2'), (Get-BIAStr 'tools_3'), (Get-BIAStr 'tools_4'), (Get-BIAStr 'tools_5'),
        (Get-BIAStr 'tools_cat_sys'),
        (Get-BIAStr 'tools_6'), (Get-BIAStr 'tools_7'), (Get-BIAStr 'tools_8'), (Get-BIAStr 'tools_9'), (Get-BIAStr 'tools_a'),
        (Get-BIAStr 'tools_cat_sec'),
        (Get-BIAStr 'tools_b'), (Get-BIAStr 'tools_c'), (Get-BIAStr 'tools_d'), (Get-BIAStr 'tools_e'), (Get-BIAStr 'tools_f'),
        (Get-BIAStr 'tools_cat_files'),
        (Get-BIAStr 'tools_g'), (Get-BIAStr 'tools_h'), (Get-BIAStr 'tools_i'),
        (Get-BIAStr 'tools_cat_shortcuts'),
        (Get-BIAStr 'tools_j'),
        (Get-BIAStr 'tools_cat_other'),
        (Get-BIAStr 'tools_k'), (Get-BIAStr 'tools_l'), (Get-BIAStr 'tools_m'), (Get-BIAStr 'tools_n'), (Get-BIAStr 'tools_o'),
        (Get-BIAStr 'tools_0')
    )
    $op = (Read-Host "  $(Get-BIAStr 'msg_prompt_choice')").Trim().ToLower()
    switch ($op) {
        '1' { $h = (Read-Host (Get-BIAStr 'msg_dns_query_prompt')).Trim(); if ($h) { nslookup $h }; Invoke-BIAPause; Show-ToolsMenu }
        '2' { $target = (Read-Host (Get-BIAStr 'msg_host_port')).Trim(); $portStr = (Read-Host (Get-BIAStr 'msg_port_enter')).Trim(); if ($target) { $p = 0; if ($portStr -and [int]::TryParse($portStr, [ref]$p) -and $p -gt 0) { Test-NetConnection -ComputerName $target -Port $p } else { Test-NetConnection -ComputerName $target } }; Invoke-BIAPause; Show-ToolsMenu }
        '3' { route print; Invoke-BIAPause; Show-ToolsMenu }
        '4' { arp -a; Invoke-BIAPause; Show-ToolsMenu }
        '5' { ipconfig /displaydns | More; Invoke-BIAPause; Show-ToolsMenu }
        '6' { whoami /all | More; Invoke-BIAPause; Show-ToolsMenu }
        '7' { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize; Invoke-BIAPause; Show-ToolsMenu }
        '8' { Get-ScheduledTask | Where-Object State -eq Ready | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize; Invoke-BIAPause; Show-ToolsMenu }
        '9' { Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name, Command, Location | Format-Table -AutoSize -Wrap; Invoke-BIAPause; Show-ToolsMenu }
        'a' { $key = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue; $win = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue; if ($key -or $win) { Write-BIAMessage (Get-BIAStr 'msg_reboot_pending_detect') Warning } else { Write-BIAMessage (Get-BIAStr 'msg_no_reboot_pending_detect') Success }; Invoke-BIAPause; Show-ToolsMenu }
        'b' { try { $mp = Get-MpComputerStatus -ErrorAction Stop; Write-Host '  Defender: ' -NoNewline; Write-Host $mp.AntivirusEnabled -ForegroundColor $(if ($mp.AntivirusEnabled) { 'Green' } else { 'Yellow' }); Write-Host "  $(Get-BIAStr 'msg_last_scan'): " -NoNewline; Write-Host $mp.QuickScanStartTime; $r = (Read-Host (Get-BIAStr 'msg_defender_scan_confirm')).Trim().ToLower(); if ($r -eq 's' -or $r -eq 'y') { Start-MpScan -ScanType Quick; Write-BIAMessage (Get-BIAStr 'msg_scan_started') Success } } catch { Write-BIAMessage (Get-BIAStr 'msg_defender_na_short') Warning }; Invoke-BIAPause; Show-ToolsMenu }
        'c' { Write-BIAMessage (Get-BIAStr 'msg_dism_warn') Warning; if ((Read-Host (Get-BIAStr 'msg_continue_yn')).Trim().ToLower() -match '^[sy]') { DISM /Online /Cleanup-Image /RestoreHealth }; Invoke-BIAPause; Show-ToolsMenu }
        'd' { $desk = [Environment]::GetFolderPath('Desktop'); Push-Location $desk; powercfg /batteryreport 2>$null; Pop-Location; $out = Join-Path $desk 'battery-report.html'; if (Test-Path $out) { Write-BIAMessage "$(Get-BIAStr 'msg_report_saved') $out" Success; Start-Process $out } else { Write-BIAMessage (Get-BIAStr 'msg_report_generated') Info }; Invoke-BIAPause; Show-ToolsMenu }
        'e' { Show-BIAWindowsActivation; Invoke-BIAPause; Show-ToolsMenu }
        'f' { Start-Process 'perfmon' -ArgumentList '/rel'; Write-BIAMessage (Get-BIAStr 'msg_opening_reliability_short') Info; Show-ToolsMenu }
        'g' { $c = Get-Clipboard -ErrorAction SilentlyContinue; if ($c) { Write-Host "  Clipboard ($($c.GetType().Name)): " -ForegroundColor $BIA_Theme.Menu; $c | Out-String | ForEach-Object { Write-Host "  $_" } } else { Write-Host "  $(Get-BIAStr 'msg_clipboard_empty')" }; Invoke-BIAPause; Show-ToolsMenu }
        'h' { $f = (Read-Host (Get-BIAStr 'msg_path_prompt')).Trim(); if ($f -and (Test-Path $f)) { Get-FileHash -Path $f -Algorithm SHA256 | Format-List } else { Write-BIAMessage (Get-BIAStr 'msg_file_not_found') Warning }; Invoke-BIAPause; Show-ToolsMenu }
        'i' { Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Write-BIAMessage (Get-BIAStr 'msg_recycle_emptied') Success; Invoke-BIAPause; Show-ToolsMenu }
        'j' { Write-Host (Get-BIAStr 'msg_panels_menu') -ForegroundColor $BIA_Theme.Menu; $r = (Read-Host).Trim(); if ($r -eq '1') { Start-Process appwiz.cpl }; if ($r -eq '2') { Start-Process ncpa.cpl }; if ($r -eq '3') { Start-Process powercfg.cpl }; if ($r -eq '4') { Start-Process mmsys.cpl }; if ($r -eq '5') { Start-Process timedate.cpl }; if ($r -eq '6') { Start-Process 'control.exe' -ArgumentList '/name', 'Microsoft.CredentialManager' }; Show-ToolsMenu }
        'k' { net share; Invoke-BIAPause; Show-ToolsMenu }
        'l' { net user; Invoke-BIAPause; Show-ToolsMenu }
        'm' { Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class PInvoke { [DllImport("user32.dll")] public static extern void LockWorkStation(); }'; [PInvoke]::LockWorkStation(); Write-BIAMessage (Get-BIAStr 'msg_station_locked') Info; Start-Sleep -Seconds 2; Show-ToolsMenu }
        'n' { $port = (Read-Host (Get-BIAStr 'msg_port_number')).Trim(); if ($port) { $conn = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 5; if ($conn) { $conn | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; Write-Host "  $(Get-BIAStr 'lbl_port') $port -> PID $($_.OwningProcess) -> $($p.ProcessName)" } } else { Write-Host (Get-BIAStr 'msg_no_process_port') } }; Invoke-BIAPause; Show-ToolsMenu }
        'o' { & wsl --list 2>$null; if ($LASTEXITCODE -ne 0) { Write-BIAMessage (Get-BIAStr 'msg_wsl_not_installed') Warning }; Invoke-BIAPause; Show-ToolsMenu }
        '0' { Show-MainMenu }
        default { Show-ToolsMenu }
    }
}

# ---------- AZURE ----------
function Install-BIAAzModuleIfNeeded {
    $az = Get-Module -ListAvailable -Name Az -ErrorAction SilentlyContinue
    if ($az) { return $true }
    Write-BIAMessage 'Modulo Az nao encontrado. Instalando automaticamente (pode levar 1-2 min)...' Info
    try {
        Show-BIASpinner -Message 'Baixando e instalando modulo Az' -ScriptBlock {
            Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
        }
        Import-Module -Name Az -Scope Global -Force -ErrorAction SilentlyContinue
        Write-BIAMessage 'Modulo Az instalado e importado.' Success
        return $true
    } catch {
        Write-BIAMessage "Falha na instalacao: $_" Error
        return $false
    }
}

function Install-BIAAzureCLIIfNeeded {
    $azCli = Get-Command az -ErrorAction SilentlyContinue
    if ($azCli) { return $true }
    Write-BIAMessage 'Azure CLI nao encontrado. Instalando via winget...' Info
    try {
        Show-BIASpinner -Message 'Instalando Azure CLI (winget)' -ScriptBlock {
            & winget install Microsoft.AzureCLI --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
        }
        Write-BIAMessage 'Azure CLI instalado. Reinicie o BIA ou abra um novo terminal para usar.' Success
        return $false
    } catch {
        Write-BIAMessage "Falha: $_" Error
        return $false
    }
}

function Show-AzureMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'title_azure') -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] Connect-AzAccount (PowerShell Az - login)',
        '  [2] Ver contexto Az (Get-AzContext)',
        '  [3] az login (Azure CLI)',
        '  [4] az account show (Azure CLI)',
        '  [5] Instalar modulo Az (PowerShell)',
        '  [6] Instalar Azure CLI (winget)',
        '  [0] Voltar'
    )
    $op = (Read-Host "  $(Get-BIAStr 'msg_prompt_choice')").Trim()
    switch ($op) {
        '1' {
            if (Install-BIAAzModuleIfNeeded) {
                try { Connect-AzAccount -ErrorAction Stop; Show-BIAAgentSuccess 'Login no Azure concluido.' } catch { Write-BIAMessage "Erro ao conectar: $_" Error }
            }
            Invoke-BIAPause; Show-AzureMenu
        }
        '2' {
            if (Install-BIAAzModuleIfNeeded) { try { Get-AzContext -ErrorAction Stop | Format-List } catch { Write-Host '  Nao conectado. Use opcao 1 para fazer login.' -ForegroundColor $BIA_Theme.Warning } }
            Invoke-BIAPause; Show-AzureMenu
        }
        '3' {
            if (-not (Get-Command az -ErrorAction SilentlyContinue)) { Install-BIAAzureCLIIfNeeded | Out-Null }
            if (Get-Command az -ErrorAction SilentlyContinue) { & az login 2>&1; Show-BIAAgentSuccess 'Azure CLI login executado.' } else { Write-BIAMessage 'Azure CLI ainda nao disponivel. Reinicie o BIA apos a instalacao.' Warning }
            Invoke-BIAPause; Show-AzureMenu
        }
        '4' {
            if (-not (Get-Command az -ErrorAction SilentlyContinue)) { Install-BIAAzureCLIIfNeeded | Out-Null }
            if (Get-Command az -ErrorAction SilentlyContinue) { & az account show 2>&1 } else { Write-Host '  Azure CLI nao instalado ou nao conectado.' -ForegroundColor $BIA_Theme.Warning }
            Invoke-BIAPause; Show-AzureMenu
        }
        '5' { if (Install-BIAAzModuleIfNeeded) { Show-BIAAgentSuccess 'Modulo Az pronto para uso.' }; Invoke-BIAPause; Show-AzureMenu }
        '6' { Install-BIAAzureCLIIfNeeded | Out-Null; Invoke-BIAPause; Show-AzureMenu }
        '0' { Show-MainMenu }
        default { Show-AzureMenu }
    }
}

# ---------- INSTALAR APLICATIVOS (winget) ----------
$script:BIA_WingetApps = @(
    @{ Id = '7zip.7zip'; Name = '7-Zip' },
    @{ Id = 'Google.Chrome'; Name = 'Google Chrome' },
    @{ Id = 'Mozilla.Firefox'; Name = 'Firefox' },
    @{ Id = 'Microsoft.Edge'; Name = 'Microsoft Edge' },
    @{ Id = 'Notepad++.Notepad++'; Name = 'Notepad++' },
    @{ Id = 'VideoLAN.VLC'; Name = 'VLC' },
    @{ Id = 'Git.Git'; Name = 'Git' },
    @{ Id = 'Microsoft.VisualStudioCode'; Name = 'VS Code' },
    @{ Id = 'Microsoft.PowerShell'; Name = 'PowerShell 7' },
    @{ Id = 'Microsoft.AzureCLI'; Name = 'Azure CLI' },
    @{ Id = 'Microsoft.WindowsTerminal'; Name = 'Windows Terminal' },
    @{ Id = 'PuTTY.PuTTY'; Name = 'PuTTY' },
    @{ Id = 'WinSCP.WinSCP'; Name = 'WinSCP' },
    @{ Id = 'Oracle.JavaRuntimeEnvironment'; Name = 'Java JRE' },
    @{ Id = 'Python.Python.3.12'; Name = 'Python 3.12' },
    @{ Id = 'OpenJS.NodeJS.LTS'; Name = 'Node.js LTS' },
    @{ Id = 'Microsoft.Teams'; Name = 'Microsoft Teams' },
    @{ Id = 'Zoom.Zoom'; Name = 'Zoom' },
    @{ Id = 'SlackTechnologies.Slack'; Name = 'Slack' },
    @{ Id = 'Discord.Discord'; Name = 'Discord' },
    @{ Id = 'Microsoft.Skype'; Name = 'Skype' },
    @{ Id = 'Telegram.TelegramDesktop'; Name = 'Telegram' },
    @{ Id = 'Adobe.Acrobat.Reader.64-bit'; Name = 'Adobe Acrobat Reader' },
    @{ Id = 'Postman.Postman'; Name = 'Postman' },
    @{ Id = 'Docker.DockerDesktop'; Name = 'Docker Desktop' },
    @{ Id = 'Spotify.Spotify'; Name = 'Spotify' },
    @{ Id = 'KeePassXCTeam.KeePassXC'; Name = 'KeePassXC' },
    @{ Id = 'OBSProject.OBSStudio'; Name = 'OBS Studio' },
    @{ Id = 'Microsoft.OneDrive'; Name = 'OneDrive' },
    @{ Id = 'Microsoft.Office'; Name = 'Microsoft 365' },
    @{ Id = 'Anaconda.Miniconda3'; Name = 'Miniconda' },
    @{ Id = 'Microsoft.SQLServerManagementStudio'; Name = 'SSMS' }
)
function Show-InstallAppsMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle (Get-BIAStr 'title_install') -IP $script:BIA_PrimaryIP
    $lines = @()
    for ($i = 0; $i -lt $script:BIA_WingetApps.Count; $i++) {
        $lines += "  [$($i+1)] $($script:BIA_WingetApps[$i].Name)"
    }
    $lines += '  [0] Voltar'
    Write-BIABox -Lines $lines
    $op = (Read-Host '  Numero do app (ou 0 voltar)').Trim()
    if ($op -eq '0') { Show-MainMenu; return }
    $num = 0
    [int]::TryParse($op, [ref]$num) | Out-Null
    if ($num -ge 1 -and $num -le $script:BIA_WingetApps.Count) {
        $app = $script:BIA_WingetApps[$num - 1]
        Write-BIAMessage "Instalando $($app.Name) ($($app.Id))..." Info
        & winget install $app.Id --accept-package-agreements --accept-source-agreements 2>&1
        Show-BIAAgentSuccess "Instalacao de $($app.Name) finalizada. Confira as mensagens acima."
    }
    Invoke-BIAPause
    Show-InstallAppsMenu
}

# ---------- SAIDA ----------
function Exit-BIA {
    Write-BIAHeader -IP $script:BIA_PrimaryIP
    $farewells = @('farewell_1','farewell_2','farewell_3','farewell_4','farewell_5')
    $farewell = Get-BIAStr $farewells[(Get-Random -Maximum 5)]
    $pad = [Math]::Max(0, ($ScreenWidth - $farewell.Length - 4) / 2)
    Write-Host ''
    Write-Host (' ' * [int]$pad) -NoNewline
    Show-BIATyping -Text "[ BIA ] $farewell" -DelayMs 35 -Color Success
    Write-Host ''
    $cred = Get-BIAStr 'credits'
    $pad2 = [Math]::Max(0, ($ScreenWidth - $cred.Length) / 2)
    Write-Host (' ' * [int]$pad2) -NoNewline
    Show-BIATyping -Text $cred -DelayMs 15 -Color Muted
    Write-Host ''
    if ($env:BIA_DEBUG -eq '1') {
        Write-Host (' ' * [int]$pad) -NoNewline
        Write-Host (Get-BIAStr 'msg_debug_prompt') -ForegroundColor $BIA_Theme.Muted
        Read-Host
    }
    exit 0
}

# ========== INICIO ==========
$script:BIA_PrimaryIP = Get-BIAPrimaryIP
try { Show-BIASplash } catch { Write-BIAHeader -IP $script:BIA_PrimaryIP }
Write-BIAHeader -IP $script:BIA_PrimaryIP
try { Invoke-BIAVersionCheck } catch { }
Show-BIALoadingShort -Message (Get-BIAStr 'collecting') -Steps 10
Show-BIAWelcomeDashboard
Write-Host ''
$saudacao = Get-BIAGreeting
$nome = $env:USERNAME
$pad = [Math]::Max(0, ($ScreenWidth - ($saudacao.Length + $nome.Length + 4)) / 2)
Write-Host (' ' * [int]$pad) -NoNewline
Show-BIATyping -Text "$saudacao, " -DelayMs 40 -NoNewline -Color Title
Write-Host $nome -NoNewline -ForegroundColor $BIA_Theme.Success
Show-BIATyping -Text '!' -DelayMs 80
Write-Host ''
$pad2 = [Math]::Max(0, ($ScreenWidth - 42) / 2)
Write-Host (' ' * [int]$pad2) -NoNewline
Show-BIATyping -Text (Get-BIAStr 'help_prompt') -DelayMs 25 -NoNewline -Color Accent
Write-Host ''
Read-Host
Show-MainMenu
