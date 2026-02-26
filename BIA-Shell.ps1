#Requires -Version 5.1
# BIA Shell v8 - CoreSafe (PowerShell)
# Animacoes, transicoes, novas funcionalidades, loading em telas

$ErrorActionPreference = 'Continue'
$script:WorkDir = Join-Path $env:TEMP 'BIA'
$script:LogFile = Join-Path $script:WorkDir 'BIA_Acoes.log'
if (-not (Test-Path $script:WorkDir)) { New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null }

$uiPath = Join-Path $PSScriptRoot 'BIA-UI.ps1'
if (Test-Path $uiPath) { . $uiPath }
try { Invoke-BIAMaximizeWindow } catch { }

function Write-BIALog {
    param([string]$Msg)
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$stamp | $Msg" | Out-File -FilePath $script:LogFile -Append -Encoding utf8
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
    if ($env:USERDNSDOMAIN) { $h['Dominio AD'] = $env:USERDNSDOMAIN } else { $h['Dominio AD'] = '(grupo de trabalho / sem AD)' }
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
        $h['RAM'] = "Total: ${totalGB} GB  |  Livre: ${freeGB} GB  |  Em uso: ${usedGB} GB"
    }
    $disks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    $diskLines = @()
    foreach ($d in $disks) {
        $total = [math]::Round($d.Size / 1GB, 1)
        $free = [math]::Round($d.FreeSpace / 1GB, 1)
        $pct = if ($d.Size -gt 0) { [math]::Round(($d.FreeSpace / $d.Size) * 100, 0) } else { 0 }
        $label = if ($d.VolumeName) { "$($d.DeviceID) $($d.VolumeName)" } else { $d.DeviceID }
        $diskLines += "  ${label}: ${free} GB livre de ${total} GB ($pct% livre)"
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
        if ($ips.Count -gt 3) { $ipDisplay += " (+$($ips.Count - 3) mais)" }
        $h['IP(s)'] = $ipDisplay
    } else { $h['IP(s)'] = 'N/A' }
    $h['Data/Hora'] = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'
    if ($ips.Count -gt 0) { $script:BIA_PrimaryIP = $ips[0] } else { $script:BIA_PrimaryIP = '' }
    return $h
}

function Get-BIAGreeting {
    $h = (Get-Date).Hour
    if ($h -ge 5 -and $h -lt 12) { return 'Bom dia' }
    if ($h -ge 12 -and $h -lt 18) { return 'Boa tarde' }
    return 'Boa noite'
}

function Get-BIAAgentTip {
    $tips = @(
        'Dica: Use o menu 8 para um diagnostico rapido da maquina.',
        'Dica: Playbooks (menu 6) automatizam PC lento, rede e impressora.',
        'Dica: Azure sem modulo? O BIA instala o Az automaticamente na opcao 1.',
        'Dica: Exporte um pacote completo do sistema em Informacoes > Exportar.',
        'Dica: R = sempre volta ao resumo e ao inicio.',
        'Dica: Impressoras travadas? Menu 6 > Impressora ou menu 9 > Limpar fila.',
        'Dica: Menu 12 reune nslookup, whoami, Defender, DISM, bateria, clipboard, hash, WSL...'
    )
    $tips[(Get-Random -Maximum $tips.Count)]
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
    Show-BIATyping -Text ' Como posso ajudar? (ENTER para ver o menu) ' -DelayMs 25 -NoNewline -Color Accent
    Write-Host ''
    Read-Host
}

function Show-BIAWelcomeDashboard {
    $data = Get-BIAWelcomeData
    $n = { param($k) if ($data.ContainsKey($k) -and $data[$k]) { $data[$k] } else { 'N/A' } }
    $lines = @()
    $lines += "  Usuario      : $(& $n 'Usuario')"
    $lines += "  Computador   : $(& $n 'Computador')"
    $lines += "  Dominio AD   : $(& $n 'Dominio AD')"
    $lines += "  SO           : $(& $n 'SO')"
    $lines += "  Versao       : $(& $n 'Versao')"
    $lines += "  Uptime       : $(& $n 'Uptime')"
    $lines += "  Fabricante   : $(& $n 'Fabricante')"
    $lines += "  Modelo       : $(& $n 'Modelo')"
    $lines += "  RAM          : $(& $n 'RAM')"
    $lines += "  Disco        :"
    $discoVal = & $n 'Disco'
    if ($discoVal -and $discoVal -ne 'N/A') { foreach ($dl in ($discoVal -split "`n")) { $lines += $dl } } else { $lines += "  (N/A)" }
    $lines += "  IP(s)        : $(& $n 'IP(s)')"
    $lines += "  Data/Hora    : $(& $n 'Data/Hora')"
    Write-BIAInfoPanel -Title ' Resumo da maquina (usuario, AD, RAM, disco, IP) ' -Lines $lines
}

# ---- Menu principal ----
function Show-MainMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -IP $script:BIA_PrimaryIP
    Write-BIABox -Title ' MENU PRINCIPAL ' -Lines @(
        '  1) Usuario - Atendimento rapido',
        '  2) TI - Ferramentas administrativas',
        '  3) Servidor - Active Directory',
        '  4) Rede e Seguranca',
        '  5) Utilitarios',
        '  6) Playbooks automaticos',
        '  7) Informacoes do sistema',
        '  8) Diagnostico rapido (health check)',
        '  9) Impressoras',
        ' 10) Azure (Connect / CLI)',
        ' 11) Instalar aplicativos (winget)',
        ' 12) Comandos e ferramentas (CMD / PowerShell)',
        '  R) Ver resumo da maquina (voltar ao inicio)',
        '  S) Sobre / Creditos',
        '  0) Sair'
    )
    Write-Host ''
    $tip = Get-BIAAgentTip
    Write-Host "  " -NoNewline
    Write-Host $tip -ForegroundColor $BIA_Theme.Muted
    Write-Host ''
    $prompts = @('O que deseja fazer?', 'O que vamos fazer agora?', 'Em que posso ajudar?', 'Qual opcao?')
    $prompt = $prompts[(Get-Random -Maximum $prompts.Count)]
    $op = (Read-Host "  $prompt").Trim().ToUpper()
    switch ($op) {
        '1' { Show-BIATransition -Title ' Usuario ' -Milliseconds 500; Show-UserMenu }
        '2' { Show-BIATransition -Title ' TI ' -Milliseconds 500; Show-TIMenu }
        '3' { Show-BIATransition -Title ' Active Directory ' -Milliseconds 500; Show-ADMenu }
        '4' { Show-BIATransition -Title ' Rede e Seguranca ' -Milliseconds 500; Show-NetMenu }
        '5' { Show-BIATransition -Title ' Utilitarios ' -Milliseconds 500; Show-UtilsMenu }
        '6' { Show-BIATransition -Title ' Playbooks ' -Milliseconds 500; Show-PlaybooksMenu }
        '7' { Show-BIATransition -Title ' Informacoes do sistema ' -Milliseconds 500; Show-SysInfoMenu }
        '8' { Show-BIATransition -Title ' Diagnostico rapido ' -Milliseconds 500; Show-HealthMenu }
        '9' { Show-BIATransition -Title ' Impressoras ' -Milliseconds 400; Show-PrintersMenu }
        '10' { Show-BIATransition -Title ' Azure ' -Milliseconds 400; Show-AzureMenu }
        '11' { Show-BIATransition -Title ' Instalar aplicativos ' -Milliseconds 400; Show-InstallAppsMenu }
        '12' { Show-BIATransition -Title ' Comandos e ferramentas ' -Milliseconds 400; Show-ToolsMenu }
        'R' { Write-Host ''; $padR = [Math]::Max(0, ($ScreenWidth - 22) / 2); Write-Host (' ' * [int]$padR) -NoNewline; Show-BIATyping -Text 'Voltando ao inicio...' -DelayMs 30 -Color Accent; Start-Sleep -Milliseconds 400; Show-BIAHomeScreen; Show-MainMenu }
        'S' { Show-BIAAbout; Invoke-BIAPause; Show-MainMenu }
        '0' { Exit-BIA }
        default { Show-MainMenu }
    }
}

function Show-BIAAbout {
    Write-BIAHeader -IP $script:BIA_PrimaryIP
    $pad = [Math]::Max(0, ($ScreenWidth - 28) / 2)
    Write-Host (' ' * [int]$pad) -NoNewline
    Show-BIATyping -Text ' SOBRE O BIA SHELL ' -DelayMs 25 -Color Title
    Write-Host ''
    Write-BIABox -Title ' SOBRE O BIA SHELL ' -Lines @(
        '  BIA Shell v8 - CoreSafe',
        '  Assistente para TI e Suporte',
        '  ',
        '  Desenvolvido por Iran Ribeiro',
        '  GitHub: https://github.com/IranRibeiro55',
        '  ',
        '  PowerShell | Menus | Diagnostico | Playbooks'
    )
    Write-Host ''
    $pad2 = [Math]::Max(0, ($ScreenWidth - 45) / 2)
    Write-Host (' ' * [int]$pad2) -NoNewline
    Show-BIATyping -Text 'Obrigado por usar o BIA. Qualquer duvida, consulte o README.' -DelayMs 20 -Color Muted
    Write-Host ''
}

# ---------- USUARIO ----------
function Show-UserMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle ' Usuario - Atendimento rapido ' -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] Limpeza basica (TEMP + Windows\Temp)',
        '  [2] Diagnostico de internet (ping/flush/renew)',
        '  [3] ipconfig /all',
        '  [4] Flush DNS',
        '  [5] Windows Update (painel)',
        '  [6] Agendar CHKDSK C: /F /R',
        '  [7] Abrir pasta do usuario',
        '  [8] Abrir Este Computador',
        '  [9] Reset caches (Teams/Office/Edge/Chrome)',
        '  [a] Abrir Documentos / Desktop / Downloads',
        '  [0] Voltar'
    )
    $op = (Read-Host '  Escolha').Trim().ToLower()
    switch ($op) {
        '1' { Invoke-UserClean; Write-BIALog 'Usuario: Limpeza basica'; Invoke-BIAPause; Show-UserMenu }
        '2' { Invoke-UserNet; Write-BIALog 'Usuario: Diagnostico rede'; Invoke-BIAPause; Show-UserMenu }
        '3' { Show-BIALoadingShort -Message 'Obtendo ipconfig...' -Steps 8; ipconfig /all | More; Invoke-BIAPause; Show-UserMenu }
        '4' { Show-BIALoadingShort -Message 'Flush DNS...' -Steps 5; ipconfig /flushdns | Out-Null; Write-BIAMessage 'DNS cache limpo.' Success; Invoke-BIAPause; Show-UserMenu }
        '5' { Start-Process 'control.exe' -ArgumentList '/name Microsoft.WindowsUpdate'; Write-BIAMessage 'Abrindo Windows Update...' Info; Start-Sleep -Seconds 2; Show-UserMenu }
        '6' { & chkdsk C: /F /R; Write-BIAMessage 'Reinicie o PC para aplicar.' Warning; Invoke-BIAPause; Show-UserMenu }
        '7' { Start-Process explorer -ArgumentList $env:USERPROFILE; Write-BIAMessage 'Abrindo pasta do usuario.' Info; Show-UserMenu }
        '8' { Start-Process explorer -ArgumentList 'shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}'; Write-BIAMessage 'Abrindo Este Computador.' Info; Show-UserMenu }
        '9' { Invoke-UserCache; Write-BIALog 'Usuario: Reset caches'; Invoke-BIAPause; Show-UserMenu }
        'a' { Write-Host '  [1] Documentos  [2] Desktop  [3] Downloads' -ForegroundColor $BIA_Theme.Menu; $r = (Read-Host).Trim(); if ($r -eq '1') { Start-Process "$env:USERPROFILE\Documents" }; if ($r -eq '2') { Start-Process "$env:USERPROFILE\Desktop" }; if ($r -eq '3') { Start-Process "$env:USERPROFILE\Downloads" }; Show-UserMenu }
        '0' { Show-MainMenu }
        default { Show-UserMenu }
    }
}

function Invoke-UserClean {
    Write-BIAMessage 'Limpando temporarios...' Info
    Write-BIAProgressBar -Message 'Limpando TEMP' -TotalSteps 6
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message 'Limpando C:\Windows\Temp' -TotalSteps 6
    Remove-Item -Path 'C:\Windows\Temp\*' -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAMessage 'Concluido.' Success
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
    Write-BIAMessage 'Reset de caches comuns...' Info
    Write-BIAProgressBar -Message 'Fechando Teams (se aberto)' -TotalSteps 3
    Stop-Process -Name 'Teams' -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message 'Limpando cache Teams/Office' -TotalSteps 4
    Remove-Item -Path "$env:APPDATA\Microsoft\Teams" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Office\16.0\Wef" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message 'Limpando cache Edge' -TotalSteps 3
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message 'Limpando cache Chrome' -TotalSteps 3
    Remove-Item -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAMessage 'OK.' Success
}

# ---------- TI ----------
function Show-TIMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle ' TI - Ferramentas administrativas ' -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] gpupdate /force',
        '  [2] Event Viewer',
        '  [3] Services.msc',
        '  [4] Perfmon',
        '  [5] Task Manager',
        '  [6] tasklist (processos)',
        '  [7] taskkill por nome',
        '  [8] Softwares instalados (pode demorar)',
        '  [9] Top 10 processos (CPU/RAM)',
        '  [a] Conexao Remota (mstsc)',
        '  [b] Gerenciar este computador (compmgmt)',
        '  [c] Gerenciar computador remoto',
        '  [d] Usuarios e grupos locais (lusrmgr)',
        '  [e] Atualizacoes instaladas (hotfix)',
        '  [f] Verificacao SFC (arquivos de sistema)',
        '  [g] Criar ponto de restauracao',
        '  [h] Status BitLocker',
        '  [i] Assistencia Remota / Painel Impressoras',
        '  [j] Sessoes RDP ativas (query session)',
        '  [k] whoami /all',
        '  [l] Tarefas agendadas (listar)',
        '  [m] Programas de inicializacao',
        '  [n] Windows Defender (status / scan rapido)',
        '  [o] net share (compartilhamentos)',
        '  [p] Pendencia de reinicio',
        '  [q] net user (usuarios locais)',
        '  [r] Bloquear estacao',
        '  [s] Processo por porta',
        '  [t] Relatorio de Confiabilidade',
        '  [0] Voltar'
    )
    $op = (Read-Host '  Escolha').Trim().ToLower()
    switch ($op) {
        '1' { Show-BIASpinner -Message 'Aplicando politicas de grupo...' -ScriptBlock { & gpupdate /force 2>&1 | Out-Null }; Invoke-BIAPause; Show-TIMenu }
        '2' { Start-Process eventvwr.msc; Write-BIAMessage 'Abrindo Event Viewer...' Info; Start-Sleep -Seconds 2; Show-TIMenu }
        '3' { Start-Process services.msc; Write-BIAMessage 'Abrindo Services...' Info; Start-Sleep -Seconds 2; Show-TIMenu }
        '4' { Start-Process perfmon; Write-BIAMessage 'Abrindo Performance Monitor...' Info; Start-Sleep -Seconds 2; Show-TIMenu }
        '5' { Start-Process taskmgr; Write-BIAMessage 'Abrindo Task Manager...' Info; Start-Sleep -Seconds 2; Show-TIMenu }
        '6' { Show-BIALoadingShort -Message 'Listando processos...' -Steps 10; Get-Process | Format-Table Id, ProcessName, CPU, WorkingSet64 -AutoSize | Out-String | More; Invoke-BIAPause; Show-TIMenu }
        '7' { $name = (Read-Host '  Processo (ex.: chrome.exe)').Trim(); if ($name) { Stop-Process -Name ($name -replace '\.exe$','') -Force -ErrorAction SilentlyContinue; Write-BIAMessage "Processo $name encerrado." Success }; Invoke-BIAPause; Show-TIMenu }
        '8' { $sw = Show-BIASpinner -Message 'Listando softwares (WMIC - pode demorar 1-2 min)...' -ScriptBlock { Get-WmiObject Win32_Product | Select-Object Name, Version }; $sw | Format-Table -AutoSize | Out-String | More; Invoke-BIAPause; Show-TIMenu }
        '9' { Show-TITopProcesses; Invoke-BIAPause; Show-TIMenu }
        'a' { Start-Process mstsc; Write-BIAMessage 'Abrindo Conexao Remota.' Info; Show-TIMenu }
        'b' { Start-Process compmgmt.msc; Write-BIAMessage 'Abrindo Gerenciamento do computador.' Info; Show-TIMenu }
        'c' { $pc = (Read-Host '  Nome do computador remoto').Trim(); if ($pc) { Start-Process "compmgmt.msc" -ArgumentList "/computer:$pc"; Write-BIAMessage "Abrindo $pc" Info }; Show-TIMenu }
        'd' { Start-Process lusrmgr.msc; Write-BIAMessage 'Abrindo Usuarios e grupos locais.' Info; Show-TIMenu }
        'e' { Show-BIALoadingShort -Message 'Listando atualizacoes...' -Steps 12; Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID, Description, InstalledOn -AutoSize | Out-String | More; Invoke-BIAPause; Show-TIMenu }
        'f' { Write-BIAMessage 'SFC pode demorar varios minutos. Deseja continuar? (s/n)' Warning; if ((Read-Host).Trim().ToLower() -eq 's') { sfc /scannow; Invoke-BIAPause }; Show-TIMenu }
        'g' { Invoke-CreateRestorePoint; Invoke-BIAPause; Show-TIMenu }
        'h' { Show-BIALoadingShort -Message 'BitLocker...' -Steps 5; manage-bde -status 2>$null; if ($LASTEXITCODE -ne 0) { Write-BIAMessage 'BitLocker nao disponivel ou sem unidades protegidas.' Muted }; Invoke-BIAPause; Show-TIMenu }
        'i' { Show-TIRemotePrintMenu; Show-TIMenu }
        'j' { query session 2>$null; Invoke-BIAPause; Show-TIMenu }
        'k' { whoami /all | More; Invoke-BIAPause; Show-TIMenu }
        'l' { Get-ScheduledTask | Where-Object State -eq Ready | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize; Invoke-BIAPause; Show-TIMenu }
        'm' { Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name, Command, Location | Format-Table -AutoSize -Wrap; Invoke-BIAPause; Show-TIMenu }
        'n' { try { $mp = Get-MpComputerStatus -ErrorAction Stop; Write-Host '  Defender ativo:' $mp.AntivirusEnabled '| Ultima varredura:' $mp.QuickScanStartTime; $r = (Read-Host '  Scan rapido agora? (s/n)').Trim().ToLower(); if ($r -eq 's') { Start-MpScan -ScanType Quick; Write-BIAMessage 'Scan iniciado.' Success } } catch { Write-BIAMessage 'Get-MpComputerStatus nao disponivel.' Warning }; Invoke-BIAPause; Show-TIMenu }
        'o' { net share; Invoke-BIAPause; Show-TIMenu }
        'p' { $k = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue; $w = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue; if ($k -or $w) { Write-BIAMessage 'Ha pendencia de reinicio.' Warning } else { Write-BIAMessage 'Nenhuma pendencia de reinicio.' Success }; Invoke-BIAPause; Show-TIMenu }
        'q' { net user; Invoke-BIAPause; Show-TIMenu }
        'r' { Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class PInvoke { [DllImport("user32.dll")] public static extern void LockWorkStation(); }'; [PInvoke]::LockWorkStation(); Write-BIAMessage 'Estacao bloqueada.' Info; Start-Sleep -Seconds 2; Show-TIMenu }
        's' { $port = (Read-Host '  Porta (ex: 443)').Trim(); if ($port) { Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; Write-Host "  Porta $port -> PID $($_.OwningProcess) -> $($p.ProcessName)" } }; Invoke-BIAPause; Show-TIMenu }
        't' { Start-Process 'perfmon' -ArgumentList '/rel'; Write-BIAMessage 'Abrindo Relatorio de Confiabilidade.' Info; Show-TIMenu }
        '0' { Show-MainMenu }
        default { Show-TIMenu }
    }
}

function Invoke-CreateRestorePoint {
    Write-BIAMessage 'Criando ponto de restauracao...' Info
    try {
        $null = powershell -NoProfile -Command "Checkpoint-Computer -Description 'BIA Shell' -RestorePointType 'MODIFY_SETTINGS'" 2>$null
        if ($LASTEXITCODE -eq 0) { Write-BIAMessage 'Ponto de restauracao criado.' Success } else { throw 'Falha' }
    } catch {
        try {
            wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "BIA", 7 2>$null
            Write-BIAMessage 'Ponto de restauracao criado (WMI).' Success
        } catch { Write-BIAMessage 'Requer elevacao de administrador.' Error }
    }
}

function Show-TIRemotePrintMenu {
    Write-Host '  [1] Assistencia Remota (msra)  [2] Painel de Impressoras' -ForegroundColor $BIA_Theme.Menu
    $r = (Read-Host '  Escolha').Trim()
    if ($r -eq '1') { Start-Process msra; Write-BIAMessage 'Abrindo Assistencia Remota.' Info }
    if ($r -eq '2') { Start-Process 'control.exe' -ArgumentList 'printers'; Write-BIAMessage 'Abrindo Impressoras.' Info }
}

function Show-TITopProcesses {
    Show-BIALoadingShort -Message 'Coletando uso CPU/RAM...' -Steps 12
    Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 |
        Format-Table ProcessName, Id, @{N='CPU(s)';E={[math]::Round($_.CPU,2)}}, @{N='RAM(MB)';E={[math]::Round($_.WorkingSet64/1MB,2)}} -AutoSize
}

# ---------- AD ----------
function Show-ADMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle ' Servidor - Active Directory ' -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] dsa.msc (AD Users and Computers)',
        '  [2] gpmc.msc (Group Policy)',
        '  [3] DNS mgmt',
        '  [4] DHCP mgmt',
        '  [5] repadmin /replsummary',
        '  [6] repadmin /syncall /AdeP',
        '  [7] dcdiag',
        '  [8] Diagnostico AD rapido (nltest/klist/gpresult)',
        '  [0] Voltar'
    )
    $op = (Read-Host '  Escolha').Trim()
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
    Write-BIAHeader -Subtitle ' Rede e Seguranca ' -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] Ping 8.8.8.8',
        '  [2] Tracert google.com',
        '  [3] netstat -ano',
        '  [4] Reset winsock/ip (basico)',
        '  [5] Firewall OFF',
        '  [6] Firewall ON',
        '  [7] Limpar ARP + renovar DHCP',
        '  [8] Portas em uso (LISTEN/ESTABLISHED)',
        '  [9] Mapear unidade de rede',
        '  [a] Abrir pasta de rede (\\\\computador)',
        '  [b] nslookup (consultar DNS)',
        '  [c] Test-NetConnection (host + porta)',
        '  [d] route print',
        '  [e] arp -a (tabela ARP)',
        '  [f] ipconfig /displaydns',
        '  [0] Voltar'
    )
    $op = (Read-Host '  Escolha').Trim().ToLower()
    switch ($op) {
        '1' { ping -n 4 8.8.8.8; Invoke-BIAPause; Show-NetMenu }
        '2' { Show-BIALoadingShort -Message 'Tracert...' -Steps 5; tracert google.com; Invoke-BIAPause; Show-NetMenu }
        '3' { Show-BIALoadingShort -Message 'netstat...' -Steps 8; netstat -ano | More; Invoke-BIAPause; Show-NetMenu }
        '4' { Write-BIAProgressBar -Message 'Reset Winsock' -TotalSteps 3; netsh winsock reset 2>$null; Write-BIAProgressBar -Message 'Reset IP' -TotalSteps 3; netsh int ip reset 2>$null; Write-BIAMessage 'Reinicie o PC para aplicar.' Warning; Invoke-BIAPause; Show-NetMenu }
        '5' { netsh advfirewall set allprofiles state off; Write-BIAMessage 'Firewall OFF.' Warning; Invoke-BIAPause; Show-NetMenu }
        '6' { netsh advfirewall set allprofiles state on; Write-BIAMessage 'Firewall ON.' Success; Invoke-BIAPause; Show-NetMenu }
        '7' { Write-BIAProgressBar -Message 'Limpando ARP' -TotalSteps 3; arp -d * 2>$null; Write-BIAProgressBar -Message 'Release/Renew DHCP' -TotalSteps 5; ipconfig /release 2>$null; ipconfig /renew 2>$null; Invoke-BIAPause; Show-NetMenu }
        '8' { Show-NetPorts; Invoke-BIAPause; Show-NetMenu }
        '9' { $drive = (Read-Host '  Letra da unidade (ex: Z)').Trim().ToUpper(); $path = (Read-Host '  Caminho (ex: \\\\servidor\\pasta)').Trim(); if ($drive -and $path) { & net use "${drive}:" $path 2>$null; Write-BIAMessage "Mapeado ${drive}: para $path" Success }; Invoke-BIAPause; Show-NetMenu }
        'a' { $pc = (Read-Host '  Nome do computador ou caminho (ex: \\\\PC01)').Trim(); if ($pc) { if ($pc -notlike '\\\\*') { $pc = "\\$pc" }; Start-Process explorer -ArgumentList $pc; Write-BIAMessage "Abrindo $pc" Info }; Show-NetMenu }
        'b' { $h = (Read-Host '  Nome ou IP para consultar DNS').Trim(); if ($h) { nslookup $h }; Invoke-BIAPause; Show-NetMenu }
        'c' { $t = (Read-Host '  Host (ex: google.com)').Trim(); $prtStr = (Read-Host '  Porta (Enter=pula)').Trim(); if ($t) { $p = 0; if ($prtStr -and [int]::TryParse($prtStr, [ref]$p) -and $p -gt 0) { Test-NetConnection -ComputerName $t -Port $p } else { Test-NetConnection -ComputerName $t } }; Invoke-BIAPause; Show-NetMenu }
        'd' { route print; Invoke-BIAPause; Show-NetMenu }
        'e' { arp -a; Invoke-BIAPause; Show-NetMenu }
        'f' { ipconfig /displaydns | More; Invoke-BIAPause; Show-NetMenu }
        '0' { Show-MainMenu }
        default { Show-NetMenu }
    }
}

function Show-NetPorts {
    Show-BIALoadingShort -Message 'Analisando portas...' -Steps 10
    $lines = netstat -ano 2>$null
    $lines | Select-String -Pattern 'LISTEN|ESTABLISHED' | Select-Object -First 30
}

# ---------- UTILITARIOS ----------
function Show-UtilsMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle ' Utilitarios ' -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] Regedit',
        '  [2] Agendar desligamento 1h',
        '  [3] Agendar desligamento 2h',
        '  [4] Cancelar desligamento',
        '  [5] Limpeza de disco (Prefetch, etc)',
        '  [6] Otimizar unidades (SSD/HDD)',
        '  [7] Backup do registro (exportar HKCU)',
        '  [8] TeamViewer / AnyDesk (se instalado)',
        '  [9] Atalhos rapidos (Notepad, Calc, CMD, PowerShell)',
        '  [a] Esvaziar Lixeira',
        '  [b] Variaveis de ambiente (listar)',
        '  [c] Ver clipboard',
        '  [d] Hash de arquivo (SHA256)',
        '  [e] Relatorio de bateria (powercfg)',
        '  [f] Ativacao do Windows (status)',
        '  [g] Painelis: Programas | Rede | Energia | Som | Data/hora | Credenciais',
        '  [0] Voltar'
    )
    $op = (Read-Host '  Escolha').Trim().ToLower()
    switch ($op) {
        '1' { Start-Process regedit; Show-UtilsMenu }
        '2' { shutdown /s /t 3600 /c 'Desligamento em 1h - BIA'; Write-BIAMessage 'Desligamento agendado em 1h.' Info; Invoke-BIAPause; Show-UtilsMenu }
        '3' { shutdown /s /t 7200 /c 'Desligamento em 2h - BIA'; Write-BIAMessage 'Desligamento agendado em 2h.' Info; Invoke-BIAPause; Show-UtilsMenu }
        '4' { shutdown /a; Write-BIAMessage 'Desligamento cancelado.' Success; Invoke-BIAPause; Show-UtilsMenu }
        '5' { Invoke-DiskCleanupLight; Invoke-BIAPause; Show-UtilsMenu }
        '6' { Invoke-OptimizeVolumes; Invoke-BIAPause; Show-UtilsMenu }
        '7' { $out = Join-Path $script:WorkDir "RegBackup_$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"; reg export HKCU $out 2>$null; Write-BIAMessage "Backup salvo: $out" Success; Invoke-BIAPause; Show-UtilsMenu }
        '8' { Invoke-StartRemoteTool; Show-UtilsMenu }
        '9' { Write-Host '  [1] Bloco de notas  [2] Calculadora  [3] CMD  [4] PowerShell' -ForegroundColor $BIA_Theme.Menu; $r = (Read-Host).Trim(); if ($r -eq '1') { Start-Process notepad }; if ($r -eq '2') { Start-Process calc }; if ($r -eq '3') { Start-Process cmd }; if ($r -eq '4') { Start-Process powershell }; Show-UtilsMenu }
        'a' { Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Write-BIAMessage 'Lixeira esvaziada.' Success; Invoke-BIAPause; Show-UtilsMenu }
        'b' { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize; Invoke-BIAPause; Show-UtilsMenu }
        'c' { $c = Get-Clipboard -ErrorAction SilentlyContinue; if ($c) { $c | Out-String | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  (vazio)' }; Invoke-BIAPause; Show-UtilsMenu }
        'd' { $f = (Read-Host '  Caminho do arquivo').Trim(); if ($f -and (Test-Path $f)) { Get-FileHash -Path $f -Algorithm SHA256 | Format-List } else { Write-BIAMessage 'Arquivo nao encontrado.' Warning }; Invoke-BIAPause; Show-UtilsMenu }
        'e' { $desk = [Environment]::GetFolderPath('Desktop'); Push-Location $desk; powercfg /batteryreport 2>$null; Pop-Location; $out = Join-Path $desk 'battery-report.html'; if (Test-Path $out) { Start-Process $out; Write-BIAMessage "Relatorio: $out" Success } else { Write-BIAMessage 'Relatorio no diretorio atual.' Info }; Invoke-BIAPause; Show-UtilsMenu }
        'f' { try { Get-WmiObject -Query "SELECT * FROM SoftwareLicensingProduct WHERE ApplicationId='55c92734-d682-4d71-983e-d6ec3f46059c' AND LicenseStatus=1" -ErrorAction Stop | Select-Object Description, LicenseStatus | Format-List } catch { cscript //nologo "$env:SystemRoot\System32\slmgr.vbs" /dlv 2>$null }; Invoke-BIAPause; Show-UtilsMenu }
        'g' { Write-Host '  [1] Programas  [2] Rede  [3] Energia  [4] Som  [5] Data/hora  [6] Credenciais' -ForegroundColor $BIA_Theme.Menu; $r = (Read-Host).Trim(); if ($r -eq '1') { Start-Process appwiz.cpl }; if ($r -eq '2') { Start-Process ncpa.cpl }; if ($r -eq '3') { Start-Process powercfg.cpl }; if ($r -eq '4') { Start-Process mmsys.cpl }; if ($r -eq '5') { Start-Process timedate.cpl }; if ($r -eq '6') { Start-Process 'control.exe' -ArgumentList '/name', 'Microsoft.CredentialManager' }; Show-UtilsMenu }
        '0' { Show-MainMenu }
        default { Show-UtilsMenu }
    }
}

function Invoke-StartRemoteTool {
    $tv = Get-ChildItem -Path 'C:\Program Files\TeamViewer\TeamViewer.exe', 'C:\Program Files (x86)\TeamViewer\TeamViewer.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    $ad = Get-ChildItem -Path 'C:\Program Files (x86)\AnyDesk\AnyDesk.exe', 'C:\Program Files\AnyDesk\AnyDesk.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($tv) { Start-Process $tv.FullName; Write-BIAMessage 'Abrindo TeamViewer.' Success }
    elseif ($ad) { Start-Process $ad.FullName; Write-BIAMessage 'Abrindo AnyDesk.' Success }
    else { Write-BIAMessage 'TeamViewer/AnyDesk nao encontrados.' Warning }
}

function Invoke-DiskCleanupLight {
    Write-BIAMessage 'Limpando Prefetch e cache de fontes...' Info
    Write-BIAProgressBar -Message 'Prefetch' -TotalSteps 5
    Remove-Item -Path 'C:\Windows\Prefetch\*' -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message 'Font cache' -TotalSteps 3
    Remove-Item -Path "$env:LOCALAPPDATA\FontCache\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAMessage 'Concluido. Para limpeza completa use "Limpeza de disco" do Windows.' Success
}

function Invoke-OptimizeVolumes {
    Write-BIAMessage 'Otimizando volumes (pode demorar)...' Info
    $vols = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter }
    if (-not $vols) { Write-BIAMessage 'Nenhum volume encontrado ou cmdlet nao disponivel.' Warning; return }
    foreach ($v in $vols) {
        Write-BIAProgressBar -Message "Otimizando $($v.DriveLetter):" -TotalSteps 8
        try { Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim -ErrorAction Stop } catch { Write-BIAMessage "Pulando $($v.DriveLetter): $_" Warning }
    }
    Write-BIAMessage 'Concluido.' Success
}

# ---------- PLAYBOOKS ----------
function Show-PlaybooksMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle ' Playbooks automaticos ' -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] PC lento (temp + flush + renew)',
        '  [2] Sem internet (winsock/ip + flush + renew)',
        '  [3] Impressora travada (spool)',
        '  [0] Voltar'
    )
    $op = (Read-Host '  Escolha').Trim()
    switch ($op) {
        '1' { Invoke-PlaybookSlow; Write-BIALog 'Playbook: PC lento'; Invoke-BIAPause; Show-PlaybooksMenu }
        '2' { Invoke-PlaybookNet; Write-BIALog 'Playbook: Sem internet'; Invoke-BIAPause; Show-PlaybooksMenu }
        '3' { Invoke-PlaybookPrint; Write-BIALog 'Playbook: Impressora'; Invoke-BIAPause; Show-PlaybooksMenu }
        '0' { Show-MainMenu }
        default { Show-PlaybooksMenu }
    }
}

function Invoke-PlaybookSlow {
    Write-BIAProgressBar -Message 'Limpando TEMP' -TotalSteps 5
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message 'Limpando C:\Windows\Temp' -TotalSteps 5
    Remove-Item -Path 'C:\Windows\Temp\*' -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message 'Flush DNS' -TotalSteps 3
    ipconfig /flushdns 2>$null
    Write-BIAProgressBar -Message 'Release/Renew IP' -TotalSteps 6
    ipconfig /release 2>$null; ipconfig /renew 2>$null
    Write-BIAMessage 'PC otimizado.' Success
}

function Invoke-PlaybookNet {
    Write-BIAProgressBar -Message 'Reset Winsock' -TotalSteps 3
    netsh winsock reset 2>$null
    Write-BIAProgressBar -Message 'Reset IP' -TotalSteps 3
    netsh int ip reset 2>$null
    Write-BIAProgressBar -Message 'Flush DNS' -TotalSteps 2
    ipconfig /flushdns 2>$null
    Write-BIAProgressBar -Message 'Release/Renew IP' -TotalSteps 4
    ipconfig /release 2>$null; ipconfig /renew 2>$null
    Write-BIAMessage 'Rede reinicializada.' Success
}

function Invoke-PlaybookPrint {
    Write-BIAProgressBar -Message 'Parando spooler' -TotalSteps 3
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message 'Limpando fila' -TotalSteps 4
    Remove-Item -Path 'C:\Windows\System32\spool\PRINTERS\*' -Recurse -Force -ErrorAction SilentlyContinue
    Write-BIAProgressBar -Message 'Iniciando spooler' -TotalSteps 3
    Start-Service -Name Spooler -ErrorAction SilentlyContinue
    Write-BIAMessage 'Spool limpo.' Success
}

# ---------- SYS INFO ----------
function Show-SysInfoMenu {
    if (-not $script:BIA_PrimaryIP) { $script:BIA_PrimaryIP = Get-BIAPrimaryIP }
    Write-BIAHeader -Subtitle ' Informacoes do sistema ' -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] Resumo na tela (detalhado)',
        "  [2] Exportar pacote completo para TXT (em $env:TEMP\BIA)",
        '  [3] Uptime do sistema',
        '  [4] Ver dashboard (usuario, maquina, AD, RAM, disco, IP)',
        '  [0] Voltar'
    )
    $op = (Read-Host '  Escolha').Trim()
    switch ($op) {
        '1' { Show-BIALoadingShort -Message 'Coletando resumo...' -Steps 12; Show-SysSummary; Invoke-BIAPause; Show-SysInfoMenu }
        '2' { Export-SysInfo; Invoke-BIAPause; Show-SysInfoMenu }
        '3' { Show-SysUptime; Invoke-BIAPause; Show-SysInfoMenu }
        '4' { Show-BIALoadingShort -Message 'Atualizando dados...' -Steps 6; Show-BIAWelcomeDashboard; Invoke-BIAPause; Show-SysInfoMenu }
        '0' { Show-MainMenu }
        default { Show-SysInfoMenu }
    }
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
    Write-BIAHeader -Subtitle ' Diagnostico rapido (health check) ' -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] Executar diagnostico completo',
        '  [2] Eventos de erro (ultimas 24h)',
        '  [3] Teste de conectividade (multi-host)',
        '  [4] Espaco em disco + memoria',
        '  [0] Voltar'
    )
    $op = (Read-Host '  Escolha').Trim()
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
    Write-BIAMessage 'Iniciando diagnostico...' Info
    Write-BIAProgressBar -Message 'Disco' -TotalSteps 5
    $vols = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    foreach ($v in $vols) {
        $freePct = if ($v.Size -gt 0) { [math]::Round(($v.FreeSpace / $v.Size) * 100, 1) } else { 0 }
        $status = if ($freePct -lt 10) { 'CRITICO' } elseif ($freePct -lt 20) { 'ATENCAO' } else { 'OK' }
        Write-Host "    $($v.DeviceID) Livre: $freePct% - $status" -ForegroundColor $(if ($freePct -lt 10) { 'Red' } elseif ($freePct -lt 20) { 'Yellow' } else { 'Green' })
    }
    Write-BIAProgressBar -Message 'Memoria' -TotalSteps 5
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        $freeMB = [math]::Round($os.FreePhysicalMemory / 1024, 0)
        $totalMB = [math]::Round($os.TotalVisibleMemorySize / 1024, 0)
        $pct = [math]::Round(($os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)
        Write-Host "    RAM: $freeMB MB livre de $totalMB MB ($pct% livre)" -ForegroundColor $(if ($pct -lt 15) { 'Yellow' } else { 'Green' })
    }
    Write-BIAProgressBar -Message 'Rede (ping)' -TotalSteps 5
    $pingOk = $false
    try { $r = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction Stop; $pingOk = $r } catch { }
    Write-Host "    Internet (8.8.8.8): $(if ($pingOk) { 'OK' } else { 'FALHA' })" -ForegroundColor $(if ($pingOk) { 'Green' } else { 'Red' })
    Write-BIAProgressBar -Message 'Servicos criticos' -TotalSteps 5
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
    Write-BIAHeader -Subtitle ' Impressoras ' -IP $script:BIA_PrimaryIP
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
    $op = (Read-Host '  Escolha').Trim()
    switch ($op) {
        '1' { Show-BIALoadingShort -Message 'Listando impressoras...' -Steps 6; Get-Printer -ErrorAction SilentlyContinue | Format-Table Name, DriverName, PortName -AutoSize; Invoke-BIAPause; Show-PrintersMenu }
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
    Write-BIAHeader -Subtitle ' Comandos e ferramentas (CMD / PowerShell) ' -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  --- Rede ---',
        '  [1] nslookup (consultar DNS)',
        '  [2] Test-NetConnection (host + porta)',
        '  [3] route print',
        '  [4] arp -a (tabela ARP)',
        '  [5] ipconfig /displaydns (cache DNS)',
        '  --- Sistema e usuario ---',
        '  [6] whoami /all',
        '  [7] Variaveis de ambiente (listar)',
        '  [8] Tarefas agendadas (listar)',
        '  [9] Programas de inicializacao',
        '  [a] Pendencia de reinicio (reboot pending)',
        '  --- Seguranca e manutencao ---',
        '  [b] Windows Defender (status + scan rapido)',
        '  [c] DISM RestoreHealth (reparo da imagem)',
        '  [d] Relatorio de bateria (powercfg)',
        '  [e] Ativacao do Windows (status)',
        '  [f] Relatorio de Confiabilidade (perfmon /rel)',
        '  --- Arquivos e clipboard ---',
        '  [g] Ver conteudo do clipboard',
        '  [h] Hash de arquivo (SHA256)',
        '  [i] Esvaziar Lixeira',
        '  --- Atalhos (painelis) ---',
        '  [j] Programas (appwiz.cpl) | Rede (ncpa.cpl) | Energia | Som | Data/hora | Credenciais',
        '  --- Outros ---',
        '  [k] net share (compartilhamentos)',
        '  [l] net user (usuarios locais)',
        '  [m] Bloquear estacao (LockWorkStation)',
        '  [n] Processo por porta (qual processo usa a porta X)',
        '  [o] WSL --list (se instalado)',
        '  [0] Voltar'
    )
    $op = (Read-Host '  Escolha').Trim().ToLower()
    switch ($op) {
        '1' { $h = (Read-Host '  Nome ou IP para consultar DNS').Trim(); if ($h) { nslookup $h }; Invoke-BIAPause; Show-ToolsMenu }
        '2' { $target = (Read-Host '  Host (ex: 8.8.8.8 ou google.com)').Trim(); $portStr = (Read-Host '  Porta (Enter=pula, ex: 443)').Trim(); if ($target) { $p = 0; if ($portStr -and [int]::TryParse($portStr, [ref]$p) -and $p -gt 0) { Test-NetConnection -ComputerName $target -Port $p } else { Test-NetConnection -ComputerName $target } }; Invoke-BIAPause; Show-ToolsMenu }
        '3' { route print; Invoke-BIAPause; Show-ToolsMenu }
        '4' { arp -a; Invoke-BIAPause; Show-ToolsMenu }
        '5' { ipconfig /displaydns | More; Invoke-BIAPause; Show-ToolsMenu }
        '6' { whoami /all | More; Invoke-BIAPause; Show-ToolsMenu }
        '7' { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize; Invoke-BIAPause; Show-ToolsMenu }
        '8' { Get-ScheduledTask | Where-Object State -eq Ready | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize; Invoke-BIAPause; Show-ToolsMenu }
        '9' { Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name, Command, Location | Format-Table -AutoSize -Wrap; Invoke-BIAPause; Show-ToolsMenu }
        'a' { $key = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue; $win = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue; if ($key -or $win) { Write-BIAMessage 'Ha pendencia de reinicio.' Warning } else { Write-BIAMessage 'Nenhuma pendencia de reinicio detectada.' Success }; Invoke-BIAPause; Show-ToolsMenu }
        'b' { try { $mp = Get-MpComputerStatus -ErrorAction Stop; Write-Host '  Defender: ' -NoNewline; Write-Host $mp.AntivirusEnabled -ForegroundColor $(if ($mp.AntivirusEnabled) { 'Green' } else { 'Yellow' }); Write-Host '  Ultima varredura: ' $mp.QuickScanStartTime; $r = (Read-Host '  Executar scan rapido agora? (s/n)').Trim().ToLower(); if ($r -eq 's') { Start-MpScan -ScanType Quick; Write-BIAMessage 'Scan iniciado.' Success } } catch { Write-BIAMessage 'Defender/Get-MpComputerStatus nao disponivel.' Warning }; Invoke-BIAPause; Show-ToolsMenu }
        'c' { Write-BIAMessage 'DISM /Online /Cleanup-Image /RestoreHealth pode demorar. Requer admin.' Warning; if ((Read-Host '  Continuar? (s/n)').Trim().ToLower() -eq 's') { DISM /Online /Cleanup-Image /RestoreHealth }; Invoke-BIAPause; Show-ToolsMenu }
        'd' { $desk = [Environment]::GetFolderPath('Desktop'); Push-Location $desk; powercfg /batteryreport 2>$null; Pop-Location; $out = Join-Path $desk 'battery-report.html'; if (Test-Path $out) { Write-BIAMessage "Relatorio: $out" Success; Start-Process $out } else { Write-BIAMessage 'Relatorio gerado no diretorio atual.' Info }; Invoke-BIAPause; Show-ToolsMenu }
        'e' { try { (Get-WmiObject -Query "SELECT * FROM SoftwareLicensingProduct WHERE ApplicationId='55c92734-d682-4d71-983e-d6ec3f46059c' AND LicenseStatus=1" -ErrorAction Stop) | Select-Object Description, LicenseStatus | Format-List } catch { cscript //nologo "$env:SystemRoot\System32\slmgr.vbs" /dlv 2>$null }; Invoke-BIAPause; Show-ToolsMenu }
        'f' { Start-Process 'perfmon' -ArgumentList '/rel'; Write-BIAMessage 'Abrindo Relatorio de Confiabilidade.' Info; Show-ToolsMenu }
        'g' { $c = Get-Clipboard -ErrorAction SilentlyContinue; if ($c) { Write-Host "  Clipboard ($($c.GetType().Name)): " -ForegroundColor $BIA_Theme.Menu; $c | Out-String | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  (vazio ou nao suportado)' }; Invoke-BIAPause; Show-ToolsMenu }
        'h' { $f = (Read-Host '  Caminho do arquivo').Trim(); if ($f -and (Test-Path $f)) { Get-FileHash -Path $f -Algorithm SHA256 | Format-List } else { Write-BIAMessage 'Arquivo nao encontrado.' Warning }; Invoke-BIAPause; Show-ToolsMenu }
        'i' { Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Write-BIAMessage 'Lixeira esvaziada.' Success; Invoke-BIAPause; Show-ToolsMenu }
        'j' { Write-Host '  [1] Programas  [2] Rede  [3] Energia  [4] Som  [5] Data/hora  [6] Credenciais' -ForegroundColor $BIA_Theme.Menu; $r = (Read-Host).Trim(); if ($r -eq '1') { Start-Process appwiz.cpl }; if ($r -eq '2') { Start-Process ncpa.cpl }; if ($r -eq '3') { Start-Process powercfg.cpl }; if ($r -eq '4') { Start-Process mmsys.cpl }; if ($r -eq '5') { Start-Process timedate.cpl }; if ($r -eq '6') { Start-Process 'control.exe' -ArgumentList '/name', 'Microsoft.CredentialManager' }; Show-ToolsMenu }
        'k' { net share; Invoke-BIAPause; Show-ToolsMenu }
        'l' { net user; Invoke-BIAPause; Show-ToolsMenu }
        'm' { Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class PInvoke { [DllImport("user32.dll")] public static extern void LockWorkStation(); }'; [PInvoke]::LockWorkStation(); Write-BIAMessage 'Estacao bloqueada.' Info; Start-Sleep -Seconds 2; Show-ToolsMenu }
        'n' { $port = (Read-Host '  Numero da porta (ex: 443)').Trim(); if ($port) { $conn = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 5; if ($conn) { $conn | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; Write-Host "  Porta $port -> PID $($_.OwningProcess) -> $($p.ProcessName)" } } else { Write-Host '  Nenhum processo encontrado nessa porta.' } }; Invoke-BIAPause; Show-ToolsMenu }
        'o' { & wsl --list 2>$null; if ($LASTEXITCODE -ne 0) { Write-BIAMessage 'WSL nao instalado.' Warning }; Invoke-BIAPause; Show-ToolsMenu }
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
    Write-BIAHeader -Subtitle ' Azure - Connect e CLI ' -IP $script:BIA_PrimaryIP
    Write-BIABox -Lines @(
        '  [1] Connect-AzAccount (PowerShell Az - login)',
        '  [2] Ver contexto Az (Get-AzContext)',
        '  [3] az login (Azure CLI)',
        '  [4] az account show (Azure CLI)',
        '  [5] Instalar modulo Az (PowerShell)',
        '  [6] Instalar Azure CLI (winget)',
        '  [0] Voltar'
    )
    $op = (Read-Host '  Escolha').Trim()
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
    Write-BIAHeader -Subtitle ' Instalar aplicativos (winget) ' -IP $script:BIA_PrimaryIP
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
$script:BIA_FarewellMessages = @(
    'Se precisar de mim, e so chamar. Ate mais!',
    'Foi um prazer ajudar. Ate a proxima!',
    'Qualquer coisa, estarei por aqui. Ate mais!',
    'Encerrando... Obrigado por usar o BIA. Ate logo!',
    'Valeu! Quando precisar, e so abrir de novo. Ate!'
)
function Exit-BIA {
    Write-BIAHeader -IP $script:BIA_PrimaryIP
    $farewell = $script:BIA_FarewellMessages[(Get-Random -Maximum $script:BIA_FarewellMessages.Count)]
    $pad = [Math]::Max(0, ($ScreenWidth - $farewell.Length - 4) / 2)
    Write-Host ''
    Write-Host (' ' * [int]$pad) -NoNewline
    Show-BIATyping -Text "[ BIA ] $farewell" -DelayMs 35 -Color Success
    Write-Host ''
    $cred = ' Desenvolvido por Iran Ribeiro - https://github.com/IranRibeiro55 '
    $pad2 = [Math]::Max(0, ($ScreenWidth - $cred.Length) / 2)
    Write-Host (' ' * [int]$pad2) -NoNewline
    Show-BIATyping -Text $cred -DelayMs 15 -Color Muted
    Write-Host ''
    if ($env:BIA_DEBUG -eq '1') {
        Write-Host (' ' * [int]$pad) -NoNewline
        Write-Host 'DEBUG ativo: pressione ENTER para fechar.' -ForegroundColor $BIA_Theme.Muted
        Read-Host
    }
    exit 0
}

# ========== INICIO ==========
$script:BIA_PrimaryIP = Get-BIAPrimaryIP
try { Show-BIASplash } catch { Write-BIAHeader -IP $script:BIA_PrimaryIP }
Write-BIAHeader -IP $script:BIA_PrimaryIP
Show-BIALoadingShort -Message 'Coletando dados da maquina...' -Steps 10
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
Show-BIATyping -Text ' Como posso ajudar? (ENTER para ver o menu) ' -DelayMs 25 -NoNewline -Color Accent
Write-Host ''
Read-Host
Show-MainMenu
