# BIA Shell - Modulo de Interface (UI) v2
# Animacoes: spinner, transicoes, loading, progresso, typing

$script:BIA_Theme = @{
    Title    = 'Cyan'
    Header   = 'DarkCyan'
    Menu     = 'White'
    Success  = 'Green'
    Warning  = 'Yellow'
    Error    = 'Red'
    Accent   = 'Cyan'
    Muted    = 'DarkGray'
}

try {
    $script:ScreenWidth = [Math]::Min(120, $Host.UI.RawUI.WindowSize.Width)
} catch {
    $script:ScreenWidth = 80
}

# ---- Spinner (animacao rotativa durante operacao) ----
$script:BIA_SpinnerChars = @('|', '/', '-', '\')
function Show-BIASpinner {
    param(
        [string]$Message = 'Aguarde...',
        [scriptblock]$ScriptBlock,
        [int]$TimeoutSeconds = 0
    )
    $job = $null
    if ($ScriptBlock) {
        $job = Start-Job -ScriptBlock $ScriptBlock
        $elapsed = 0
        $idx = 0
        while ($job.State -eq 'Running') {
            $char = $BIA_SpinnerChars[$idx % $BIA_SpinnerChars.Length]
            Write-Host "`r  [ $char ] $Message    " -NoNewline -ForegroundColor $BIA_Theme.Accent
            $idx++
            Start-Sleep -Milliseconds 120
            $elapsed += 0.12
            if ($TimeoutSeconds -gt 0 -and $elapsed -ge $TimeoutSeconds) { break }
        }
        $result = Receive-Job $job
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        Write-Host "`r  [ OK ] $Message    " -ForegroundColor $BIA_Theme.Success
        return $result
    }
    # Sem scriptblock: so gira por um tempo
    $sec = if ($TimeoutSeconds -gt 0) { $TimeoutSeconds } else { 3 }
    $end = (Get-Date).AddSeconds($sec)
    $idx = 0
    while ((Get-Date) -lt $end) {
        $char = $BIA_SpinnerChars[$idx % $BIA_SpinnerChars.Length]
        Write-Host "`r  [ $char ] $Message    " -NoNewline -ForegroundColor $BIA_Theme.Accent
        $idx++
        Start-Sleep -Milliseconds 120
    }
    Write-Host "`r  [ OK ] $Message    " -ForegroundColor $BIA_Theme.Success
}

# ---- Transicao ao entrar em menu ----
function Show-BIATransition {
    param(
        [string]$Title = 'Carregando...',
        [int]$Milliseconds = 600
    )
    $pad = [Math]::Max(0, ($ScreenWidth - $Title.Length) / 2)
    $steps = [Math]::Max(4, $Milliseconds / 150)
    for ($i = 0; $i -le $steps; $i++) {
        Clear-Host
        Write-Host ''
        Write-Host (' ' * [int]$pad) -NoNewline
        $dots = '.' * ($i % 4)
        Write-Host "$Title$dots" -ForegroundColor $BIA_Theme.Accent
        Write-Host ''
        $barLen = [Math]::Min(40, $ScreenWidth - 10)
        $filled = [int](($i / $steps) * $barLen)
        $bar = ('#' * $filled).PadRight($barLen, ' ')
        $padBar = [Math]::Max(0, ($ScreenWidth - $barLen - 4) / 2)
        Write-Host (' ' * [int]$padBar) -NoNewline
        Write-Host "[$bar]" -ForegroundColor $BIA_Theme.Header
        Start-Sleep -Milliseconds ([Math]::Min(150, $Milliseconds / $steps))
    }
}

# ---- Efeito de digitacao ----
function Show-BIATyping {
    param(
        [string]$Text,
        [int]$DelayMs = 30,
        [switch]$NoNewline
    )
    foreach ($c in $Text.ToCharArray()) {
        Write-Host $c -NoNewline -ForegroundColor $BIA_Theme.Menu
        Start-Sleep -Milliseconds $DelayMs
    }
    if (-not $NoNewline) { Write-Host '' }
}

# ---- Loading full screen (reutilizavel) ----
function Show-BIALoading {
    param(
        [string]$Message = 'Carregando BIA Shell...',
        [int]$Seconds = 2
    )
    $steps = 40
    $stepMs = [Math]::Max(50, ($Seconds * 1000) / $steps)
    $barWidth = [Math]::Min(50, $ScreenWidth - 20)
    $pad = [Math]::Max(0, ($ScreenWidth - $Message.Length) / 2)
    Write-Host ''
    Write-Host (' ' * [int]$pad) -NoNewline
    Write-Host $Message -ForegroundColor $BIA_Theme.Accent
    Write-Host ''
    for ($i = 0; $i -le $steps; $i++) {
        $pct = [int](($i / $steps) * 100)
        $filled = [int](($i / $steps) * $barWidth)
        $bar = ('#' * $filled).PadRight($barWidth, ' ')
        $padBar = [Math]::Max(0, ($ScreenWidth - $barWidth - 10) / 2)
        Write-Host (' ' * [int]$padBar) -NoNewline
        Write-Host '[' -NoNewline -ForegroundColor $BIA_Theme.Header
        Write-Host $bar -NoNewline -ForegroundColor $BIA_Theme.Success
        Write-Host '] ' -NoNewline -ForegroundColor $BIA_Theme.Header
        Write-Host ("{0,3}%" -f $pct) -ForegroundColor $BIA_Theme.Title
        if ($i -lt $steps) {
            try { $cursorTop = [Console]::CursorTop; [Console]::SetCursorPosition(0, $cursorTop - 1) } catch { }
        }
        Start-Sleep -Milliseconds $stepMs
    }
    Write-Host ''
}

function Show-BIALoadingShort {
    param([string]$Message = 'Processando...', [int]$Steps = 15)
    $barWidth = 25
    for ($i = 0; $i -le $Steps; $i++) {
        $filled = [int](($i / $Steps) * $barWidth)
        $bar = ('#' * $filled).PadRight($barWidth, '.')
        Write-Host "`r  $Message [$bar] $i/$Steps " -NoNewline -ForegroundColor $BIA_Theme.Accent
        Start-Sleep -Milliseconds 80
    }
    Write-Host "`r  $Message [" -NoNewline
    Write-Host ('#' * $barWidth) -NoNewline -ForegroundColor $BIA_Theme.Success
    Write-Host "] OK.    " -ForegroundColor $BIA_Theme.Success
}

function Write-BIAHeader {
    param(
        [string]$Subtitle = '',
        [string]$IP = ''
    )
    $Host.UI.RawUI.WindowTitle = 'BIA Shell - CoreSafe'
    Clear-Host
    $line = '=' * $ScreenWidth
    Write-Host $line -ForegroundColor $BIA_Theme.Header
    $title = "  BIA SHELL  "
    $user = "Usuario: $env:USERNAME  |  Computador: $env:COMPUTERNAME"
    if ($IP) { $user += "  |  IP: $IP" }
    $full = $title + '  ::  ' + $user
    $pad = [Math]::Max(0, ($ScreenWidth - $full.Length) / 2)
    Write-Host (' ' * [int]$pad) -NoNewline
    Write-Host $title -ForegroundColor $BIA_Theme.Title -NoNewline
    Write-Host '  ::  ' -ForegroundColor $BIA_Theme.Header -NoNewline
    Write-Host $user -ForegroundColor $BIA_Theme.Muted
    Write-Host $line -ForegroundColor $BIA_Theme.Header
    if ($Subtitle) {
        $sp = [Math]::Max(0, ($ScreenWidth - $Subtitle.Length) / 2)
        Write-Host (' ' * [int]$sp) -NoNewline
        Write-Host $Subtitle -ForegroundColor $BIA_Theme.Accent
    }
    Write-Host ''
}

function Write-BIABox {
    param(
        [string[]]$Lines,
        [string]$Title = ''
    )
    $maxLen = ($Lines + $Title | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $w = [Math]::Min($maxLen + 4, $ScreenWidth - 4)
    $top = '+' + ('-' * ($w - 2)) + '+'
    Write-Host $top -ForegroundColor $BIA_Theme.Accent
    if ($Title) {
        Write-Host '| ' -NoNewline -ForegroundColor $BIA_Theme.Accent
        Write-Host $Title.PadRight($w - 4) -NoNewline -ForegroundColor $BIA_Theme.Title
        Write-Host ' |' -ForegroundColor $BIA_Theme.Accent
        Write-Host $top -ForegroundColor $BIA_Theme.Accent
    }
    foreach ($l in $Lines) {
        $len = [Math]::Min($l.Length, $w - 4)
        $padded = $l.Substring(0, [Math]::Max(0, $len)).PadRight($w - 4)
        Write-Host '| ' -NoNewline -ForegroundColor $BIA_Theme.Accent
        Write-Host $padded -NoNewline -ForegroundColor $BIA_Theme.Menu
        Write-Host ' |' -ForegroundColor $BIA_Theme.Accent
    }
    Write-Host $top -ForegroundColor $BIA_Theme.Accent
}

function Show-BIASplash {
    Clear-Host
    $art = @'
   ____  ___    ____
  | __ )|_ _|  / ___|  ___ _ __ __ _ _ __
  |  _ \ | |   \___ \ / _ \ '__/ _` | '_ \
  | |_) || |    ___) |  __/ | | (_| | | | |
  |____/|___|  |____/ \___|_|  \__,_|_| |_|
     SHELL v8 - CoreSafe
  Desenvolvido por Iran Ribeiro
  https://github.com/IranRibeiro55
'@
    $lines = $art -split "`n"
    $maxLen = ($lines | Measure-Object -Property Length -Maximum).Maximum
    $pad = [Math]::Max(0, ($ScreenWidth - $maxLen) / 2)
    $i = 0
    foreach ($line in $lines) {
        Write-Host (' ' * [int]$pad) -NoNewline
        if ($i -eq 7) { Write-Host $line -ForegroundColor DarkGray }
        elseif ($i -eq 8) { Write-Host $line -ForegroundColor Cyan }
        else { Write-Host $line -ForegroundColor Cyan }
        $i++
    }
    Write-Host ''
    Show-BIALoading -Message ' Inicializando modulos... ' -Seconds 2
}

function Write-BIAProgressBar {
    param(
        [string]$Message,
        [int]$TotalSteps = 15,
        [ValidateSet('bar','dots','pulse')]
        [string]$Style = 'bar'
    )
    $barWidth = 30
    for ($i = 0; $i -le $TotalSteps; $i++) {
        if ($Style -eq 'dots') {
            $bar = ('.' * $i).PadRight($TotalSteps, ' ')
        } elseif ($Style -eq 'pulse') {
            $pos = $i % $barWidth
            $bar = (' ' * $barWidth).ToCharArray()
            $bar[[Math]::Min($pos, $barWidth - 1)] = '#'
            $bar = -join $bar
        } else {
            $filled = [int](($i / $TotalSteps) * $barWidth)
            $bar = ('#' * $filled).PadRight($barWidth, '.')
        }
        Write-Host "`r  $Message [$bar] $i/$TotalSteps " -NoNewline -ForegroundColor $BIA_Theme.Accent
        Start-Sleep -Milliseconds 100
    }
    Write-Host "`r  $Message [" -NoNewline
    Write-Host ('#' * $barWidth) -NoNewline -ForegroundColor $BIA_Theme.Success
    Write-Host "] Concluido.    " -ForegroundColor $BIA_Theme.Success
}

function Invoke-BIAPause {
    $pad = [Math]::Max(0, ($ScreenWidth - 45) / 2)
    Write-Host ''
    Write-Host (' ' * [int]$pad) -NoNewline
    Write-Host '[ BIA ] Pressione ENTER para continuar... ' -ForegroundColor $BIA_Theme.Muted
    Read-Host
}

function Get-BIAInput {
    param([string]$Prompt = 'Escolha', [string]$VariableName = 'Choice')
    Write-Host "  $Prompt : " -NoNewline -ForegroundColor $BIA_Theme.Menu
    $val = (Read-Host).Trim()
    Set-Variable -Name $VariableName -Value $val -Scope 1
    return $val
}

function Write-BIAMessage {
    param(
        [string]$Text,
        [ValidateSet('Info','Success','Warning','Error')]
        [string]$Type = 'Info'
    )
    $color = switch ($Type) { Success { $BIA_Theme.Success } Warning { $BIA_Theme.Warning } Error { $BIA_Theme.Error } default { $BIA_Theme.Accent } }
    Write-Host "  [ BIA ] $Text" -ForegroundColor $color
}

# Painel de informacoes (chave : valor) para dashboard
function Write-BIAInfoPanel {
    param(
        [string]$Title = ' Resumo da maquina ',
        [string[]]$Lines
    )
    if (-not $Lines -or $Lines.Count -eq 0) { return }
    $maxLen = ($Lines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $w = [Math]::Min($maxLen + 4, $ScreenWidth - 4)
    $top = '+' + ('-' * ($w - 2)) + '+'
    Write-Host $top -ForegroundColor $BIA_Theme.Header
    Write-Host '| ' -NoNewline -ForegroundColor $BIA_Theme.Accent
    Write-Host $Title.PadRight($w - 4) -NoNewline -ForegroundColor $BIA_Theme.Title
    Write-Host ' |' -ForegroundColor $BIA_Theme.Accent
    Write-Host $top -ForegroundColor $BIA_Theme.Header
    foreach ($l in $Lines) {
        $len = [Math]::Min($l.Length, $w - 4)
        $padded = $l.Substring(0, [Math]::Max(0, $len)).PadRight($w - 4)
        Write-Host '| ' -NoNewline -ForegroundColor $BIA_Theme.Accent
        Write-Host $padded -NoNewline -ForegroundColor $BIA_Theme.Menu
        Write-Host ' |' -ForegroundColor $BIA_Theme.Accent
    }
    Write-Host $top -ForegroundColor $BIA_Theme.Header
}
