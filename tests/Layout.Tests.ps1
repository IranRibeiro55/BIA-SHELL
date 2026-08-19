# Sanity checks for the launcher files.
# Run from repo root:
#   Invoke-Pester -Path .\tests -Output Detailed

Describe "BIA-SHELL layout" {
    It "has the four files people actually need" {
        $root = Split-Path $PSScriptRoot -Parent
        @(
            "BIA-Launcher.bat"
            "BIA-Shell.ps1"
            "BIA-UI.ps1"
            "BIA-Lang.ps1"
        ) | ForEach-Object {
            Join-Path $root $_ | Should -Exist
        }
    }
}
