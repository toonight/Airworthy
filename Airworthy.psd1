@{
    RootModule           = 'Airworthy.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '68dfdc89-9ca8-4892-8a7a-b19b0d8e2835'
    Author               = 'Toonight'
    CompanyName          = 'Community'
    Copyright            = 'Copyright 2026 Toonight'
    Description          = 'Offline static analyzer that scores the security of custom AI agent harness configurations (VS Code GitHub Copilot, Claude Code, Copilot CLI, MCP).'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @('Invoke-Airworthy')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('security', 'ai-agents', 'mcp', 'copilot', 'github-copilot', 'vscode', 'claude-code', 'copilot-cli', 'static-analysis', 'sarif', 'owasp')
            ProjectUri = 'https://github.com/toonight/Airworthy'
            LicenseUri = 'https://github.com/toonight/Airworthy/blob/main/LICENSE'
        }
    }
}
