$errors = @()
$tokens = @()
[System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw WS1API.psm1), [ref]$errors) | Out-Null

if ($errors) {
    $errors | ForEach-Object {
        Write-Host "Error at line $($_.Token.StartLine): $($_.Message)"
        Write-Host "Token: $($_.Token.Content)"
    }
} else {
    Write-Host "No tokenization errors"
}
