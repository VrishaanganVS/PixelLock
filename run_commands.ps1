<#
Run script for PixelLock project (PowerShell)
Usage:
  .\run_commands.ps1 -Action compile
  .\run_commands.ps1 -Action run
  .\run_commands.ps1 -Action clean
  .\run_commands.ps1 -Action all   # compile then run
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('compile','run','clean','all')]
    [string]$Action = 'compile'
)

function Compile-Project {
    Write-Host "Compiling project..."
    if (-not (Test-Path -Path "out")) { New-Item -ItemType Directory -Path "out" | Out-Null }
    javac -d out src\AESImageEncryptor.java
    if ($LASTEXITCODE -eq 0) { Write-Host "Compilation succeeded." } else { Write-Error "Compilation failed." }
}

function Run-Project {
    Write-Host "Running project (expects zebra.bmp in the working directory)..."
    java -cp out AESImageEncryptor
}

function Clean-Project {
    Write-Host "Cleaning build artifacts and generated images..."
    if (Test-Path -Path "out") { Remove-Item -Recurse -Force -Path "out" }
    Get-ChildItem -Filter "*encrypted*.bmp" -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Filter "*decrypted*.bmp" -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Host "Clean completed."
}

switch ($Action) {
    'compile' { Compile-Project }
    'run' { Run-Project }
    'clean' { Clean-Project }
    'all' { Compile-Project; if ($LASTEXITCODE -eq 0) { Run-Project } }
}
