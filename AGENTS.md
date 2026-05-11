# AGENTS.md

## Cursor Cloud specific instructions

### Overview

This repo contains a single PowerShell cmdlet (`Get-CurbyRandomNumber`) that generates quantum-sourced random numbers via the CURBy HTTP API at `https://random.colorado.edu/api`. There is no build step, no package manager, and no test framework.

### Runtime requirement

PowerShell 7+ (`pwsh`) is the only dependency. It is installed from the Microsoft APT repository for Ubuntu (see update script). The cmdlet relies on .NET types (`System.Numerics.BigInteger`, `System.Security.Cryptography.SHA512`) that ship with PowerShell 7+.

### Running the cmdlet

Dot-source the script, then call the function:

```powershell
pwsh -Command '. /workspace/powershell/CurbyRandom/Get-CurbyRandomNumber.ps1; Get-CurbyRandomNumber -Min 1 -Max 100'
```

The README documents all parameter combinations (`-Count`, `-IncludeMetadata`, `-RandomChainId`, `-ChainId`).

### Gotchas

- The README references `CurbyRandom.psm1` but the actual file is `Get-CurbyRandomNumber.ps1`. Use dot-sourcing (`. ./path/to/Get-CurbyRandomNumber.ps1`) rather than `Import-Module`.
- The cmdlet requires live internet access to `https://random.colorado.edu`. There is no mock/stub server; all tests hit the real API.
- There are no automated tests (no Pester tests) in the repo.
- There is no linter or formatter configured for this project.
