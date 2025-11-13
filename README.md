# CURBy Randomness Cmdlet

`Get-CurbyRandomNumber` is a PowerShell cmdlet that calls the CURBy HTTP API
(`https://random.colorado.edu/api`) to obtain verifiable randomness sourced
from the University of Colorado's quantum randomness beacon.

The cmdlet lives in `powershell/CurbyRandom/CurbyRandom.psm1` and is designed
to be imported into PowerShell 7+ sessions.

## Getting Started

1. Open PowerShell (6 or later) on a machine with internet access.
2. Import the module:

   ```powershell
   Import-Module (Join-Path (Get-Location) 'powershell/CurbyRandom/CurbyRandom.psm1')
   ```

   Adjust the path if you're importing from a different location.

## Usage

Generate a single number inside a range:

```powershell
Get-CurbyRandomNumber -Min 1 -Max 100
```

Or request multiple values:

```powershell
Get-CurbyRandomNumber -Min 1 -Max 100 -Count 5
```

Include metadata from the underlying CURBy pulse:

```powershell
Get-CurbyRandomNumber -Min 10 -Max 99 -Count 3 -IncludeMetadata
```

Use a random CURBy chain for each value:

```powershell
Get-CurbyRandomNumber -Min 1 -Max 100 -Count 5 -RandomChainId
```

Lock to a specific chain while sampling pulses at random:

```powershell
Get-CurbyRandomNumber -Min 1 -Max 100 -Count 5 -RandomChainId -ChainId 'bafyriqci6f3st2mg7gq733ho4zvvth32zpy2mtiylixwmhoz6d627eo3jfpmbxepe54u2zdvymonq5sp3armtm4rodxsynsirr5g3xsbd3q4s'
```

Example response with `-IncludeMetadata`:

```
Value PulseIndex Timestamp               ChainId
----- ---------- ---------               -------
27    1074143    2025-11-10T17:29:00.242Z bafyriqci6f3st2mg7gq733ho4zvvth32zpy2mtiylixwmhoz6d627eo3jfpmbxepe54u2zdvymonq5sp3armtm4rodxsynsirr5g3xsbd3q4s
54    1074143    2025-11-10T17:29:00.242Z bafyriqci6f3st2mg7gq733ho4zvvth32zpy2mtiylixwmhoz6d627eo3jfpmbxepe54u2zdvymonq5sp3armtm4rodxsynsirr5g3xsbd3q4s
63    1074143    2025-11-10T17:29:00.242Z bafyriqci6f3st2mg7gq733ho4zvvth32zpy2mtiylixwmhoz6d627eo3jfpmbxepe54u2zdvymonq5sp3armtm4rodxsynsirr5g3xsbd3q4s
```

## How It Works

- Calls `https://random.colorado.edu/api/chains/<CURBy-RNG-CID>/pulses?limit=1`
  to fetch the latest randomness pulse.
- Extracts the 64-byte salt payload, base64-decodes it, and uses it as high-quality entropy.
- Expands the entropy with SHA-512 and produces unbiased integers via rejection sampling.

The default chain identifier corresponds to the CURBy RNG chain (version 1.0.x).
You can override `-ChainId` or `-BaseUri` to target different Twine-compatible sources.

## Verification

After importing the module, you can run a multi-sample check to confirm that
entropy expansion works for larger batches:

```powershell
Get-CurbyRandomNumber -Min 5 -Max 15 -Count 25 -IncludeMetadata
```

The command should return 25 entries without errors. If the request fails, ensure
that PowerShell can reach `https://random.colorado.edu` and rerun the command.
