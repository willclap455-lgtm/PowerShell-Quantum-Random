<#
.SYNOPSIS
Gets one or more random numbers sourced from the CURBy randomness beacon.

.DESCRIPTION
`Get-CurbyRandomNumber` calls the CURBy HTTP API and derives uniform random
integers inside the requested range. The cmdlet fetches the latest CURBy RNG
pulse, decodes its salt payload, and expands it with SHA-512 to obtain
enough entropy for the requested amount of numbers.

.LINK
https://random.colorado.edu
#>

using namespace System.Collections.Generic
using namespace System.Numerics

function Get-CurbyRandomNumber {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [long]$Min,

        [Parameter(Mandatory)]
        [long]$Max,

        [ValidateRange(1, 1024)]
        [int]$Count = 1,

        [ValidateNotNullOrEmpty()]
        [string]$BaseUri = 'https://random.colorado.edu/api',

        [ValidateNotNullOrEmpty()]
        [string]$ChainId = 'bafyriqci6f3st2mg7gq733ho4zvvth32zpy2mtiylixwmhoz6d627eo3jfpmbxepe54u2zdvymonq5sp3armtm4rodxsynsirr5g3xsbd3q4s',

        [switch]$IncludeMetadata
    )

    if ($Min -gt $Max) {
        throw [System.ArgumentException]::new('The Min value must be less than or equal to Max.')
    }

    $rangeValue = [BigInteger]::Parse((($Max - $Min) + 1).ToString())
    $results = [List[long]]::new()

    $normalisedBaseUri = $BaseUri.TrimEnd('/')
    $seedInfo = Get-CurbySeed -BaseUri $normalisedBaseUri -ChainId $ChainId
    $seed = $seedInfo.Bytes

    if (-not $seed -or $seed.Length -eq 0) {
        throw "Unable to obtain entropy seed from $normalisedBaseUri."
    }

    if ($rangeValue -eq [BigInteger]::One) {
        for ($i = 0; $i -lt $Count; $i++) {
            $results.Add($Min)
        }

        return Resolve-Output -Values $results -Metadata ([pscustomobject]@{
                ChainId   = $ChainId
                Index     = $seedInfo.Index
                Timestamp = $seedInfo.Timestamp
            }) -IncludeMetadata:$IncludeMetadata
    }

    $byteCount = Get-ByteRequirement -Range $rangeValue
    $buffer = [List[byte]]::new()
    $counter = [uint64]0

    while ($results.Count -lt $Count) {
        $candidate = [BigInteger]::Zero
        $maxValue = Get-MaxValueForByteCount -ByteCount $byteCount
        $threshold = $maxValue - ($maxValue % $rangeValue)

        while ($true) {
            $entropy = Get-Entropy -Seed $seed -Buffer $buffer -Counter ([ref]$counter) -ByteCount $byteCount
            $entropyBytes = [byte[]]@($entropy)

            if ($entropyBytes.Length -eq 0) {
                throw 'Unable to derive entropy bytes for random candidate.'
            }

            $candidate = $entropyBytes | Convert-BytesToBigInteger

            if ($candidate -lt $threshold) {
                break
            }
        }

        $offset = [BigInteger]::Remainder($candidate, $rangeValue)
        $results.Add($Min + [long]$offset)
    }

    Resolve-Output -Values $results -Metadata ([pscustomobject]@{
            ChainId   = $ChainId
            Index     = $seedInfo.Index
            Timestamp = $seedInfo.Timestamp
        }) -IncludeMetadata:$IncludeMetadata
}

function Resolve-Output {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [List[long]]$Values,

        [Parameter(Mandatory)]
        [pscustomobject]$Metadata,

        [switch]$IncludeMetadata
    )

    if (-not $IncludeMetadata) {
        return $Values.ToArray()
    }

    foreach ($value in $Values) {
        [pscustomobject]@{
            Value      = $value
            PulseIndex = $Metadata.Index
            Timestamp  = $Metadata.Timestamp
            ChainId    = $Metadata.ChainId
        }
    }
}

function Get-CurbySeed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUri,

        [Parameter(Mandatory)]
        [string]$ChainId
    )

    $uri = '{0}/chains/{1}/pulses?limit=1' -f $BaseUri, $ChainId

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop
    } catch {
        throw "Failed to call CURBy API ($uri): $($_.Exception.Message)"
    }

    if (-not $response) {
        throw 'CURBy API returned no data.'
    }

    $pulse = if ($response -is [System.Array]) { $response[0] } else { $response }

    $payload = $pulse.data.content.payload
    if (-not $payload) {
        throw 'CURBy response did not include a payload.'
    }

    $saltWrapper = $payload.salt.'/'
    if (-not $saltWrapper) {
        throw 'CURBy payload did not include a salt value.'
    }

    $saltBase64 = $saltWrapper.bytes
    $saltBytes = Convert-FromBase64Unpadded -Value $saltBase64

    $timestamp = [datetime]::Parse($payload.timestamp).ToUniversalTime()
    $index = [long]$pulse.data.content.index

    [pscustomobject]@{
        Bytes     = $saltBytes
        Timestamp = $timestamp
        Index     = $index
    }
}

function Convert-FromBase64Unpadded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $sanitised = $Value.Trim()
    $paddingLength = (4 - ($sanitised.Length % 4)) % 4
    if ($paddingLength -gt 0) {
        $sanitised = $sanitised + ('=' * $paddingLength)
    }

    try {
        return [System.Convert]::FromBase64String($sanitised)
    } catch {
        throw "Unable to decode base64 value from CURBy payload: $($_.Exception.Message)"
    }
}

function Get-ByteRequirement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [BigInteger]$Range
    )

    $byteCount = 1
    $capacity = [BigInteger]::One * 256

    while ($capacity -lt $Range) {
        $byteCount++
        $capacity *= 256
    }

    return $byteCount
}

function Get-MaxValueForByteCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$ByteCount
    )

    $value = [BigInteger]::One
    for ($i = 0; $i -lt $ByteCount; $i++) {
        $value *= 256
    }
    return $value
}

function Get-Entropy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Seed,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [List[byte]]$Buffer,

        [Parameter(Mandatory)]
        [ref]$Counter,

        [Parameter(Mandatory)]
        [int]$ByteCount
    )

    while ($Buffer.Count -lt $ByteCount) {
        $counterBytes = [System.BitConverter]::GetBytes([UInt64]$Counter.Value)
        if ([System.BitConverter]::IsLittleEndian) {
            [Array]::Reverse($counterBytes)
        }

        $input = [byte[]]::new($Seed.Length + $counterBytes.Length)
        [System.Buffer]::BlockCopy($Seed, 0, $input, 0, $Seed.Length)
        [System.Buffer]::BlockCopy($counterBytes, 0, $input, $Seed.Length, $counterBytes.Length)

        $hash = [System.Security.Cryptography.SHA512]::HashData($input)
        $Buffer.AddRange($hash)
        $Counter.Value++
    }

    $segment = $Buffer.GetRange(0, $ByteCount)
    $Buffer.RemoveRange(0, $ByteCount)
    return $segment.ToArray()
}

function Convert-BytesToBigInteger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline = $true)]
        [byte]$Byte
    )

    begin {
        $result = [BigInteger]::Zero
    }

    process {
        $result = ($result * 256) + $Byte
    }

    end {
        return $result
    }
}

Export-ModuleMember -Function Get-CurbyRandomNumber
