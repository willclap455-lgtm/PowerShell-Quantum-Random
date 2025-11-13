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

# Set strict mode to catch common issues when this script is dot-sourced.
Set-StrictMode -Version Latest

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

        [switch]$RandomChainId,

        [switch]$IncludeMetadata
    )

    if ($Min -gt $Max) {
        throw [System.ArgumentException]::new('The Min value must be less than or equal to Max.')
    }

    $normalisedBaseUri = $BaseUri.TrimEnd('/')
    $chainParameterWasBound = $PSBoundParameters.ContainsKey('ChainId')
    if ($RandomChainId) {
        if ($chainParameterWasBound) {
            $seedInfos = @(Select-RandomSeedsFromSingleChain -BaseUri $normalisedBaseUri -ChainId $ChainId -Count $Count)
        } else {
            $seedInfos = @(Select-RandomSeedsAcrossChains -BaseUri $normalisedBaseUri -Count $Count)
        }
    } else {
        $seedInfos = @(Get-CurbySeed -BaseUri $normalisedBaseUri -ChainId $ChainId -Count $Count)
    }

    if (-not $seedInfos -or $seedInfos.Count -eq 0) {
        throw "Unable to obtain entropy seeds from $normalisedBaseUri."
    }

    $seedStates = [List[pscustomobject]]::new()
    foreach ($seedInfo in $seedInfos) {
        $seedStates.Add([pscustomobject]@{
                Info    = $seedInfo
                Buffer  = [Queue[byte]]::new()
                Counter = [ref]([UInt64]0)
            })
    }

    if ($seedStates.Count -eq 0) {
        throw "Unable to initialise entropy buffers for seeds returned from $normalisedBaseUri."
    }

    $rangeValue = [BigInteger]::Parse((($Max - $Min) + 1).ToString())
    $results = [List[long]]::new()
    $metadataEntries = [List[pscustomobject]]::new()

    if ($rangeValue -eq [BigInteger]::One) {
        for ($i = 0; $i -lt $Count; $i++) {
            $results.Add($Min)
            $currentSeed = $seedStates[$i % $seedStates.Count].Info
            $metadataEntries.Add([pscustomobject]@{
                    ChainId   = $currentSeed.ChainId
                    Index     = $currentSeed.Index
                    Timestamp = $currentSeed.Timestamp
                })
        }

        return Resolve-Output -Values $results -Metadata $metadataEntries -IncludeMetadata:$IncludeMetadata
    }

    $byteCount = Get-ByteRequirement -Range $rangeValue
    $maxValue = Get-MaxValueForByteCount -ByteCount $byteCount
    $threshold = $maxValue - ($maxValue % $rangeValue)

    for ($i = 0; $i -lt $Count; $i++) {
        $stateIndex = $i % $seedStates.Count
        $state = $seedStates[$stateIndex]
        $seedInfo = $state.Info
        $seed = $seedInfo.Bytes

        if (-not $seed -or $seed.Length -eq 0) {
            throw "Unable to obtain entropy seed from $normalisedBaseUri."
        }

        $candidate = [BigInteger]::Zero

        while ($true) {
            $entropyBytes = Get-Entropy -Seed $seed -Buffer $state.Buffer -Counter $state.Counter -ByteCount $byteCount

            if (-not $entropyBytes -or $entropyBytes.Length -eq 0) {
                throw 'Unable to derive entropy bytes for random candidate.'
            }

            $candidate = Convert-BytesToBigInteger -Bytes $entropyBytes

            if ($candidate -lt $threshold) {
                break
            }
        }

        $offset = [BigInteger]::Remainder($candidate, $rangeValue)
        $results.Add($Min + [long]$offset)
        $metadataEntries.Add([pscustomobject]@{
                ChainId   = $seedInfo.ChainId
                Index     = $seedInfo.Index
                Timestamp = $seedInfo.Timestamp
            })
    }

    Resolve-Output -Values $results -Metadata $metadataEntries -IncludeMetadata:$IncludeMetadata
}

function Resolve-Output {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [List[long]]$Values,

        [Parameter(Mandatory)]
        [List[pscustomobject]]$Metadata,

        [switch]$IncludeMetadata
    )

    if (-not $IncludeMetadata) {
        return $Values.ToArray()
    }

    if (-not $Metadata -or $Metadata.Count -ne $Values.Count) {
        throw 'Metadata entries must match the number of values when IncludeMetadata is specified.'
    }

    for ($i = 0; $i -lt $Values.Count; $i++) {
        $value = $Values[$i]
        $entryMetadata = $Metadata[$i]

        [pscustomobject]@{
            Value      = $value
            PulseIndex = $entryMetadata.Index
            Timestamp  = $entryMetadata.Timestamp
            ChainId    = $entryMetadata.ChainId
        }
    }
}

function Get-CurbySeed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUri,

        [Parameter(Mandatory)]
        [string]$ChainId,

        [ValidateRange(1, 1024)]
        [int]$Count = 1
    )

    $uri = '{0}/chains/{1}/pulses?limit={2}' -f $BaseUri, $ChainId, $Count

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop
    } catch {
        throw "Failed to call CURBy API ($uri): $($_.Exception.Message)"
    }

    if (-not $response) {
        throw 'CURBy API returned no data.'
    }

    $pulses = if ($response -is [System.Array]) { $response } else { @($response) }

    if (-not $pulses -or $pulses.Count -eq 0) {
        throw 'CURBy API did not return any pulses.'
    }

    $seeds = [List[pscustomobject]]::new()
    $limit = [System.Math]::Min($Count, $pulses.Count)

    for ($i = 0; $i -lt $limit; $i++) {
        $pulse = $pulses[$i]

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

        $chainCid = $null
        $chainCidRaw = $pulse.data.chainCid
        if ($chainCidRaw) {
            if ($chainCidRaw -is [string]) {
                $chainCid = $chainCidRaw
            } else {
                $chainCidProperty = $chainCidRaw.PSObject.Properties['/']
                if ($chainCidProperty -and $chainCidProperty.Value) {
                    $chainCid = [string]$chainCidProperty.Value
                }
            }
        }

        if (-not $chainCid) {
            $pulseCidRaw = $pulse.cid
            if ($pulseCidRaw) {
                if ($pulseCidRaw -is [string]) {
                    $chainCid = $pulseCidRaw
                } else {
                    $pulseCidProperty = $pulseCidRaw.PSObject.Properties['/']
                    if ($pulseCidProperty -and $pulseCidProperty.Value) {
                        $chainCid = [string]$pulseCidProperty.Value
                    } else {
                        $chainCid = $pulseCidRaw.ToString()
                    }
                }
            }
        }

        if (-not $chainCid) {
            $chainCid = $ChainId
        }

        $seeds.Add([pscustomobject]@{
                Bytes     = $saltBytes
                Timestamp = $timestamp
                Index     = $index
                ChainId   = $chainCid
            })
    }

    $seeds
}

function Resolve-CurbyCidValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if (-not $Value) {
        return $null
    }

    if ($Value -is [string]) {
        return $Value
    }

    $slashProperty = $Value.PSObject.Properties['/']
    if ($slashProperty -and $slashProperty.Value) {
        return [string]$slashProperty.Value
    }

    return $Value.ToString()
}

function Get-CurbyChainCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUri
    )

    $uri = '{0}/chains' -f $BaseUri

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop
    } catch {
        throw "Failed to call CURBy API ($uri): $($_.Exception.Message)"
    }

    if (-not $response) {
        throw 'CURBy API returned no chain metadata.'
    }

    $rawChains = if ($response -is [System.Array]) {
        $response
    } elseif ($response.chains) {
        $response.chains
    } elseif ($response.items) {
        $response.items
    } else {
        @($response)
    }

    if (-not $rawChains -or $rawChains.Count -eq 0) {
        throw 'CURBy API did not include any chain entries.'
    }

    $chains = [List[pscustomobject]]::new()
    foreach ($chain in $rawChains) {
        $chainId = $null

        if ($chain.cid) {
            $chainId = Resolve-CurbyCidValue -Value $chain.cid
        }

        if (-not $chainId -and $chain.data -and $chain.data.cid) {
            $chainId = Resolve-CurbyCidValue -Value $chain.data.cid
        }

        if (-not $chainId -and $chain.data -and $chain.data.chainCid) {
            $chainId = Resolve-CurbyCidValue -Value $chain.data.chainCid
        }

        if ($chainId) {
            $chains.Add([pscustomobject]@{
                    ChainId  = $chainId
                    Metadata = $chain
                })
        }
    }

    if ($chains.Count -eq 0) {
        throw 'CURBy API response did not include resolvable chain identifiers.'
    }

    return $chains
}

function Select-RandomSeedsFromSingleChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUri,

        [Parameter(Mandatory)]
        [string]$ChainId,

        [Parameter(Mandatory)]
        [ValidateRange(1, 1024)]
        [int]$Count
    )

    $poolRequestCount = [System.Math]::Min([System.Math]::Max($Count * 4, 32), 1024)
    $seedPool = @(Get-CurbySeed -BaseUri $BaseUri -ChainId $ChainId -Count $poolRequestCount)

    if (-not $seedPool -or $seedPool.Count -eq 0) {
        throw "Unable to obtain entropy seeds from $BaseUri for chain $ChainId."
    }

    $selectedSeeds = [List[pscustomobject]]::new()

    for ($i = 0; $i -lt $Count; $i++) {
        $randomIndex = Get-Random -Minimum 0 -Maximum $seedPool.Count
        $selectedSeeds.Add($seedPool[$randomIndex])
    }

    return $selectedSeeds
}

function Select-RandomSeedsAcrossChains {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUri,

        [Parameter(Mandatory)]
        [ValidateRange(1, 1024)]
        [int]$Count
    )

    $chains = @(Get-CurbyChainCatalog -BaseUri $BaseUri)
    if (-not $chains -or $chains.Count -eq 0) {
        throw "CURBy API did not return any chains from $BaseUri."
    }

    $selectedChainIds = [List[string]]::new()
    for ($i = 0; $i -lt $Count; $i++) {
        $randomChainIndex = Get-Random -Minimum 0 -Maximum $chains.Count
        $selectedChainIds.Add($chains[$randomChainIndex].ChainId)
    }

    $requirements = @{}
    foreach ($chainId in $selectedChainIds) {
        if ($requirements.ContainsKey($chainId)) {
            $requirements[$chainId]++
        } else {
            $requirements[$chainId] = 1
        }
    }

    $seedPools = @{}
    foreach ($chainId in $requirements.Keys) {
        $requiredCount = $requirements[$chainId]
        $poolRequestCount = [System.Math]::Min([System.Math]::Max($requiredCount * 4, 32), 1024)
        $pool = @(Get-CurbySeed -BaseUri $BaseUri -ChainId $chainId -Count $poolRequestCount)
        if (-not $pool -or $pool.Count -eq 0) {
            throw "Unable to obtain entropy seeds from $BaseUri for chain $chainId."
        }
        $seedPools[$chainId] = $pool
    }

    $selectedSeeds = [List[pscustomobject]]::new()
    for ($i = 0; $i -lt $Count; $i++) {
        $chainId = $selectedChainIds[$i]
        $pool = $seedPools[$chainId]
        $randomIndex = Get-Random -Minimum 0 -Maximum $pool.Count
        $selectedSeeds.Add($pool[$randomIndex])
    }

    return $selectedSeeds
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
        [Queue[byte]]$Buffer,

        [Parameter(Mandatory)]
        [ref]$Counter,

        [Parameter(Mandatory)]
        [int]$ByteCount
    )

    if ($ByteCount -le 0) {
        throw [System.ArgumentOutOfRangeException]::new('ByteCount', $ByteCount, 'ByteCount must be greater than zero.')
    }

    while ($Buffer.Count -lt $ByteCount) {
        $counterBytes = [System.BitConverter]::GetBytes([UInt64]$Counter.Value)
        if ([System.BitConverter]::IsLittleEndian) {
            [Array]::Reverse($counterBytes)
        }

        $input = [byte[]]::new($Seed.Length + $counterBytes.Length)
        [System.Buffer]::BlockCopy($Seed, 0, $input, 0, $Seed.Length)
        [System.Buffer]::BlockCopy($counterBytes, 0, $input, $Seed.Length, $counterBytes.Length)

        $hash = [System.Security.Cryptography.SHA512]::HashData($input)
        foreach ($byteValue in $hash) {
            $Buffer.Enqueue($byteValue)
        }
        $Counter.Value++
    }

    $result = [byte[]]::new($ByteCount)
    for ($i = 0; $i -lt $ByteCount; $i++) {
        $result[$i] = $Buffer.Dequeue()
    }

    return $result
}

function Convert-BytesToBigInteger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline = $true)]
        [byte[]]$Bytes
    )

    process {
        if (-not $Bytes) {
            return [BigInteger]::Zero
        }

        $result = [BigInteger]::Zero
        foreach ($byteValue in $Bytes) {
            $result = ($result * 256) + $byteValue
        }

        return $result
    }
}
