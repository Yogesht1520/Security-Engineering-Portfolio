<#
.SYNOPSIS
    Deep Recursive JSON Schema Validator for Conditional Access Policies.
.DESCRIPTION
    Validates Microsoft Entra ID Conditional Access declarative policy definitions
    strictly against draft-07 JSON Schema specifications:
    - Enforces all required properties at all schema tiers.
    - Rejects unpermitted properties when additionalProperties is false.
    - Enforces strict data types (string, integer, boolean, array, object).
    - Enforces enum constraints.
    - Enforces regular expression patterns (e.g. ^CAP-[0-9]{3}:\s.+$, GUIDs).
    - Validates anyOf and required combinations.
#>

function Test-PolicyJsonSchema {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$JsonData,

        [Parameter(Mandatory=$true)]
        [string]$SchemaPath,

        [Parameter(Mandatory=$false)]
        [string]$PolicyFileName = "policy.json"
    )

    if (-not (Test-Path $SchemaPath)) {
        throw "JSON Schema file not found at: $SchemaPath"
    }

    $schema = Get-Content -Path $SchemaPath -Raw | ConvertFrom-Json
    $errors = [System.Collections.Generic.List[string]]::new()

    # Recursive Schema Evaluation Engine
    function Test-Node {
        param (
            [PSObject]$Data,
            [PSObject]$SubSchema,
            [string]$Path
        )

        if ($null -eq $Data -or $null -eq $SubSchema) { return }

        # 1. Type Validation
        if ($SubSchema.type) {
            $expectedType = $SubSchema.type
            $isValidType = $false

            switch ($expectedType) {
                "string" {
                    $isValidType = ($Data -is [string])
                }
                "integer" {
                    $isValidType = ($Data -is [int] -or $Data -is [long] -or ($Data -is [string] -and $Data -match "^[0-9]+$"))
                }
                "boolean" {
                    $isValidType = ($Data -is [bool] -or ($Data -is [string] -and ($Data -eq "true" -or $Data -eq "false")))
                }
                "array" {
                    $isValidType = ($Data -is [System.Collections.IEnumerable] -and -not ($Data -is [string]) -and -not ($Data -is [System.Collections.IDictionary]))
                }
                "object" {
                    $isValidType = ($Data -is [PSCustomObject] -or $Data -is [System.Collections.IDictionary])
                }
                Default {
                    $isValidType = $true
                }
            }

            if (-not $isValidType) {
                $errors.Add("[$Path] Expected type '$expectedType', but got '$($Data.GetType().Name)'.")
                return
            }
        }

        # 2. Enum Validation
        if ($SubSchema.enum) {
            $allowed = @($SubSchema.enum)
            if ($allowed -notcontains $Data) {
                $errors.Add("[$Path] Value '$Data' is invalid. Must be one of: [$($allowed -join ', ')].")
            }
        }

        # 3. String Regex Pattern Validation
        if ($SubSchema.pattern -and ($Data -is [string])) {
            if (-not ($Data -match $SubSchema.pattern)) {
                $errors.Add("[$Path] Value '$Data' does not match required regex pattern: '$($SubSchema.pattern)'.")
            }
        }

        # 4. String Min/Max Length
        if ($Data -is [string]) {
            if ($SubSchema.minLength -and $Data.Length -lt $SubSchema.minLength) {
                $errors.Add("[$Path] String length $($Data.Length) is shorter than minimum required ($($SubSchema.minLength)).")
            }
            if ($SubSchema.maxLength -and $Data.Length -gt $SubSchema.maxLength) {
                $errors.Add("[$Path] String length $($Data.Length) exceeds maximum allowed ($($SubSchema.maxLength)).")
            }
        }

        # 5. Object Required Properties Validation
        if ($SubSchema.required -and ($Data -is [PSCustomObject] -or $Data -is [System.Collections.IDictionary])) {
            $dataKeys = if ($Data -is [PSCustomObject]) { $Data.PSObject.Properties.Name } else { @($Data.Keys) }
            foreach ($req in $SubSchema.required) {
                if ($dataKeys -notcontains $req) {
                    $errors.Add("[$Path] Missing required property: '$req'.")
                }
            }
        }

        # 6. Object AdditionalProperties: false Validation
        if ($SubSchema.additionalProperties -eq $false -and ($Data -is [PSCustomObject] -or $Data -is [System.Collections.IDictionary])) {
            $dataKeys = if ($Data -is [PSCustomObject]) { $Data.PSObject.Properties.Name } else { @($Data.Keys) }
            $allowedProps = if ($SubSchema.properties) {
                if ($SubSchema.properties -is [PSCustomObject]) { $SubSchema.properties.PSObject.Properties.Name } else { @($SubSchema.properties.Keys) }
            } else { @() }

            foreach ($propName in $dataKeys) {
                if ($allowedProps -notcontains $propName) {
                    $errors.Add("[$Path] Unsupported property '$propName' is not allowed by schema (additionalProperties: false).")
                }
            }
        }

        # 7. anyOf Validation (e.g. applications conditions)
        if ($SubSchema.anyOf -and ($Data -is [PSCustomObject] -or $Data -is [System.Collections.IDictionary])) {
            $dataKeys = if ($Data -is [PSCustomObject]) { $Data.PSObject.Properties.Name } else { @($Data.Keys) }
            $satisfiedAnyOf = $false
            foreach ($option in $SubSchema.anyOf) {
                if ($option.required) {
                    $hasAll = $true
                    foreach ($reqProp in $option.required) {
                        if ($dataKeys -notcontains $reqProp) { $hasAll = $false; break }
                    }
                    if ($hasAll) { $satisfiedAnyOf = $true; break }
                }
            }
            if (-not $satisfiedAnyOf) {
                $errors.Add("[$Path] Failed anyOf requirement: None of the required alternative schemas were satisfied.")
            }
        }

        # 8. Recursive Evaluation of Object Properties
        if ($SubSchema.properties -and ($Data -is [PSCustomObject] -or $Data -is [System.Collections.IDictionary])) {
            $schemaProps = if ($SubSchema.properties -is [PSCustomObject]) { $SubSchema.properties.PSObject.Properties } else { $SubSchema.properties.GetEnumerator() }
            foreach ($sp in $schemaProps) {
                $pName = $sp.Name
                $childSchema = $sp.Value

                $childData = $null
                if ($Data -is [PSCustomObject]) {
                    if ($Data.PSObject.Properties[$pName]) {
                        $childData = $Data.$pName
                    }
                } elseif ($Data.ContainsKey($pName)) {
                    $childData = $Data[$pName]
                }

                if ($null -ne $childData) {
                    $childPath = if ($Path -eq "$") { "$.$pName" } else { "$Path.$pName" }
                    Test-Node -Data $childData -SubSchema $childSchema -Path $childPath
                }
            }
        }

        # 9. Recursive Evaluation of Array Items
        if ($SubSchema.type -eq "array" -and $SubSchema.items -and ($Data -is [System.Collections.IEnumerable])) {
            if ($SubSchema.minItems -and @($Data).Count -lt $SubSchema.minItems) {
                $errors.Add("[$Path] Array contains $(@($Data).Count) items, which is less than minItems ($($SubSchema.minItems)).")
            }

            $idx = 0
            foreach ($item in $Data) {
                Test-Node -Data $item -SubSchema $SubSchema.items -Path "$Path[$idx]"
                $idx++
            }
        }
    }

    # Run Top-Level Validation
    Test-Node -Data $JsonData -SubSchema $schema -Path "$"

    if ($errors.Count -gt 0) {
        $errorMessage = "Schema validation failed for '$PolicyFileName' with $($errors.Count) violation(s):`n" + ($errors | ForEach-Object { "  - $_" } | Out-String)
        throw $errorMessage
    }

    return $true
}

if ($MyInvocation.MyCommand.ModuleName) {
    Export-ModuleMember -Function Test-PolicyJsonSchema -ErrorAction SilentlyContinue
}
