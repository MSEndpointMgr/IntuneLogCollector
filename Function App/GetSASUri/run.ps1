using namespace System.Net

# Input bindings are passed in via param block.
param(
    [Parameter(Mandatory = $true)]
    $Request,

    [Parameter(Mandatory = $false)]
    $TriggerMetadata
)

# Functions
function Get-AuthenticationHeader {
    <#
    .SYNOPSIS
        Retrieve an access token for the Managed System Identity.
    
    .DESCRIPTION
        Retrieve an access token for the Managed System Identity.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2021-06-07
    
        Version history:
        1.0.0 - (2021-06-07) Function created
    #>
    Process {
        # Get Managed Service Identity details from the Azure Functions application settings
        $MSIEndpoint = $env:MSI_ENDPOINT
        $MSISecret = $env:MSI_SECRET

        # Define the required URI and token request params
        $APIVersion = "2017-09-01"
        $ResourceURI = "https://graph.microsoft.com"
        $AuthURI = $MSIEndpoint + "?resource=$($ResourceURI)&api-version=$($APIVersion)"

        # Call resource URI to retrieve access token as Managed Service Identity
        $Response = Invoke-RestMethod -Uri $AuthURI -Method "Get" -Headers @{ "Secret" = "$($MSISecret)" }

        # Construct authentication header to be returned from function
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $($Response.access_token)"
            "ExpiresOn" = $Response.expires_on
        }

        # Handle return value
        return $AuthenticationHeader
    }
}

function New-ErrorResponse {
    <#
    .SYNOPSIS
        Construct an error response to be returned to the client.
    
    .DESCRIPTION
        Construct an error response to be returned to the client.
    
    .NOTES
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the HTTP status code to be returned.")]
        [ValidateNotNull()]
        [string]$Code,

        [parameter(Mandatory = $true, HelpMessage = "Specify the error message to be returned.")]
        [ValidateNotNull()]
        [string]$Message
    )
    Process {
        # Construct error response
        $ErrorResponse = [PSCustomObject]@{
            error = [PSCustomObject]@{
                code = $Code
                message = $Message
            }
        }

        # Handle return value
        return $ErrorResponse
    }
}

# Version control
# 2023-11-20 - Version 1.0.0

# Retrieve authentication header for usage in Entra ID Graph API calls
$Global:AuthenticationHeader = Get-AuthenticationHeader

# Read application configuration settings
$AllowedStorageAccounts = $env:AllowedStorageAccounts

# Initate variables
$StatusCode = [HttpStatusCode]::OK
$BodyTable = @{
    SASToken = $null
}
$HeaderValidation = $true

# Assign incoming request properties to variables
$DeviceName = $Request.Body.DeviceName
$DeviceID = $Request.Body.DeviceID
$Signature = $Request.Body.Signature
$Thumbprint = $Request.Body.Thumbprint
$PublicKey = $Request.Body.PublicKey
$StorageAccountName = $env:StorageAccountLogsName
$StorageAccountAccessKey = $env:StorageAccountLogsAccessKey

# Validate request header values
$HeaderValidationList = @(@{ "DeviceName" = $DeviceName }, @{ "DeviceID" = $DeviceID }, @{ "Signature" = $Signature }, @{ "Thumbprint" = $Thumbprint }, @{ "PublicKey" = $PublicKey })
foreach ($HeaderValidationItem in $HeaderValidationList) {
    foreach ($HeaderItem in $HeaderValidationItem.Keys) {
        if ([string]::IsNullOrEmpty($HeaderValidationItem[$HeaderItem])) {
            Write-Warning -Message "Header validation for '$($HeaderItem)' failed, request will not be handled"
            $StatusCode = [HttpStatusCode]::BadRequest
            $HeaderValidation = $false
            $Body = New-ErrorResponse -Code "BadRequest" -Message "Header validation failed"
        }
        else {
            if ($HeaderItem -in @("Signature", "PublicKey")) {
                if ($DebugLogging -eq $true) {
                    Write-Information -MessageData "Header validation succeeded for '$($HeaderItem)' with value: $($HeaderValidationItem[$HeaderItem])"
                }
                else {
                    Write-Information -MessageData "Header validation succeeded for '$($HeaderItem)' with value: <redacted>"
                }
            }
            else {
                Write-Information -MessageData "Header validation succeeded for '$($HeaderItem)' with value: $($HeaderValidationItem[$HeaderItem])"
            }
        }
    }
}

if ($HeaderValidation -eq $true) {
    # Initiate request handling
    Write-Information -MessageData "Initiating request handling for device named as '$($DeviceName)' with identifier: $($DeviceID)"

    # Retrieve Entra ID device record based on DeviceID property from incoming request body
    $EntraIDDeviceRecord = Get-EntraIDDeviceRecord -DeviceID $DeviceID
    if ($EntraIDDeviceRecord -ne $null) {
        Write-Information -MessageData "Found trusted Entra ID device record with object identifier: $($EntraIDDeviceRecord.id)"

        # Validate thumbprint from input request with Entra ID device record's alternativeSecurityIds details
        if (Test-EntraIDDeviceAlternativeSecurityIds -AlternativeSecurityIdKey $EntraIDDeviceRecord.alternativeSecurityIds.key -Type "Thumbprint" -Value $Thumbprint) {
            Write-Information -MessageData "Successfully validated certificate thumbprint from inbound request"

            # Validate public key hash from input request with Entra ID device record's alternativeSecurityIds details
            if (Test-EntraIDDeviceAlternativeSecurityIds -AlternativeSecurityIdKey $EntraIDDeviceRecord.alternativeSecurityIds.key -Type "Hash" -Value $PublicKey) {
                Write-Information -MessageData "Successfully validated certificate SHA256 hash value from inbound request"

                $EncryptionVerification = Test-Encryption -PublicKeyEncoded $PublicKey -Signature $Signature -Content $EntraIDDeviceRecord.deviceId
                if ($EncryptionVerification -eq $true) {
                    Write-Information -MessageData "Successfully validated inbound request came from a trusted Entra ID device record"

                    # Validate that the inbound request came from a trusted device that's not disabled
                    if ($EntraIDDeviceRecord.accountEnabled -eq $true) {
                        Write-Information -MessageData "Entra ID device record was validated as enabled"

                        try {
                            # Construct storage account context
                            Write-Information -MessageData "Constructing storage account context for storage account named: '$($StorageAccountName)'"
                            $StorageAccountContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountAccessKey -ErrorAction "Stop"

                            try {
                                # Create new SAS token with read and write permissions
                                $StartTime = (Get-Date).AddMinutes(-30).ToUniversalTime()
                                $ExpiryTime = (Get-Date).AddHours(1).ToUniversalTime()
                                Write-Information -MessageData "Constructing SAS token with read and write permissions for storage account named: '$($StorageAccountName)'"
                                Write-Information -MessageData "Valid from: $($StartTime.ToString())"
                                Write-Information -MessageData "Valid to: $($ExpiryTime.ToString())"
                                $StorageAccountSASToken = New-AzStorageContainerSASToken -Name "logs" -Context $StorageAccountContext -Policy "UploadLogs" -StartTime $StartTime -ExpiryTime $ExpiryTime -ErrorAction "Stop"

                                # Handle return value
                                $BodyTable["SASToken"] = $StorageAccountSASToken
                            }
                            catch [System.Exception] {
                                Write-Warning -Message "Failed to construct SAS token. Error message: $($_.Exception.Message)"
                                $StatusCode = [HttpStatusCode]::InternalServerError
                                $BodyTable = New-ErrorResponse -Code "InternalServerError" -Message "Failed to construct SAS token"
                            }
                        }
                        catch [System.Exception] {
                            Write-Warning -Message "Failed to retrieve storage account context. Error message: $($_.Exception.Message)"
                            $StatusCode = [HttpStatusCode]::InternalServerError
                            $BodyTable = New-ErrorResponse -Code "InternalServerError" -Message "Failed to retrieve storage account context"
                        }
                    }
                    else {
                        Write-Information -MessageData "Trusted Entra ID device record validation for inbound request failed, record with deviceId '$($DeviceID)' is disabled"
                        $StatusCode = [HttpStatusCode]::Forbidden
                        $BodyTable = New-ErrorResponse -Code "Forbidden" -Message "Trusted Entra ID device record validation for inbound request failed, record with deviceId '$($DeviceID)' is disabled"
                    }
                }
                else {
                    Write-Warning -Message "Trusted Entra ID device record validation for inbound request failed, could not validate signed content from client"
                    $StatusCode = [HttpStatusCode]::Forbidden
                    $BodyTable = New-ErrorResponse -Code "Forbidden" -Message "Trusted Entra ID device record validation for inbound request failed, could not validate signed content from client"
                }
            }
            else {
                Write-Warning -Message "Trusted Entra ID device record validation for inbound request failed, could not validate certificate SHA256 hash value"
                $StatusCode = [HttpStatusCode]::Forbidden
                $BodyTable = New-ErrorResponse -Code "Forbidden" -Message "Trusted Entra ID device record validation for inbound request failed, could not validate certificate SHA256 hash value"
            }
        }
        else {
            Write-Warning -Message "Trusted Entra ID device record validation for inbound request failed, could not validate certificate thumbprint"
            $StatusCode = [HttpStatusCode]::Forbidden
            $BodyTable = New-ErrorResponse -Code "Forbidden" -Message "Trusted Entra ID device record validation for inbound request failed, could not validate certificate thumbprint"
        }
    }
    else {
        Write-Warning -Message "Trusted Entra ID device record validation for inbound request failed, could not find device with deviceId: $($DeviceID)"
        $StatusCode = [HttpStatusCode]::Forbidden
        $BodyTable = New-ErrorResponse -Code "Forbidden" -Message "Trusted Entra ID device record validation for inbound request failed, could not find device with deviceId: $($DeviceID)"
    }
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $BodyTable
})