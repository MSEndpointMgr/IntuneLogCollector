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
# 2022-09-20 - Version 1.0.0

# Retrieve authentication header for usage in Entra ID Graph API calls
$Global:AuthenticationHeader = Get-AuthenticationHeader

# Read application configuration settings
$AllowedStorageAccounts = $env:AllowedStorageAccounts

# Initate variables
$StatusCode = [HttpStatusCode]::OK
$Body = [string]::Empty
$HeaderValidation = $true

# Assign incoming request properties to variables
$DeviceName = $Request.Body.DeviceName
$DeviceID = $Request.Body.DeviceID
$Signature = $Request.Body.Signature
$Thumbprint = $Request.Body.Thumbprint
$PublicKey = $Request.Body.PublicKey
$StorageAccountName = $Request.Body.StorageAccountName
$StorageAccountContainer = $Request.Body.StorageAccountContainer
$BlobName = $Request.Body.BlobName

# Validate request header values
$HeaderValidationList = @(@{ "DeviceName" = $DeviceName }, @{ "DeviceID" = $DeviceID }, @{ "Signature" = $Signature }, @{ "Thumbprint" = $Thumbprint }, @{ "PublicKey" = $PublicKey }, @{ "StorageAccountName" = $StorageAccountName }, @{ "StorageContainerName" = $StorageAccountContainer}, @{ "BlobName" = $BlobName })
foreach ($HeaderValidationItem in $HeaderValidationList) {
    foreach ($HeaderItem in $HeaderValidationItem.Keys) {
        if ([string]::IsNullOrEmpty($HeaderValidationItem[$HeaderItem])) {
            Write-Warning -Message "Header validation for '$($HeaderItem)' failed, request will not be handled"
            $StatusCode = [HttpStatusCode]::BadRequest
            $HeaderValidation = $false
            $Body = New-ErrorResponse -Code "BadRequest" -Message "Header validation failed"
        }
        else {
            if ($HeaderItem -like "StorageAccountName") {
                if ($StorageAccountName -in ($AllowedStorageAccounts -split ";")) {
                    Write-Information -MessageData "Header validation succeeded for '$($HeaderItem)' with value: $($HeaderValidationItem[$HeaderItem])"
                }
                else {
                    Write-Warning -Message "Header validation for '$($HeaderItem)' failed, request will not be handled"
                    $StatusCode = [HttpStatusCode]::BadRequest
                    $HeaderValidation = $false
                    $Body = New-ErrorResponse -Code "BadRequest" -Message "Header validation failed"
                }
            }
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
                            $StorageAccountContext = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount -ErrorAction "Stop"

                            try {
                                # Define temporary file name and local temp destination
                                $BlobDestinationPath = $env:TMP
                                $BlobFilePath = Join-Path -Path $BlobDestinationPath -ChildPath $BlobName
    
                                try {
                                    # Get blob item from storage account
                                    $BlobItem = Get-AzStorageBlob -Container $StorageAccountContainer -Blob $BlobName -Context $StorageAccountContext -ErrorAction "Stop" -Verbose:$false

                                    # Ensure latest available version of blob is downloaded
                                    if (Test-Path -Path $BlobFilePath) {
                                        if ((Get-FileHash -Path $BlobFilePath -Algorithm MD5).Hash -eq ([BitConverter]::ToString($BlobItem.BlobProperties.ContentHash).Replace('-',''))) {
                                            Write-Information -MessageData "Blob file was present locally and was valid, skipping download"
                                        }
                                        else {
                                            Write-Information -MessageData "Blob file was present locally but was invalid, attempting to download '$($BlobName)' from storage account"
                                            $BlobItemContent = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $BlobName -Context $StorageAccountContext -Destination $BlobDestinationPath -Force -ErrorAction "Stop" -Verbose:$false
                                        }
                                    }
                                    else {
                                        Write-Information -MessageData "Blob file was not present locally, attempting to download '$($BlobName)' from storage account"
                                        $BlobItemContent = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $BlobName -Context $StorageAccountContext -Destination $BlobDestinationPath -Force -ErrorAction "Stop" -Verbose:$false
                                    }

                                    # Read contents of blob and download a local copy
                                    if (Test-Path -Path $BlobFilePath) {
                                        Write-Information -MessageData "Successfully detected '$($BlobName)' in folder path: $($BlobDestinationPath)"

                                        # Read contents of downloaded blob
                                        Write-Information -MessageData "Reading blob content from file: $($BlobFilePath)"
                                        $BlobContent = Get-Content -Path $BlobFilePath -Raw
                                        if ($BlobContent -ne $null) {
                                            Write-Information -MessageData "Successfully read blob content from file: $($BlobFilePath)"

                                            try {
                                                # Create custom powershell object with content from blob and return it as the response body
                                                $BlobContentJSON = $BlobContent | ConvertFrom-Json -ErrorAction "Stop"
                                                Write-Information -MessageData "Blob content is of type JSON, returning blob content as response body"
                                                $Body = [PSCustomObject]@{
                                                    BlobContent = $BlobContentJSON
                                                }
                                            }
                                            catch [System.Exception] {
                                                Write-Warning -Message "Could not convert blob content from JSON to a custom powershell object"
                                            }
                                        }
                                        else {
                                            Write-Warning -Message "Could not read blob content from file: $($BlobFilePath)"
                                            $StatusCode = [HttpStatusCode]::InternalServerError
                                            $Body = New-ErrorResponse -Code "InternalServerError" -Message "Could not read blob content from file: $($BlobFilePath)"
                                        }
                                    }
                                    else {
                                        Write-Warning -Message "Could not find blob file in temporary location after download operation"
                                        $StatusCode = [HttpStatusCode]::InternalServerError
                                        $Body = New-ErrorResponse -Code "InternalServerError" -Message "Could not find blob file in temporary location after download operation"
                                    }
                                }
                                catch [System.Exception] {
                                    Write-Warning -Message "Failed to retrieve storage account blob item. Error message: $($_.Exception.Message)"
                                    $StatusCode = [HttpStatusCode]::InternalServerError
                                    $Body = New-ErrorResponse -Code "InternalServerError" -Message "Failed to retrieve storage account blob item"
                                }
                            }
                            catch [System.Exception] {
                                Write-Warning -Message "Failed to define temporary file name and local temp destination"
                                $StatusCode = [HttpStatusCode]::InternalServerError
                                $Body = New-ErrorResponse -Code "InternalServerError" -Message "Failed to define temporary file name and local temp destination"
                            }
                        }
                        catch [System.Exception] {
                            Write-Warning -Message "Failed to retrieve storage account context. Error message: $($_.Exception.Message)"
                            $StatusCode = [HttpStatusCode]::InternalServerError
                            $Body = New-ErrorResponse -Code "InternalServerError" -Message "Failed to retrieve storage account context"
                        }
                    }
                    else {
                        Write-Information -MessageData "Trusted Entra ID device record validation for inbound request failed, record with deviceId '$($DeviceID)' is disabled"
                        $StatusCode = [HttpStatusCode]::Forbidden
                        $Body = New-ErrorResponse -Code "Forbidden" -Message "Trusted Entra ID device record validation for inbound request failed, record with deviceId '$($DeviceID)' is disabled"
                    }
                }
                else {
                    Write-Warning -Message "Trusted Entra ID device record validation for inbound request failed, could not validate signed content from client"
                    $StatusCode = [HttpStatusCode]::Forbidden
                    $Body = New-ErrorResponse -Code "Forbidden" -Message "Trusted Entra ID device record validation for inbound request failed, could not validate signed content from client"
                }
            }
            else {
                Write-Warning -Message "Trusted Entra ID device record validation for inbound request failed, could not validate certificate SHA256 hash value"
                $StatusCode = [HttpStatusCode]::Forbidden
                $Body = New-ErrorResponse -Code "Forbidden" -Message "Trusted Entra ID device record validation for inbound request failed, could not validate certificate SHA256 hash value"
            }
        }
        else {
            Write-Warning -Message "Trusted Entra ID device record validation for inbound request failed, could not validate certificate thumbprint"
            $StatusCode = [HttpStatusCode]::Forbidden
            $Body = New-ErrorResponse -Code "Forbidden" -Message "Trusted Entra ID device record validation for inbound request failed, could not validate certificate thumbprint"
        }
    }
    else {
        Write-Warning -Message "Trusted Entra ID device record validation for inbound request failed, could not find device with deviceId: $($DeviceID)"
        $StatusCode = [HttpStatusCode]::Forbidden
        $Body = New-ErrorResponse -Code "Forbidden" -Message "Trusted Entra ID device record validation for inbound request failed, could not find device with deviceId: $($DeviceID)"
    }
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $Body
})