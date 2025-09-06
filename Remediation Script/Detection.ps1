<#
.SYNOPSIS
    Proaction Remediation script for remotely collect logs from endpoints.

.DESCRIPTION
    This is the detection script for a Proactive Remediation in Endpoint Analytics used to remotely collect logs.

.EXAMPLE
    .\Detection.ps1

.NOTES
    FileName:    Detection.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2022-05-23
    Updated:     2022-05-23

    Version history:
    1.0.0 - (2022-05-23) Script created
#>
Begin {
    # Define the proactive remediation name
    $ProactiveRemediationName = "CollectLogs"

    # Define if any modules must be present on the device for this proactive remediation to execute properly
    # Set to $null if no modules are to be installed
    $Modules = @()

    # Enable TLS 1.2 support for downloading modules from PSGallery
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Install required modules for script execution
    if ($Modules -ne $null) {
        foreach ($Module in $Modules) {
            try {
                $CurrentModule = Get-InstalledModule -Name $Module -ErrorAction "Stop" -Verbose:$false
                if ($CurrentModule -ne $null) {
                    $LatestModuleVersion = (Find-Module -Name $Module -ErrorAction "Stop" -Verbose:$false).Version
                    if ($LatestModuleVersion -gt $CurrentModule.Version) {
                        $UpdateModuleInvocation = Update-Module -Name $Module -Force -AcceptLicense -ErrorAction "Stop" -Confirm:$false -Verbose:$false
                    }
                }
            }
            catch [System.Exception] {
                try {
                    # Install NuGet package provider
                    $PackageProvider = Install-PackageProvider -Name "NuGet" -Force -Verbose:$false
            
                    # Install current missing module
                    Install-Module -Name $Module -Force -AcceptLicense -ErrorAction "Stop" -Confirm:$false -Verbose:$false
                }
                catch [System.Exception] {
                    Write-Warning -Message "An error occurred while attempting to install $($Module) module. Error message: $($_.Exception.Message)"
                }
            }
        }
    }
}
Process {
    # Functions
    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Value,
    
            [parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]$Severity,
    
            [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = "$($ProactiveRemediationName).log"
        )
        # Determine log file location
        $LogFilePath = Join-Path -Path (Join-Path -Path $env:ProgramData -ChildPath "Microsoft\IntuneManagementExtension\Logs") -ChildPath $FileName
        
        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($ProactiveRemediationName)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry $($ProactiveRemediationName).log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function Get-EntraIDDeviceID {
        <#
        .SYNOPSIS
            Get the Entra ID device ID from the local device.
        
        .DESCRIPTION
            Get the Entra ID device ID from the local device.
        
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-05-26
            Updated:     2021-05-26
        
            Version history:
            1.0.0 - (2021-05-26) Function created
            1.0.1 - (2022-15.09) Updated to support CloudPC (Different method to find EntraID DeviceID)
        #>
        Process {
            # Define Cloud Domain Join information registry path
            $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
            
            # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
            $EntraIDJoinInfoKey = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
            if ($EntraIDJoinInfoKey -ne $null) {
                # Retrieve the machine certificate based on thumbprint from registry key
                
                if ($EntraIDJoinInfoKey -ne $null) {
                    # Match key data against GUID regex
                    if ([guid]::TryParse($EntraIDJoinInfoKey, $([ref][guid]::Empty))) {
                        $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($EntraIDJoinInfoKey)" }
                    }
                    else {
                        $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $EntraIDJoinInfoKey }    
                    }
                }
                if ($EntraIDJoinCertificate -ne $null) {
                    # Determine the device identifier from the subject name
                    $EntraIDDeviceID = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
                    # Handle return value
                    return $EntraIDDeviceID
                }
            }
        }
    }

    function Get-EntraIDRegistrationCertificateThumbprint {
        <#
        .SYNOPSIS
            Get the thumbprint of the certificate used for Entra ID device registration.
        
        .DESCRIPTION
            Get the thumbprint of the certificate used for Entra ID device registration.
        
        .NOTES
            Author:      Nickolaj Andersen
            Contributor: @JankeSkanke
            Contact:     @NickolajA
            Created:     2021-06-03
            Updated:     2022-26-10
        
            Version history:
            1.0.0 - (2021-06-03) Function created
            1.1.0 - (2022-26-10) Added support for finding thumbprint for Cloud PCs @JankeSkanke
        #>
        Process {
            # Define Cloud Domain Join information registry path
            $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"

            # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
            $EntraIDJoinInfoKey = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"

             # Retrieve the machine certificate based on thumbprint from registry key or Certificate (CloudPC)        
            if ($EntraIDJoinInfoKey -ne $null) {
                # Match key data against GUID regex for CloudPC Support 
                if ([guid]::TryParse($EntraIDJoinInfoKey, $([ref][guid]::Empty))) {
                    #This is for CloudPC
                    $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($EntraIDJoinInfoKey)" }
                    $EntraIDJoinInfoThumbprint = $EntraIDJoinCertificate.Thumbprint
                }
                else {
                    # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid (non-CloudPC)
                    $EntraIDJoinInfoThumbprint = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
                }
            }
            # Handle return value
            return $EntraIDJoinInfoThumbprint
        }
    }

    function New-RSACertificateSignature {
        <#
        .SYNOPSIS
            Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
        
        .DESCRIPTION
            Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
            The certificate used must be available in the LocalMachine\My certificate store, and must also contain a private key.
    
        .PARAMETER Content
            Specify the content string to be signed.
    
        .PARAMETER Thumbprint
            Specify the thumbprint of the certificate.
        
        .NOTES
            Author:      Nickolaj Andersen / Thomas Kurth
            Contact:     @NickolajA
            Created:     2021-06-03
            Updated:     2021-06-03
        
            Version history:
            1.0.0 - (2021-06-03) Function created
    
            Credits to Thomas Kurth for sharing his original C# code.
        #>
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the content string to be signed.")]
            [ValidateNotNullOrEmpty()]
            [string]$Content,
    
            [parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
            [ValidateNotNullOrEmpty()]
            [string]$Thumbprint
        )
        Process {
            # Determine the certificate based on thumbprint input
            $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $CertificateThumbprint }
            if ($Certificate -ne $null) {
                if ($Certificate.HasPrivateKey -eq $true) {
                    # Read the RSA private key
                    $RSAPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
                    
                    if ($RSAPrivateKey -ne $null) {
                        if ($RSAPrivateKey -is [System.Security.Cryptography.RSACng]) {
                            # Construct a new SHA256Managed object to be used when computing the hash
                            $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"
    
                            # Construct new UTF8 unicode encoding object
                            $UnicodeEncoding = [System.Text.UnicodeEncoding]::UTF8
    
                            # Convert content to byte array
                            [byte[]]$EncodedContentData = $UnicodeEncoding.GetBytes($Content)
    
                            # Compute the hash
                            [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($EncodedContentData)
    
                            # Create signed signature with computed hash
                            [byte[]]$SignatureSigned = $RSAPrivateKey.SignHash($ComputedHash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    
                            # Convert signature to Base64 string
                            $SignatureString = [System.Convert]::ToBase64String($SignatureSigned)
                            
                            # Handle return value
                            return $SignatureString
                        }
                    }
                }
            }
        }
    }
    
    function Get-PublicKeyBytesEncodedString {
        <#
        .SYNOPSIS
            Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
        
        .DESCRIPTION
            Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
            The certificate used must be available in the LocalMachine\My certificate store.
    
        .PARAMETER Thumbprint
            Specify the thumbprint of the certificate.
        
        .NOTES
            Author:      Nickolaj Andersen / Thomas Kurth
            Contact:     @NickolajA
            Created:     2021-06-07
            Updated:     2021-06-07
        
            Version history:
            1.0.0 - (2021-06-07) Function created
    
            Credits to Thomas Kurth for sharing his original C# code.
        #>
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
            [ValidateNotNullOrEmpty()]
            [string]$Thumbprint
        )
        Process {
            # Determine the certificate based on thumbprint input
            $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $Thumbprint }
            if ($Certificate -ne $null) {
                # Get the public key bytes
                [byte[]]$PublicKeyBytes = $Certificate.GetPublicKey()
    
                # Handle return value
                return [System.Convert]::ToBase64String($PublicKeyBytes)
            }
        }
    }

    function New-DeviceTrustBody {
        <#
        .SYNOPSIS
            Construct the body with the elements for a sucessful device trust validation required by a Function App that's leveraging the AADDeviceTrust.FunctionApp module.
    
        .DESCRIPTION
            Construct the body with the elements for a sucessful device trust validation required by a Function App that's leveraging the AADDeviceTrust.FunctionApp module.
    
        .EXAMPLE
            .\New-DeviceTrustBody.ps1
    
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2022-03-14
            Updated:     2022-03-14
    
            Version history:
            1.0.0 - (2022-03-14) Script created
        #>
        [CmdletBinding(SupportsShouldProcess = $true)]
        param()
        Process {
            # Retrieve required data for building the request body
            $EntraIDDeviceID = Get-EntraIDDeviceID
            $CertificateThumbprint = Get-EntraIDRegistrationCertificateThumbprint
            $Signature = New-RSACertificateSignature -Content $EntraIDDeviceID -Thumbprint $CertificateThumbprint
            $PublicKeyBytesEncoded = Get-PublicKeyBytesEncodedString -Thumbprint $CertificateThumbprint
    
            # Construct client-side request header
            $BodyTable = [ordered]@{
                DeviceName = $env:COMPUTERNAME
                DeviceID = $EntraIDDeviceID
                Signature = $Signature
                Thumbprint = $CertificateThumbprint
                PublicKey = $PublicKeyBytesEncoded
            }
    
            # Handle return value
            return $BodyTable
        }
    }

    function Get-EntraIDJoinDate {
        <#
        .SYNOPSIS
            Get the Entra ID Join Date from the local device.
        
        .DESCRIPTION
            Get the Entra ID Join Date from the local device.
        
        .NOTES
            Author:      Jan Ketil Skanke (and Nickolaj Andersen)
            Contact:     @JankeSkanke
            Created:     2021-05-26
            Updated:     2021-05-26
        
            Version history:
            1.0.0 - (2021-05-26) Function created
            1.0.1 - (2022-15.09) Updated to support CloudPC (Different method to find EntraID DeviceID)
        #>
        Process {
            # Define Cloud Domain Join information registry path
            $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
            
            # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
            $EntraIDJoinInfoKey = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
            if ($EntraIDJoinInfoKey -ne $null) {
                # Retrieve the machine certificate based on thumbprint from registry key
                
                if ($EntraIDJoinInfoKey -ne $null) {
                    # Match key data against GUID regex
                    if ([guid]::TryParse($EntraIDJoinInfoKey, $([ref][guid]::Empty))) {
                        $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($EntraIDJoinInfoKey)" }
                    }
                    else {
                        $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $EntraIDJoinInfoKey }    
                    }
                }
            if ($EntraIDJoinCertificate -ne $null) {
                    # Determine the device identifier from the subject name
                    $EntraIDJoinDate = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
                    # Handle return value
                    return $EntraIDJoinDate
                }
            }
        }
    }

    function Test-EntraIDDeviceRegistration {
        <#
        .SYNOPSIS
            Determine if the device conforms to the requirement of being either Entra ID joined or Hybrid Entra ID joined.
        
        .DESCRIPTION
            Determine if the device conforms to the requirement of being either Entra ID joined or Hybrid Entra ID joined.
        
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2022-01-27
            Updated:     2022-01-27
        
            Version history:
            1.0.0 - (2022-01-27) Function created
        #>
        Process {
            $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
            if (Test-Path -Path $EntraIDJoinInfoRegistryKeyPath) {
                return $true
            }
            else {
                return $false
            }
        }
    }

    function Start-DownloadFile {
        <#
        .SYNOPSIS
            Download a file from a given URL and save it in a specific location.
    
        .DESCRIPTION
            Download a file from a given URL and save it in a specific location.
    
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2020-01-04
            Updated:     2020-01-04
    
            Version history:
            1.0.0 - (2020-01-04) Function created
        #>     
        param(
            [parameter(Mandatory = $true, HelpMessage = "URL for the file to be downloaded.")]
            [ValidateNotNullOrEmpty()]
            [string]$URL,
    
            [parameter(Mandatory = $true, HelpMessage = "Folder where the file will be downloaded.")]
            [ValidateNotNullOrEmpty()]
            [string]$Path,
    
            [parameter(Mandatory = $true, HelpMessage = "Name of the file including file extension.")]
            [ValidateNotNullOrEmpty()]
            [string]$Name
        )
        Begin {
            # Set global variable
            $ErrorActionPreference = "Stop"
    
            # Construct WebClient object
            $WebClient = New-Object -TypeName System.Net.WebClient
        }
        Process {
            # Create path if it doesn't exist
            if (-not(Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force | Out-Null
            }
    
            # Register events for tracking download progress
            $Global:DownloadComplete = $false
            $EventDataComplete = Register-ObjectEvent $WebClient DownloadFileCompleted -SourceIdentifier WebClient.DownloadFileComplete -Action {$Global:DownloadComplete = $true}
            $EventDataProgress = Register-ObjectEvent $WebClient DownloadProgressChanged -SourceIdentifier WebClient.DownloadProgressChanged -Action { $Global:DPCEventArgs = $EventArgs }                
    
            # Start download of file
            $WebClient.DownloadFileAsync($URL, (Join-Path -Path $Path -ChildPath $Name))
    
            # Track the download progress
            do {
                $PercentComplete = $Global:DPCEventArgs.ProgressPercentage
                $DownloadedBytes = $Global:DPCEventArgs.BytesReceived
                if ($DownloadedBytes -ne $null) {
                    Write-Progress -Activity "Downloading file: $($Name)" -Id 1 -Status "Downloaded bytes: $($DownloadedBytes)" -PercentComplete $PercentComplete
                }
            }
            until ($Global:DownloadComplete)
        }
        End {
            # Dispose of the WebClient object
            $WebClient.Dispose()
    
            # Unregister events used for tracking download progress
            Unregister-Event -SourceIdentifier WebClient.DownloadProgressChanged
            Unregister-Event -SourceIdentifier WebClient.DownloadFileComplete
        }
    }

    function Invoke-AzureCopyUtility {
        <#
        .SYNOPSIS
            Upload and commit .intunewin file into Azure Storage blob container.
    
        .DESCRIPTION
            Upload and commit .intunewin file into Azure Storage blob container.
    
        .PARAMETER StorageUri
            Specify the Storage Account Uri.
    
        .PARAMETER FilePath
            Specify the path to the file for upload.
    
        .PARAMETER Resource
            Specify the Storage Account files Uri for renewal if process takes a long time.
    
    
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2022-10-02
            Updated:     2023-01-20
    
            Version history:
            1.0.0 - (2022-10-02) Function created
            1.0.1 - (2023-01-20) Added parameter switch to support scenario explained in issue #64
        #>    
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the path to the file for upload.")]
            [ValidateNotNullOrEmpty()]
            [string]$FilePath,

            [parameter(Mandatory = $true, HelpMessage = "Specify the Storage Account Uri.")]
            [ValidateNotNullOrEmpty()]
            [string]$StorageUri
        )
        Process {
            # Download URL for AzCopy.exe
            $DownloadURL = "https://aka.ms/downloadazcopy-v10-windows"
    
            # Construct expected path to AzCopy utility
            $AzCopyPath = Resolve-Path -Path (Join-Path -Path $env:TEMP -ChildPath "AzCopy\azcopy_windows_amd64*") -ErrorAction "SilentlyContinue" | Select-Object -ExpandProperty "Path"
    
            if ($AzCopyPath -eq $null) {
                try {
                    # Download AzCopy.exe if not present in context temporary folder
                    Write-Verbose -Message "Unable to detect AzCopy.exe in specified location, attempting to download to: $($env:TEMP)"
                    Start-DownloadFile -URL $DownloadURL -Path $env:TEMP -Name "AzCopy.zip" -ErrorAction "Stop"
    
                    try {
                        # Expand downloaded zip archive
                        $AzCopyExtractedPath = (Join-Path -Path $env:TEMP -ChildPath "AzCopy")
                        Expand-Archive -Path (Join-Path -Path $env:TEMP -ChildPath "AzCopy.zip") -DestinationPath $AzCopyExtractedPath -ErrorAction "Stop"
                    }
                    catch [System.Exception] {
                        throw "$($MyInvocation.MyCommand): Failed to extract AzCopy.exe with error message: $($_.Exception.Message)"
                    }
                }
                catch [System.Exception] {
                    throw "$($MyInvocation.MyCommand): Failed to download AzCopy.exe from '$($DownloadURL)' with error message: $($_.Exception.Message)"
                }
            }
    
            # Attempt to resolve path to AzCopy.exe in extracted content
            $AzCopyPath = Join-Path -Path (Resolve-Path -Path (Join-Path -Path $env:TEMP -ChildPath "AzCopy\azcopy_windows_amd64*") | Select-Object -ExpandProperty "Path") -ChildPath "AzCopy.exe"
            if ($AzCopyPath -ne $null) {
                try {
                    # Initiate transfer of content depending on window style parameter
                    $TransferOperation = Start-Process -FilePath $AzCopyPath -ArgumentList "cp `"$($FilePath)`" `"$($StorageUri)`" --output-type `"json`"" -PassThru -WindowStyle "Hidden" -Wait -ErrorAction "Stop"
                }
                catch [System.Exception] {
                    throw "$($MyInvocation.MyCommand): AzCopy.exe file transfer failed. Error message: $($_.Exception.Message)"
                }
                finally {
                    Write-LogEntry -Value "AzCopy.exe file transfer completed" -Severity 1
                }
            }
            else {
                throw "$($MyInvocation.MyCommand): AzCopy.exe could not be found, this transfer method cannot be used"
            }
        }
    }

    # Enter the GetSASUri function URI
    $FunctionGetSASUri = "<enter_uri_for_function_GetSASUri>"

    # Enter the GetBlobContent function URI
    $FunctionGetBlobContent = "<enter_uri_for_function_GetBlobContent>"

    # Enter Storage Account details for the account where logs files will be uploaded
    $StorageAccountLogsName = "<enter_storage_account_name>" # e.g. "samplestorageaccountname"
    $StorageAccountLogsContainerName = "<enter_storage_account_container_name>" # e.g. "logs"
    
    # Enter Storage Account details for the account where the logs gather rules file is located
    $StorageAccountRulesName = "<enter_storage_account_name>" # e.g. "samplestorageaccountname"
    $StorageAccountRulesContainerName = "<enter_storage_account_container_name>" # e.g. "rules"
    $StorageAccountRulesFileName = "LogsGatherRules.json" # Change this value if the file name is different than what's provided in the solution

    # Initial logging details for detection script
    Write-LogEntry -Value "[$($ProactiveRemediationName)-Detection] - Initializing" -Severity 1

    # Validate that the script is running on an Entra ID joined or hybrid Entra ID joined device
    Write-LogEntry -Value "Testing Entra ID device registration" -Severity 1
    if (Test-EntraIDDeviceRegistration -eq $true) {
        # Create body for Function App request
        $BodyTable = New-DeviceTrustBody

        try {
            # Construct URI for Function App request to retrieve SAS token
            Write-LogEntry -Value "Retrieving SAS token from Function App" -Severity 1
            $Response = Invoke-RestMethod -Method "POST" -Uri $FunctionGetSASUri -Body ($BodyTable | ConvertTo-Json) -ContentType "application/json" -ErrorAction "Stop"

            # Check if leading character of response string is equal to '?'
            if ($Response -ne $null) {
                if ($Response.SASToken.SubString(0,1) -eq "?") {
                    # Question mark should not be added to full Uri
                    Write-LogEntry -Value "SAS token retrieved from Function App, constructing full storage Uri" -Severity 1
                    $StorageUri = -join@("https://", $StorageAccountLogsName, ".blob.core.windows.net/", $StorageAccountLogsContainerName, $Response.SASToken)
                }
                else {
                    # Add question mark to full Uri
                    Write-LogEntry -Value "SAS token retrieved from Function App, constructing full storage Uri" -Severity 1
                    $StorageUri = -join@("https://", $StorageAccountLogsName, ".blob.core.windows.net/", $StorageAccountLogsContainerName, "?", $Response.SASToken)
                }

                # Add items to body for Function App request
                $BodyTable.Add("StorageAccountName", $StorageAccountRulesName)
                $BodyTable.Add("StorageAccountContainer", $StorageAccountRulesContainerName)
                $BodyTable.Add("BlobName", $StorageAccountRulesFileName)

                try {
                    # Construct URI for Function App request to retrieve log collection rules
                    Write-LogEntry -Value "Retrieving log collection rules from Function App" -Severity 1
                    $Response = Invoke-RestMethod -Method "POST" -Uri $FunctionGetBlobContent -Body ($BodyTable | ConvertTo-Json) -ContentType "application/json" -ErrorAction "Stop"

                    if ($Response.BlobContent -ne $null) {
                        Write-LogEntry -Value "Successfully retrieved log collection rules from Function App" -Severity 1

                        try {
                            # Create temporary folder for log collection
                            $TempFolderPath = Join-Path -Path $env:TEMP -ChildPath $env:COMPUTERNAME
                            Write-LogEntry -Value "Using temporary folder '$($TempFolderPath)' for log collection" -Severity 1
                            Write-LogEntry -Value "Testing for presence of temporary folder for log collection" -Severity 1
                            if (-not(Test-Path -Path $TempFolderPath)) {
                                Write-LogEntry -Value "Temporary folder for log collection does not exist, creating folder" -Severity 1
                                New-Item -Path $env:TEMP -Name $env:COMPUTERNAME -ItemType "Directory" -ErrorAction "Stop" | Out-Null
                            }

                            try {
                                # Check if temporary folder contains any files
                                if ((Get-ChildItem -Path $TempFolderPath).Count -gt 0) {
                                    # Remove all files from temporary folder
                                    Write-LogEntry -Value "Temporary folder for log collection contains files, cleaning up the folder" -Severity 1
                                    Get-ChildItem -Path $TempFolderPath -Recurse | Remove-Item -Recurse -Force -ErrorAction "Stop"
                                }
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "Unable to cleanup temporary folder for log collection. Error message: $($_.Exception.Message)" -Severity 3
                            }

                            # Process each log collection rule
                            foreach ($RuleItem in $Response.BlobContent.Rules) {
                                switch ($RuleItem.Type) {
                                    "Folder" {
                                        Write-LogEntry -Value "Processing log collection rule for folder '$($RuleItem.Path)'" -Severity 1

                                        # Construct log file name arguments for Get-ChildItem cmdlet
                                        $LogFileNameArgs = @{
                                            Path = $RuleItem.Path
                                            File = $true
                                            Filter = -join@("*.", $RuleItem.FileExtension)
                                        }

                                        # Append the attribute Recurse from rule to the Get-ChildItem cmdlet if set to true
                                        if ($RuleItem.Recurse -eq $true) {
                                            $LogFileNameArgs.Add("Recurse", $true)
                                        }

                                        # Copy each log file from the source folder defined in the attribute Path from rule, to the temporary folder
                                        $LogFileItems = Get-ChildItem @LogFileNameArgs
                                        if ($LogFileItems.Count -ge 1) {
                                            # Create a new folder in the temporary folder, named after the attribute LogFolderName from rule
                                            $CurrentLogFolderPath = Join-Path -Path $TempFolderPath -ChildPath $RuleItem.LogFolderName
                                            if (-not(Test-Path -Path $CurrentLogFolderPath)) {
                                                New-Item -Path $TempFolderPath -Name $RuleItem.LogFolderName -ItemType "Directory" -ErrorAction "Stop" | Out-Null
                                            }

                                            Write-LogEntry -Value "Copying '$($LogFileItems.Count)' log files from source folder '$($RuleItem.Path)' to temporary folder" -Severity 1
                                            foreach ($LogFileItem in $LogFileItems) {
                                                try {
                                                    $CopyOperation = Copy-Item -Path $LogFileItem.FullName -Destination $CurrentLogFolderPath -ErrorAction "Stop"
                                                }
                                                catch [System.Exception] {
                                                    Write-LogEntry -Value "Unable to copy log file '$($LogFileItem.FullName)' to temporary folder. Error message: $($_.Exception.Message)" -Severity 3
                                                }
                                            }
                                        }
                                        else {
                                            Write-LogEntry -Value "No log files found in source folder '$($RuleItem.Path)' with file extension '.$($RuleItem.FileExtension)'" -Severity 2
                                        }
                                    }
                                    "MultipleFiles" {
                                        Write-LogEntry -Value "Processing log collection rule for multiple files" -Severity 1

                                        # Copy each log file from the source folder defined in the attribute Path from rule, to the temporary folder
                                        foreach ($LogFileName in $RuleItem.FileNames.Split(";")) {
                                            $LogFileItem = Get-Item -Path (Join-Path -Path $RuleItem.Path -ChildPath $LogFileName) -ErrorAction "SilentlyContinue"
                                            if ($LogFileItem -ne $null) {
                                                # Create a new folder in the temporary folder, named after the attribute LogFolderName from rule
                                                $CurrentLogFolderPath = Join-Path -Path $TempFolderPath -ChildPath $RuleItem.LogFolderName
                                                if (-not(Test-Path -Path $CurrentLogFolderPath)) {
                                                    New-Item -Path $TempFolderPath -Name $RuleItem.LogFolderName -ItemType "Directory" -ErrorAction "Stop" | Out-Null
                                                }

                                                try {
                                                    # Copy log file from the source folder defined in the attribute Path from rule, to the temporary folder
                                                    Write-LogEntry -Value "Copying log file from source folder '$($LogFileName)' to temporary folder" -Severity 1
                                                    $CopyOperation = Copy-Item -Path $LogFileItem.FullName -Destination $CurrentLogFolderPath -ErrorAction "Stop"
                                                }
                                                catch [System.Exception] {
                                                    Write-LogEntry -Value "Unable to copy log file '$($LogFileItem.FullName)' to temporary folder. Error message: $($_.Exception.Message)" -Severity 3
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "Log file not found in source folder '$($LogFileName)'" -Severity 2
                                            }
                                        }
                                    }
                                    "File" {
                                        Write-LogEntry -Value "Processing log collection rule for file '$($RuleItem.Path)'" -Severity 1

                                        # Retrieve the log file from the source folder defined in the attribute Path from rule
                                        $LogFileItem = Get-Item -Path $RuleItem.Path -ErrorAction "SilentlyContinue"
                                        if ($LogFileItem -ne $null) {
                                            # Create a new folder in the temporary folder, named after the attribute LogFolderName from rule
                                            $CurrentLogFolderPath = Join-Path -Path $TempFolderPath -ChildPath $RuleItem.LogFolderName
                                            if (-not(Test-Path -Path $CurrentLogFolderPath)) {
                                                New-Item -Path $TempFolderPath -Name $RuleItem.LogFolderName -ItemType "Directory" -ErrorAction "Stop" | Out-Null
                                            }

                                            
                                            try {
                                                # Copy log file from the source folder defined in the attribute Path from rule, to the temporary folder
                                                Write-LogEntry -Value "Copying log file from source folder '$($RuleItem.Path)' to temporary folder" -Severity 1
                                                $CopyOperation = Copy-Item -Path $LogFileItem.FullName -Destination $CurrentLogFolderPath -ErrorAction "Stop"
                                            }
                                            catch [System.Exception] {
                                                Write-LogEntry -Value "Unable to copy log file '$($LogFileItem.FullName)' to temporary folder. Error message: $($_.Exception.Message)" -Severity 3
                                            }
                                        }
                                        else {
                                            Write-LogEntry -Value "Log file not found in source folder '$($RuleItem.Path)'" -Severity 2
                                        }
                                    }
                                    "EventLog" {
                                        Write-LogEntry -Value "Processing log collection rule for event log '$($RuleItem.EventLogName)'" -Severity 1

                                        # Create a new folder in the temporary folder, named after the attribute LogFolderName from rule
                                        $CurrentLogFolderPath = Join-Path -Path $TempFolderPath -ChildPath $RuleItem.LogFolderName
                                        if (-not(Test-Path -Path $CurrentLogFolderPath)) {
                                            New-Item -Path $TempFolderPath -Name $RuleItem.LogFolderName -ItemType "Directory" -ErrorAction "Stop" | Out-Null
                                        }

                                        # Determine event log file to use based on the attribute LogName and LogFolderName from rule
                                        if (-not([string]::IsNullOrEmpty($RuleItem.EventLogPath))) {
                                            $CurrentEventLog = -join@($RuleItem.EventLogPath, "/", $RuleItem.EventLogName)
                                            $CurrentEventLogExportName = -join@($($CurrentLogFolderPath), "\", $($RuleItem.EventLogPath), "-", $($RuleItem.EventLogName), ".evtx")
                                        }
                                        else {
                                            $CurrentEventLog = $RuleItem.EventLogName
                                            $CurrentEventLogExportName = -join@($($CurrentLogFolderPath), "\", $($RuleItem.EventLogName), ".evtx")
                                        }

                                        # Export event log to temporary folder
                                        try {
                                            Write-LogEntry -Value "Exporting event log '$($CurrentEventLog)' to temporary folder" -Severity 1
                                            $ArgumentList = "export-log $($CurrentEventLog) $($CurrentEventLogExportName)"
                                            Start-Process -FilePath "wevtutil.exe" -ArgumentList $ArgumentList -Wait -WindowStyle "Hidden" -ErrorAction "Stop"
                                        }
                                        catch [System.Exception] {
                                            Write-LogEntry -Value "Unable to export event log '$($CurrentEventLog)' to temporary folder. Error message: $($_.Exception.Message)" -Severity 3
                                        }
                                    }
                                    "Registry" {
                                        Write-LogEntry -Value "Processing log collection rule for registry key '$($RuleItem.Path)'" -Severity 1

                                        # Create a new folder in the temporary folder, named after the attribute LogFolderName from rule
                                        $CurrentLogFolderPath = Join-Path -Path $TempFolderPath -ChildPath $RuleItem.LogFolderName
                                        if (-not(Test-Path -Path $CurrentLogFolderPath)) {
                                            New-Item -Path $TempFolderPath -Name $RuleItem.LogFolderName -ItemType "Directory" -ErrorAction "Stop" | Out-Null
                                        }

                                        # Determine if registry path from rule is valid
                                        $CurrentRegistryKeyPath = $RuleItem.Path
                                        if (Test-Path -Path $CurrentRegistryKeyPath) {
                                            # Retrieve all registry keys from current path
                                            $RegistryKeys = Get-ChildItem -Path $CurrentRegistryKeyPath -Recurse -ErrorAction "SilentlyContinue"

                                            # Process each registry key and value to construct a custom object with registry data
                                            if ($RegistryKeys -ne $null) {
                                                $RegistryKeyData = foreach ($Key in $RegistryKeys) {
                                                    foreach ($Value in $Key) {
                                                        foreach ($ValueName in $Key.Property) {
                                                            [PSCustomObject]@{
                                                                Key = $Value.Name
                                                                Value = "$($ValueName)"
                                                                Data = Get-ItemPropertyValue -Path $Key.PSPath -Name $ValueName
                                                                Type = $Key.GetValueKind($ValueName)
                                                            }
                                                        }
                                                    }
                                                }

                                                try {
                                                    # Export registry data to temporary folder
                                                    Write-LogEntry -Value "Exporting registry data to temporary folder" -Severity 1
                                                    $OutputFileName = -join@($RuleItem.Path.Replace("\", "-").Replace(":", ""), ".csv")
                                                    $RegistryKeyData | Sort-Object -Property "Name", "Property" | Export-Csv -Path (Join-Path -Path $CurrentLogFolderPath -ChildPath $OutputFileName) -Encoding UTF8 -Delimiter ';' -NoTypeInformation -ErrorAction "Stop"
                                                }
                                                catch [System.Exception] {
                                                    Write-LogEntry -Value "Unable to export registry data to temporary folder. Error message: $($_.Exception.Message)" -Severity 3
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "No registry keys found to export in given path '$($CurrentRegistryKeyPath)'" -Severity 2
                                            }
                                        }
                                        else {
                                            Write-LogEntry -Value "Registry key '$($CurrentRegistryKeyPath)' does not exist" -Severity 2
                                        }
                                    }
                                    "MDMDiagnostics" {
                                        Write-LogEntry -Value "Processing log collection rule for MDM diagnostics" -Severity 1

                                        # Create a new folder in the temporary folder, named after the attribute LogFolderName from rule
                                        $CurrentLogFolderPath = Join-Path -Path $TempFolderPath -ChildPath $RuleItem.LogFolderName
                                        if (-not(Test-Path -Path $CurrentLogFolderPath)) {
                                            New-Item -Path $TempFolderPath -Name $RuleItem.LogFolderName -ItemType "Directory" -ErrorAction "Stop" | Out-Null
                                        }

                                        try {
                                            # Invoke MdmDiagnosticsTool.exe for area specified in rule
                                            $MDMDiagnosticsFileName = Join-Path -Path $CurrentLogFolderPath -ChildPath "MDMDiagnostics.cab"
                                            Write-LogEntry -Value "Invoking MdmDiagnosticsTool.exe using area input of '$($RuleItem.Area)' and exporting to temporary folder" -Severity 1
                                            $ArgumentList = "-area $($RuleItem.Area) -cab $($MDMDiagnosticsFileName)"
                                            Start-Process -FilePath "MdmDiagnosticsTool.exe" -ArgumentList $ArgumentList -Wait -WindowStyle "Hidden" -ErrorAction "Stop"
                                        }
                                        catch [System.Exception] {
                                            Write-LogEntry -Value "Unable to export MDM diagnostics to temporary folder. Error message: $($_.Exception.Message)" -Severity 3
                                        }
                                    }
                                    "MDMReport" {
                                        Write-LogEntry -Value "Processing log collection rule for MDM report" -Severity 1

                                        # Create a new folder in the temporary folder, named after the attribute LogFolderName from rule
                                        $CurrentLogFolderPath = Join-Path -Path $TempFolderPath -ChildPath $RuleItem.LogFolderName
                                        if (-not(Test-Path -Path $CurrentLogFolderPath)) {
                                            New-Item -Path $TempFolderPath -Name $RuleItem.LogFolderName -ItemType "Directory" -ErrorAction "Stop" | Out-Null
                                        }

                                        try {
                                            # Invoke MdmDiagnosticsTool.exe for html report
                                            Write-LogEntry -Value "Generating and exporting MdmDiagnosticsTool.exe HTML report to temporary folder" -Severity 1
                                            $ArgumentList = "-out $($CurrentLogFolderPath)"
                                            Start-Process -FilePath "MdmDiagnosticsTool.exe" -ArgumentList $ArgumentList -Wait -WindowStyle "Hidden" -ErrorAction "Stop"
                                        }
                                        catch [System.Exception] {
                                            Write-LogEntry -Value "Unable to generate and export MdmDiagnosticsTool.exe HTML report to temporary folder. Error message: $($_.Exception.Message)" -Severity 3
                                        }
                                    }
                                    "WindowsUpdateClient" {
                                        Write-LogEntry -Value "Processing log collection rule for Windows Update Client" -Severity 1

                                        # Create a new folder in the temporary folder, named after the attribute LogFolderName from rule
                                        $CurrentLogFolderPath = Join-Path -Path $TempFolderPath -ChildPath $RuleItem.LogFolderName
                                        if (-not(Test-Path -Path $CurrentLogFolderPath)) {
                                            New-Item -Path $TempFolderPath -Name $RuleItem.LogFolderName -ItemType "Directory" -ErrorAction "Stop" | Out-Null
                                        }

                                        try {
                                            # Invoke WindowsUpdateClient.exe for log collection
                                            Write-LogEntry -Value "Calling Get-WindowsUpdateLog cmdlet to export log file to temporary folder" -Severity 1
                                            Get-WindowsUpdateLog -LogPath (Join-Path -Path $CurrentLogFolderPath -ChildPath "WindowsUpdateClient.log") -ErrorAction "Stop"
                                        }
                                        catch [System.Exception] {
                                            Write-LogEntry -Value "Unable to export Windows Update client ETL files into a log file to the temporary folder. Error message: $($_.Exception.Message)" -Severity 3
                                        }
                                    }
                                }
                            }

                            try {
                                # Compress all files in temporary folder
                                $CollectedLogsArchivePath = Join-Path -Path $env:TEMP -ChildPath (-join@($env:COMPUTERNAME, "_", (Get-Date).ToString("yyyy-MM-dd-hhmmss"), ".zip"))
                                Write-LogEntry -Value "Compressing all files in temporary folder to '$($CollectedLogsArchivePath)'" -Severity 1
                                Compress-Archive -Path "$($TempFolderPath)\*" -DestinationPath $CollectedLogsArchivePath -Force -ErrorAction "Stop"

                                try {
                                    # Upload compressed log file to storage account
                                    Write-LogEntry -Value "Uploading compressed log file to storage account" -Severity 1
                                    Invoke-AzureCopyUtility -FilePath $CollectedLogsArchivePath -StorageUri $StorageUri -ErrorAction "Stop"
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value "Unable to upload compressed log file to storage account. Error message: $($_.Exception.Message)" -Severity 3
                                }

                                try {
                                    # Remove compressed log file from temporary folder
                                    Write-LogEntry -Value "Removing compressed log file '$($CollectedLogsArchivePath)'" -Severity 1
                                    Remove-Item -Path $CollectedLogsArchivePath -Force -ErrorAction "Stop"
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value "Unable to remove compressed log file from temporary folder. Error message: $($_.Exception.Message)" -Severity 3
                                }

                                try {
                                    # Remove temporary folder and all files
                                    Write-LogEntry -Value "Removing temporary folder and files recursively" -Severity 1
                                    Remove-Item -Path $TempFolderPath -Recurse -Force -ErrorAction "Stop"
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value "Unable to remove temporary folder and files recursively. Error message: $($_.Exception.Message)" -Severity 3
                                }
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "Unable to compress log files in temporary folder. Error message: $($_.Exception.Message)" -Severity 3
                            }
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Unable to create temporary folder for log collection. Error message: $($_.Exception.Message)" -Severity 3
                        }
                    }
                    else {
                        Write-LogEntry -Value "Empty response for log collection rules from Function App" -Severity 3
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Unable to retrieve log collection rules from Function App. Error message: $($_.Exception.Message)" -Severity 3
                    Write-LogEntry -Value "[$($ProactiveRemediationName)-Detection] - Completed" -Severity 1
                }
            }
            else {
                Write-LogEntry -Value "Empty response for SAS token from Function App" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Unable to retrieve SAS token from Function App. Error message: $($_.Exception.Message)" -Severity 3
        }
    }
    else {
        Write-LogEntry -Value "Script is not running on an Entra ID joined or hybrid Entra ID joined device" -Severity 2
    }

    # Output completion message to log file
    Write-LogEntry -Value "[$($ProactiveRemediationName)-Detection] - Completed" -Severity 1
}