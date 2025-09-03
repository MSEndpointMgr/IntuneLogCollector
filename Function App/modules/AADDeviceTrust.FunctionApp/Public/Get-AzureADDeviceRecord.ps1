function Get-AzureADDeviceRecord {
    <#
    .SYNOPSIS
        Retrieve an Azure AD device record.
    
    .DESCRIPTION
        Retrieve an Azure AD device record.

    .PARAMETER DeviceID
        Specify the Device ID of an Azure AD device record.

    .PARAMETER AuthToken
        Specify a hash table consisting of the authentication headers.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2022-01-01
    
        Version history:
        1.0.0 - (2021-06-07) Function created
        1.0.1 - (2022-01-01) Added support for passing in the authentication header table to the function
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the Device ID of an Azure AD device record.")]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceID
    )
    Process {
        $GraphURI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($DeviceID)'"
        $GraphResponse = (Invoke-RestMethod -Method "Get" -Uri $GraphURI -ContentType "application/json" -Headers $Global:AuthenticationHeader -ErrorAction Stop).value
        
        # Handle return response
        return $GraphResponse
    }
}