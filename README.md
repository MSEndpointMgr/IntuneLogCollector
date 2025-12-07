# Intune Log Collector Deployment

This repository contains an Azure solution for deploying the Intune Log Collector using Bicep (recommended) or ARM templates, and a custom portal UI.

## Solution Overview
- Collect any log file, directory or event log from Intune managed devices.
- Deploys an Azure Function App, Storage Account, and Key Vault.
- Supports deployment via Azure Template Spec (with Bicep or ARM template) or direct ARM template.
- The main logic for log gathering is in the Remediation script (`Remediation Script/Detection.ps1`).
- The script connects to the Function App authenticating itself using the Entra ID device registration certificate, downloads the `LogsGatherRules.json` file from the `rules` container, and reads it for instructions on which files to collect. When all required data is gathered, the Function App is queried again for a SAS token eligible for the Storage Account container named 'logs', where the compressed archive of all gathered logs are uploaded.

## Requirements
- Azure subscription with permissions to create resources and template specs.
- The user running the deployment must have at least the **Contributor** role on the target resource group. This is required for all resources and for the deployment script to execute successfully.
- [Azure PowerShell](https://docs.microsoft.com/powershell/azure/new-azureps-module-az) or [Azure CLI](https://docs.microsoft.com/cli/azure/install-azure-cli) installed.

## Deployment Options


### 1. Publish as Azure Template Spec (Recommended)

1. **Connect to Azure with a specific tenant and subscription:**
   ```pwsh
   Connect-AzAccount -Tenant <your-tenant-id> -Subscription <your-subscription-id>
   ```
   Replace `<your-tenant-id>` and `<your-subscription-id>` with your Azure tenant and subscription IDs.

2. **Clone the repository:**
   ```pwsh
   git clone https://github.com/MSEndpointMgr/IntuneLogCollector.git
   ```


3. **Publish the template spec (Bicep):**

   **PowerShell:**
   > **Note:** Bicep CLI must be installed locally for PowerShell deployments. [Install Bicep](https://learn.microsoft.com/azure/azure-resource-manager/bicep/install)
   ```pwsh
   New-AzTemplateSpec `
     -Name "IntuneLogCollector" `
     -Version "1.0.0" `
     -ResourceGroupName "<your-resource-group>" `
     -Location "<your-location>" `
     -TemplateFile "Deploy/logcoll-spec.bicep" `
     -UIFormDefinitionFile "Deploy/logcollector-def.json"
   ```

4. **Get the template spec resource ID:**
   ```pwsh
   $specId = (Get-AzTemplateSpec -Name "IntuneLogCollector" -ResourceGroupName "<your-resource-group>").Versions["1.0.0"].Id
   ```
   Save this resource ID for deployment.

5. **Deploy the solution using the template spec:**
   - Open the Azure portal and navigate to:
     ```
     https://portal.azure.com/#create/Microsoft.TemplateSpec/resourceId/$specId
     ```
   - This will launch the custom deployment experience for the Intune Log Collector solution, allowing you to configure and deploy all required resources using the portal form.

### 2. (Optional) Deploy Directly from ARM Template (No Custom UI)

> **Note:** Bicep is the recommended format for new deployments. Direct ARM/JSON deployment is supported for legacy scenarios only.

Use the Deploy to Azure button and follow the portal prompts to configure and deploy the solution:

  [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMSEndpointMgr%2FIntuneLogCollector%2Fmain%2FDeploy%2Flogcoll-spec.json)

### Post-Deployment Cleanup

After the deployment completes (using either the Azure Deploy button or Template Spec method), you can safely remove the following resources from the resource group:

- `logcoll-script-identity` (user-assigned managed identity)
- `logsContainerPolicyScript` (deployment script resource)
- `zipDeployScript` (deployment script resource)

These resources are only required during the initial deployment and are not needed for the ongoing operation of the solution.

## Configuration

### Granting Microsoft Graph Device.Read.All Permission to the Function App

The managed system identity of the Function App must be granted the Microsoft Graph `Device.Read.All` application permission. This is required because the Function App queries Microsoft Entra ID for device records to validate and authorize requests (using the public key of the device registration certificate that's present in the alternativeSecurityIds property of the device record) from coming from the Intune-managed devices. Without this permission, the Function App will not be able to retrieve device information and will fail to process requests from clients.

#### How to assign Device.Read.All to the Function App's managed identity
> **Note:** Assigning Microsoft Graph application permissions to a managed identity must be done via PowerShell and Microsoft Graph API. The Azure Portal does not support this for managed identities as of 2025-09-08. If this changes in the future, the steps below can simply be skipped and the permission be assigned through the Azure portal.

1. **Install the Microsoft Graph PowerShell module (if not already installed):**
  ```pwsh
  # Install only the minimal required Microsoft Graph submodules for this scenario:
  Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications -Scope CurrentUser
  ```
  > The required commands (Connect-MgGraph, Get-MgServicePrincipal, New-MgServicePrincipalAppRoleAssignment, etc.) are available after installing these child modules. You do not need to install the full Microsoft.Graph module.

2. **Connect to Microsoft Graph as a `Global Administrator`, `Cloud Application Administrator` or `Application Administrator`:**
  ```pwsh
  Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All'
  ```

3. **Find the managed identity's service principal (replace `<function-app-name>` with your Function App name):**
  ```pwsh
  $sp = Get-MgServicePrincipal -Filter "displayName eq '<function-app-name>'"
  ```

4. **Get the Device.Read.All app role ID for Microsoft Graph:**
  ```pwsh
  $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
  $role = $graphSp.AppRoles | Where-Object { $_.Value -eq 'Device.Read.All' -and $_.AllowedMemberTypes -contains 'Application' }
  ```

5. **Assign Device.Read.All to the managed identity:**
  ```pwsh
  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $role.Id
  ```

6. **Verify the permission assignment:**
  ```pwsh
  Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id | Where-Object { $_.ResourceDisplayName -eq 'Microsoft Graph' }
  ```

> **You must be a Global Administrator or have sufficient directory permissions to grant admin consent for application permissions.**

Once this is done, the Function App will be able to query device records in Microsoft Graph as required for the solution to function.

#### Why is Device.Read.All needed?
- The Function App uses Microsoft Graph to look up device objects and their properties in your tenant.
- This is essential for validating device identity, alternative security IDs, and other device attributes as part of the log collection workflow.

#### How to assign Device.Read.All to the Function App's managed identity
1. **Register the permission in Azure Portal:**
   - Go to **Azure Active Directory** > **App registrations** > **Managed Identities**.
   - Find and select your Function App's managed identity (search for the Function App name).
   - In the left menu, select **API permissions** > **Add a permission**.
   - Choose **Microsoft Graph** > **Application permissions**.
   - Search for and select `Device.Read.All`.
   - Click **Add permissions**.
2. **Grant admin consent:**
   - Still in the **API permissions** blade, click **Grant admin consent for [Tenant]**.
   - Confirm the action. The status should show as "Granted for [Tenant]".

> **Note:** You must be a Global Administrator or have sufficient directory permissions to grant admin consent for application permissions.

Once this is done, the Function App will be able to query device records in Microsoft Graph as required for the solution to function.

---
### Uploading Log Collection Rules to Storage Account

After deployment, you must upload the `LogsGatherRules.json` file to the `rules` container in your Storage Account. This file controls what logs are collected from endpoints.

**Step-by-step instructions:**
1. Download or edit your `LogsGatherRules.json` file (see `Files/LogsGatherRules.json` for a sample).
2. Open the Azure Portal and navigate to your deployed Storage Account.
3. In the left menu, select **Containers** and click on the `rules` container.
4. Click **Upload** and select your `LogsGatherRules.json` file.
5. Confirm the file appears in the container.


Alternatively, you can use Azure CLI or PowerShell:

**Azure CLI:**
```pwsh
az storage blob upload --account-name <storage-account-name> --container-name rules --name LogsGatherRules.json --file Files/LogsGatherRules.json --auth-mode login
```
Replace `<storage-account-name>` with your actual storage account name.

**PowerShell (Az.Storage module):**
```pwsh
$ctx = New-AzStorageContext -StorageAccountName '<storage-account-name>'
Set-AzStorageBlobContent -Context $ctx -Container 'rules' -File 'Files/LogsGatherRules.json' -Blob 'LogsGatherRules.json'
```
Replace `<storage-account-name>` with your actual storage account name. You may be prompted to authenticate if not already logged in.

---
### Configuring the Detection.ps1 Script

The `Detection.ps1` script requires you to specify the Function App URLs and Storage Account details for log upload and rule retrieval.

**Variables to update:**
```powershell
# Enter the GetSASUri function URI
$FunctionGetSASUri = "<enter_uri_for_function_GetSASUri>"

# Enter the GetBlobContent function URI
$FunctionGetBlobContent = "<enter_uri_for_function_GetBlobContent>"
```

**How to find the Function App URLs:**
1. In the Azure Portal, go to your deployed Function App.
2. In the left menu, select **Functions**.
3. Click on the `GetSASUri` function. In the top menu, click **Get Function URL**. Copy the URL and paste it into `$FunctionGetSASUri` in your script.
4. Repeat for the `GetBlobContent` function and update `$FunctionGetBlobContent`.

**Example:**
```powershell
$FunctionGetSASUri = "https://<function-app-name>.azurewebsites.net/api/GetSASUri?code=<function-key>"
$FunctionGetBlobContent = "https://<function-app-name>.azurewebsites.net/api/GetBlobContent?code=<function-key>"
```

**Other variables to update:**
- `$StorageAccountLogsName`: The name of your Storage Account (lowercase, no hyphens, with environment suffix if used).
- `$StorageAccountLogsContainerName`: Should be `logs`.
- `$StorageAccountRulesName`: The name of your Storage Account (same as above).
- `$StorageAccountRulesContainerName`: Should be `rules`.

---
### Setting Up Remediation Script in Intune
1. **Prepare the Detection Script:**
  - Ensure the script has been modified as explained in the previous section.
2. **Create a Remediation in Intune:**
  - Go to the Microsoft Endpoint Manager admin center.
  - Navigate to **Devices > Scripts and remediations > Remediations**.
  - Click **Create**.
  - Upload `Detection.ps1` as the detection script. (You can also add a remediation script if needed.)
  - Configure assignment and schedule as desired.
3. **Ensure Access to Storage Account:**
  - Devices running the script must have internet access to the Azure Storage Account.
  - The script uses the rules file in the `rules` container to determine what to collect.
4. **Update Log Collection Rules:**
  - To change what is collected, update `LogsGatherRules.json` and upload it to the `rules` container in your storage account.

---
**Summary:**
- Upload `LogsGatherRules.json` to the `rules` container in your Storage Account.
- Update the Function App URLs and Storage Account details in `Detection.ps1`.
- Use the Azure Portal to find the correct Function URLs for both `GetSASUri` and `GetBlobContent`.

## Log Collection Rules (LogsGatherRules.json)
- The `Files/LogsGatherRules.json` file defines which logs and files are collected from target devices.
- After deployment, this file is placed in a container named `rules` on the deployed Azure Storage Account.
- You can extend log gathering by adding custom entries to the JSON file and uploading the updated file to the `rules` container.
- By default, the sample file includes common log locations for Intune and Windows diagnostics.

### Allowed Attributes in LogsGatherRules.json

The `LogsGatherRules.json` file supports only the attributes shown in the sample file. The Remediation script will only process these attributes:

- **Type**: Specifies the rule type. Allowed values include `Folder`, `MultipleFiles`, `File`, `Registry`, `MDMDiagnostics`, `MDMReport`, `WindowsUpdateClient`, `EventLog`.
- **Path**: The file, folder, or registry path to collect.
- **LogFolderName**: The name of the folder where files, logs, or exported data are copied before all gathered logs are compressed into a single archive and sent to the storage account. This helps organize collected data by source or type prior to upload.
- **Recurse**: (For `Folder` type) Boolean indicating whether to search subfolders.
- **FileExtension**: (For `Folder` type) The file extension to filter files.
- **FileNames**: (For `MultipleFiles` type) Semicolon-separated list of file names to collect.
- **Area**: (For `MDMDiagnostics` type) Semicolon-separated list of diagnostic areas.
- **EventLogName**: (For `EventLog` type) The name of the event log to collect.
- **EventLogPath**: (For `EventLog` type) The event log path (provider).

No other attributes are supported. Only use the attributes and types present in the sample file to ensure compatibility with the Remediation script.

---
### Rule Types and Attribute Constructs in LogsGatherRules.json

Below are the supported rule types and their required/optional attributes, based on the sample file:

#### Folder
Collects files from a folder, optionally filtered by extension and recursion.
```json
{
  "Type": "Folder",
  "Path": "C:\\Windows\\Logs",
  "LogFolderName": "WindowsLogs",
  "Recurse": false,
  "FileExtension": "log"
}
```
- **Type**: "Folder"
- **Path**: Folder path
- **LogFolderName**: Logical folder inside the compressed archive containing the different collected logs
- **Recurse**: (optional) true/false
- **FileExtension**: (optional) file extension to filter

#### MultipleFiles
Collects specific files from a folder.
```json
{
  "Type": "MultipleFiles",
  "Path": "C:\\Windows\\Temp",
  "LogFolderName": "WindowsTemp",
  "FileNames": "msedge_installer.log;sample_logfile_name.log"
}
```
- **Type**: "MultipleFiles"
- **Path**: Folder path
- **LogFolderName**: Logical folder inside the compressed archive containing the different collected logs
- **FileNames**: Semicolon-separated list of file names

#### File
Collects a single file.
```json
{
  "Type": "File",
  "Path": "C:\\Windows\\System32\\drivers\\CrowdStrike\\hbfw.log",
  "LogFolderName": "CrowdStrike"
}
```
- **Type**: "File"
- **Path**: File path
- **LogFolderName**: Logical folder inside the compressed archive containing the different collected logs

#### Registry
Exports a registry key.
```json
{
  "Type": "Registry",
  "Path": "HKLM:\\SOFTWARE\\Microsoft\\IntuneManagementExtension",
  "LogFolderName": "Registry"
}
```
- **Type**: "Registry"
- **Path**: Registry key path
- **LogFolderName**: Logical folder inside the compressed archive containing the different collected logs

#### MDMDiagnostics
Collects MDM diagnostics for specified areas.
```json
{
  "Type": "MDMDiagnostics",
  "Area": "Autopilot;DeviceEnrollment;DeviceProvisioning",
  "LogFolderName": "MDMDiagnostics"
}
```
- **Type**: "MDMDiagnostics"
- **Area**: Semicolon-separated diagnostic areas. For a list of available diagnostic areas, see the official Microsoft documentation: [MDMDiagnosticsTool.exe command-line options](https://learn.microsoft.com/en-us/windows/client-management/mdmdiagnosticstool-command-line)
- **LogFolderName**: Logical folder inside the compressed archive containing the different collected logs

#### MDMReport
Collects MDM report.
```json
{
  "Type": "MDMReport",
  "LogFolderName": "MDMReport"
}
```
- **Type**: "MDMReport"
- **LogFolderName**: Logical folder inside the compressed archive containing the different collected logs

#### WindowsUpdateClient
Collects Windows Update Client logs.
```json
{
  "Type": "WindowsUpdateClient",
  "LogFolderName": "WindowsUpdateClient"
}
```
- **Type**: "WindowsUpdateClient"
- **LogFolderName**: Logical folder inside the compressed archive containing the different collected logs

#### EventLog
Exports Windows event logs.
```json
{
  "Type": "EventLog",
  "EventLogName": "Application",
  "EventLogPath": "",
  "LogFolderName": "EventLogs"
}
```
- **Type**: "EventLog"
- **EventLogName**: Log name (e.g., Application, System, Operational, Admin, etc.)
- **EventLogPath**: (optional) Provider path (e.g., Microsoft-Windows-AAD)
- **LogFolderName**: Logical folder inside the compressed archive containing the different collected logs

Use only these constructs and attributes for compatibility with the Remediation script.

## Support
For issues or questions, open an issue in this repository or contact the maintainers.