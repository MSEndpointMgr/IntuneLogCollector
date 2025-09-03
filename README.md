# Intune Log Collector Deployment

This repository contains an Azure solution for deploying the Intune Log Collector using Azure Resource Manager (ARM) templates and a custom portal UI.

## Solution Overview
- Collect any log file, directory or event log from Intune managed devices.
- Deploys an Azure Function App, Storage Account, and Key Vault.
- Supports deployment via Azure Template Spec or direct ARM template.

## Prerequisites
- Azure subscription with permissions to create resources and template specs.
- [Azure PowerShell](https://docs.microsoft.com/powershell/azure/new-azureps-module-az) or [Azure CLI](https://docs.microsoft.com/cli/azure/install-azure-cli) installed.

## Deployment Options

### 1. Publish as Azure Template Spec (Recommended for Custom UI)

1. **Connect to Azure with a specific tenant and subscription:**
   ```pwsh
   Connect-AzAccount -Tenant <your-tenant-id> -Subscription <your-subscription-id>
   ```
   Replace `<your-tenant-id>` and `<your-subscription-id>` with your Azure tenant and subscription IDs.

2. **Clone the repository:**
   ```pwsh
   git clone https://github.com/MSEndpointMgr/IntuneLogCollector.git
   ```

3. **Publish the template spec:**
   ```pwsh
   New-AzTemplateSpec `
     -Name "IntuneLogCollector" `
     -Version "1.0.0" `
     -ResourceGroupName "<your-resource-group>" `
     -Location "<your-location>" `
     -TemplateFile "Deploy/logcollector-spec.json" `
     -UIFormDefinitionFile "Deploy/logcollector-def.json"
   ```
   Replace `<your-resource-group>` and `<your-location>` with your values.

4. **Get the template spec resource ID:**
   ```pwsh
   (Get-AzTemplateSpec -Name "IntuneLogCollector" -ResourceGroupName "<your-resource-group>").Versions["1.0.0"].Id
   ```

5. **Share the resource ID:**
   Users can deploy using the Azure portal:
   ```
   https://portal.azure.com/#create/Microsoft.TemplateSpec/resourceId/<template-spec-resource-id>
   ```

### 2. Deploy Directly from ARM Template (No Custom UI)

1. Use the Deploy to Azure button and follow the portal prompts to configure and deploy the solution:
   
   [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMSEndpointMgr%2FIntuneLogCollector%2Fmain%2FDeploy%2Flogcollector-spec.json)

## Configuration

### Log Collection Rules (LogsGatherRules.json)
- The `Files/LogsGatherRules.json` file defines which logs and files are collected from target devices.
- After deployment, this file is placed in a container named `rules` on the deployed Azure Storage Account.
- You can extend log gathering by adding custom entries to the JSON file and uploading the updated file to the `rules` container.
- By default, the sample file includes common log locations for Intune and Windows diagnostics.

### Allowed Attributes in LogsGatherRules.json

The `LogsGatherRules.json` file supports only the attributes shown in the sample file. The Proactive Remediation script will only process these attributes:

- **Type**: Specifies the rule type. Allowed values include `Folder`, `MultipleFiles`, `File`, `Registry`, `MDMDiagnostics`, `MDMReport`, `WindowsUpdateClient`, `EventLog`.
- **Path**: The file, folder, or registry path to collect.
- **LogFolderName**: The name of the folder where files, logs, or exported data are copied before all gathered logs are compressed into a single archive and sent to the storage account. This helps organize collected data by source or type prior to upload.
- **Recurse**: (For `Folder` type) Boolean indicating whether to search subfolders.
- **FileExtension**: (For `Folder` type) The file extension to filter files.
- **FileNames**: (For `MultipleFiles` type) Semicolon-separated list of file names to collect.
- **Area**: (For `MDMDiagnostics` type) Semicolon-separated list of diagnostic areas.
- **EventLogName**: (For `EventLog` type) The name of the event log to collect.
- **EventLogPath**: (For `EventLog` type) The event log path (provider).

No other attributes are supported. Only use the attributes and types present in the sample file to ensure compatibility with the Proactive Remediation script.

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
- **LogFolderName**: Destination folder name
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
- **LogFolderName**: Destination folder name
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
- **LogFolderName**: Destination folder name

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
- **LogFolderName**: Destination folder name

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
- **Area**: Semicolon-separated diagnostic areas
- **LogFolderName**: Destination folder name

#### MDMReport
Collects MDM report.
```json
{
  "Type": "MDMReport",
  "LogFolderName": "MDMReport"
}
```
- **Type**: "MDMReport"
- **LogFolderName**: Destination folder name

#### WindowsUpdateClient
Collects Windows Update Client logs.
```json
{
  "Type": "WindowsUpdateClient",
  "LogFolderName": "WindowsUpdateClient"
}
```
- **Type**: "WindowsUpdateClient"
- **LogFolderName**: Destination folder name

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
- **LogFolderName**: Destination folder name

Use only these constructs and attributes for compatibility with the Proactive Remediation script.

### Proactive Remediation Script
- The main logic for log gathering is in the Proactive Remediation script (`Proactive Remediation/Detection.ps1`).
- The script connects to the storage account, downloads the `LogsGatherRules.json` file from the `rules` container, and reads it for instructions on which files to collect.

#### Setting Up Proactive Remediation in Intune
1. **Prepare the Detection Script:**
   - Use the provided `Proactive Remediation/Detection.ps1` script as the detection logic for your remediation.
   - Modify the script if needed to match your environment or log collection requirements.
2. **Create a Proactive Remediation in Intune:**
   - Go to the Microsoft Endpoint Manager admin center.
   - Navigate to **Reports > Endpoint analytics > Proactive remediations**.
   - Click **Create script package**.
   - Upload `Detection.ps1` as the detection script. (You can also add a remediation script if needed.)
   - Configure assignment and schedule as desired.
3. **Ensure Access to Storage Account:**
   - Devices running the script must have network access to the Azure Storage Account.
   - The script uses the rules file in the `rules` container to determine what to collect.
4. **Update Log Collection Rules:**
   - To change what is collected, update `LogsGatherRules.json` and upload it to the `rules` container in your storage account.

For more details, refer to the official [Intune Proactive Remediation documentation](https://learn.microsoft.com/en-us/mem/analytics/proactive-remediations) or open an issue for support.

## Notes
- For cross-tenant or public sharing with custom UI, consider publishing to the [Azure Marketplace](https://learn.microsoft.com/en-us/azure/marketplace/marketplace-publisher-guide).
- For troubleshooting, validate your ARM template and UI definition using the [ARM Tools VS Code extension](https://aka.ms/armtools).

## Support
For issues or questions, open an issue in this repository or contact the maintainers.