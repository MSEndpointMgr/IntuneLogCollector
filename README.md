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

## Notes
- For cross-tenant or public sharing with custom UI, consider publishing to the [Azure Marketplace](https://learn.microsoft.com/en-us/azure/marketplace/marketplace-publisher-guide).
- For troubleshooting, validate your ARM template and UI definition using the [ARM Tools VS Code extension](https://aka.ms/armtools).

## Support
For issues or questions, open an issue in this repository or contact the maintainers.