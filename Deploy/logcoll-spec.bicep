// Param: environment
@allowed(['Development', 'Production'])
param environment string = 'Development'

// Param: storageAccountName
@minLength(3)
@maxLength(24)
@description('The name of the storage account. Must be 3-24 characters, lowercase, and alphanumeric. Must be globally unique in Azure.')
param storageAccountName string

// Param: storageAccountSku
param storageAccountSku string = 'Standard_LRS'

// Param: functionAppName
@minLength(3)
@maxLength(32)
@description('The name of the Function App. Must be 3-32 characters, lowercase, and alphanumeric.')
param functionAppName string

// Param: functionAppSku
@allowed([
  'Y1'      // Consumption
  'EP1'     // Premium
  'EP2'
  'EP3'
  'S1'      // Dedicated (Standard)
  'S2'
  'S3'
  'P1V2'    // Dedicated (PremiumV2)
  'P2V2'
  'P3V2'
  'P1V3'    // Dedicated (PremiumV3)
  'P2V3'
  'P3V3'
])
param functionAppSku string = 'Y1'

// Param: keyVaultName
@minLength(3)
@maxLength(24)
@description('The name of the Key Vault. Must be 3-24 characters, lowercase, and alphanumeric. Must be globally unique in Azure.')
param keyVaultName string

// Param: tags
param tags object = {}

var environmentShortName = environment == 'Production' ? 'prod' : 'dev'
var storageAccountFullName = toLower(substring(
  '${storageAccountName}${environmentShortName}',
  0,
  min(length('${storageAccountName}${environmentShortName}'), 24)
))
var functionAppPlanName = '${functionAppName}-${environmentShortName}-plan'
var functionAppResourceName = '${functionAppName}-${environmentShortName}'
var keyVaultResourceName = '${keyVaultName}-${environmentShortName}'

// User-assigned managed identity for deployment scripts
resource scriptIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'logcoll-script-identity'
  location: resourceGroup().location
}

// Assign Storage Blob Data Contributor role to the managed identity on the storage account
resource storageBlobContributor 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(scriptIdentity.id, 'StorageBlobDataContributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
    )
    principalId: scriptIdentity.properties.principalId
  }
}

// Assign Storage Account Key Operator role to the managed identity on the storage account
resource storageKeyOperator 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(scriptIdentity.id, 'StorageKeyOperator')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '81a9662b-bebf-436f-a333-f67b29880f12'
    )
    principalId: scriptIdentity.properties.principalId
  }
}

// Assign Website Contributor role to the managed identity on the Function App
resource functionAppWebsiteContributor 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(scriptIdentity.id, 'WebsiteContributor')
  scope: functionApp
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'de139f84-1756-47ae-9be6-808fbbe84772'
    )
    principalId: scriptIdentity.properties.principalId
  }
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountFullName
  location: resourceGroup().location
  tags: tags
  sku: {
    name: storageAccountSku
  }
  kind: 'StorageV2'
}

resource rulesContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  name: '${storageAccountFullName}/default/rules'
  dependsOn: [storageAccount]
  properties: {
    publicAccess: 'None'
  }
}

resource logsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  name: '${storageAccountFullName}/default/logs'
  dependsOn: [storageAccount]
  properties: {
    publicAccess: 'None'
  }
}

resource logsContainerPolicyScript 'Microsoft.Resources/deploymentScripts@2020-10-01' = {
  name: 'logsContainerPolicyScript'
  location: resourceGroup().location
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${scriptIdentity.id}': {}
    }
  }
  properties: {
    azCliVersion: '2.20.0'
    scriptContent: '''
      connectionString=$(az storage account show-connection-string --name $STORAGE_ACCOUNT_NAME --resource-group $RESOURCE_GROUP --query connectionString -o tsv)
      az storage container policy create \
        --account-name $STORAGE_ACCOUNT_NAME \
        --container-name $CONTAINER_NAME \
        --name $POLICY_NAME \
        --permission $PERMISSION \
        --connection-string "$connectionString"
    '''
    environmentVariables: [
      {
        name: 'STORAGE_ACCOUNT_NAME'
        value: storageAccountFullName
      }
      {
        name: 'RESOURCE_GROUP'
        value: resourceGroup().name
      }
      {
        name: 'CONTAINER_NAME'
        value: 'logs'
      }
      {
        name: 'POLICY_NAME'
        value: 'UploadLogs'
      }
      {
        name: 'PERMISSION'
        value: 'rw'
      }
    ]
    timeout: 'PT10M'
    cleanupPreference: 'Always'
    forceUpdateTag: '1'
    retentionInterval: 'P1D'
  }
  dependsOn: [logsContainer]
}

resource appServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: functionAppPlanName
  location: resourceGroup().location
  sku: {
    name: functionAppSku
  }
  properties: {
    reserved: false
  }
}

resource functionApp 'Microsoft.Web/sites@2022-03-01' = {
  name: functionAppResourceName
  location: resourceGroup().location
  kind: 'functionapp'
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      powerShellVersion: '~7'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmType: 'None'
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccountFullName};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${az.environment().suffixes.storage}'
        }
        {
          name: 'AllowedStorageAccounts'
          value: storageAccountFullName
        }
        {
          name: 'StorageAccountLogsName'
          value: storageAccountFullName
        }
        {
          name: 'StorageAccountLogsAccessKey'
          value: '@Microsoft.KeyVault(SecretUri=https://${keyVaultResourceName}.vault.azure.net/secrets/StorageAccountKey)'
        }
        {
          name: 'TenantId'
          value: subscription().tenantId
        }
        {
          name: 'SubscriptionId'
          value: subscription().subscriptionId
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: '1'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccountFullName};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${az.environment().suffixes.storage}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(functionAppName)
        }
        {
          name: 'KeyVaultName'
          value: keyVaultName
        }
      ]
    }
  }
}

resource zipDeployScript 'Microsoft.Resources/deploymentScripts@2020-10-01' = {
  name: 'zipDeployScript'
  location: resourceGroup().location
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${scriptIdentity.id}': {}
    }
  }
  properties: {
    azCliVersion: '2.20.0'
    scriptContent: '''
      curl -L -o app.zip https://github.com/MSEndpointMgr/IntuneLogCollector/raw/main/Packages/IntuneLogCollector-FuncApp-1.0.0.zip
      az webapp deployment source config-zip \
        --resource-group $RESOURCE_GROUP \
        --name $FUNCTION_APP_NAME \
        --src app.zip
    '''
    environmentVariables: [
      {
        name: 'RESOURCE_GROUP'
        value: resourceGroup().name
      }
      {
        name: 'FUNCTION_APP_NAME'
        value: functionAppResourceName
      }
    ]
    timeout: 'PT30M'
    cleanupPreference: 'Always'
    forceUpdateTag: '1'
    retentionInterval: 'P1D'
  }
  dependsOn: [functionApp]
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: keyVaultResourceName
  location: resourceGroup().location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    accessPolicies: [
      {
        tenantId: subscription().tenantId
        objectId: functionApp.identity.principalId
        permissions: {
          secrets: ['get', 'list']
        }
      }
    ]
  }
}

resource keyVaultSecret 'Microsoft.KeyVault/vaults/secrets@2023-02-01' = {
  parent: keyVault
  name: 'StorageAccountKey'
  properties: {
    value: storageAccount.listKeys().keys[0].value
  }
}
