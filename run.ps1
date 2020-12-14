<#
    .SYNOPSIS
        Send Azure Policy Alerts and compliance state to subscription owner via email

    .DESCRIPTION
  
    .NOTES

    .COMPONENT
        Requires Module AzureRM.Profile >= 5.8.3
        Requires Module AzureRM.PolicyInsights
        Requires Module Azure.Policy 

    .LINK
#>

# Parameter Set
param (
)

# Functions
# Get Azure API Token Function
function getOAuthToken {
    $AzureRMSubscription = (Get-AzureRmContext).Subscription
    $AzureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $RMProfileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($AzureRmProfile)
    $OAuthToken = $RMProfileClient.AcquireAccessToken($AzureRMSubscription.TenantId)

    return $OAuthToken
}

# connect to Azure
$connectionName = "AzureRunAsConnection"
try
{
    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName         

    "Logging in to Azure..."
    Add-AzureRmAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
}
catch {
    if (!$servicePrincipalConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

# local variables
$location = $env:temp # location will be used to store images and html content files during runtime
$StorageAccountName = Get-AutomationVariable -Name ""
$StorageAccountKey = Get-AutomationVariable -Name ""
$contentContainerName = ""

# SMTP and mail variables 
$cred = Get-AutomationPSCredential -Name ""
$SMTPServer = ""
$From = ""
$Subject = ""

# Load files from storage account
try {
    $ctx = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey
    # Download file to temp dir
    Get-AzureStorageBlob -Container $contentContainerName -Context $ctx | Get-AzureStorageBlobContent -Destination $location | Out-Null
}
catch {
    "ERR: Download files from Storage Account"
    $_.Exception.Message
    $_.Exception.ItemName
    break
}

# Get REST API token
$OAuthToken = getOAuthToken

# Get all enabled subscriptions
$allSubscriptions = Get-AzureRmSubscription | Where-Object { $_.State -eq 'Enabled' }

foreach ($s in $allSubscriptions) {
    try {
        # Select subscription
        Select-AzureRmSubscription -SubscriptionId $s.SubscriptionId | Out-Null
        write-output "INFO: Running policy compliance check for Subscription: $($s.Name)!"
    }
    catch {
        "ERR: Select subscription"
        $_.Exception.Message
        $_.Exception.ItemName
        continue
    }

    # region Get Compliance data and subscription information
    # Get tags for all resource groups of current subscription
    $tags = $null
    $tags = Get-AzureRmResourceGroup | Where-Object {$_.Tags -ne $null}

    $TagsObject = @()
    $resourcegrouptagsString = $null

    if($tags){
        foreach ($item in $tags)
        {
            $Object = New-Object PSObject -Property $item.Tags

            $tempObject = New-Object PSObject -Property @{       
                RG              = $item.ResourceGroupName
                TagName         = $($Object.'FACTSID') # als Idee für Schutzklassen Tags
            }
        
            $TagsObject += $tempObject;
        }

        if(!$TagsObject) {
            $resourcegrouptagsString = "Resource Group tags not set. Please set tags!"
        }
    }

    # Get policy compliance of current subscription
    $compliance = $null
    $compliance = Get-AzureRmPolicyStateSummary
    $policyAssignments = (Get-AzureRmPolicyStateSummary).PolicyAssignments

    $complianceObject = @()
    $nonCompliantResource = $null
    $nonCompliantPolicies = $null
    
    # Get azure security center security contacts
    $output = $null
    $Header = @{"Content-Type" = "application/json"; "Authorization" = ("Bearer {0}" -f $OAuthToken.AccessToken) }
    $getACScontact = "https://management.azure.com/subscriptions/$($s.subscriptionId)/providers/Microsoft.Security/securityContacts?api-version=2017-08-01-preview"
    $output = Invoke-RestMethod -Uri $getACScontact -Method GET -Headers $Header

    if ($output) {
        $AscContacts = $output.value.properties.email
        [string]$AscContactsList = $null
        foreach ($i in $AscContacts ) {
            $AscContactsList += $i
            if ($AscContacts.IndexOf($i) -lt ($AscContacts.Count - 1)) {
                $AscContactsList += "<br>"
            }
        }
        # Get Azure Security Center phone contact
        $phone = $null
        $phone = ($output.value | Where-Object {$_.Name -eq "default1"}).properties.phone
    }

    # Get azure security center recommendations from Azure Resource Graph API
    $request = $null
    $query = $null
    $query = @"
{
"subscriptions": [
"$($s.Id)"
],
"query": "SecurityResources | where type == 'microsoft.security/assessments' | where subscriptionId == '$($s.Id)' | extend assessmentKey = name, resourceId = tolower(trim(' ',tostring(properties.resourceDetails.Id))), healthStatus = properties.status.code, displayName = properties.displayName | where healthStatus =~ 'unhealthy' | where properties.metadata.assessmentType == "BuiltIn"| summarize count() by tostring(displayName) | order by count_"
}
"@

    $Header = @{"Content-Type" = "application/json"; "Authorization" = ("Bearer {0}" -f $OAuthToken.AccessToken) }
    $getACSRecommendation = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2018-09-01-preview"
    $request = Invoke-RestMethod -Uri $getACSRecommendation -Method POST -Headers $Header -body $query
 
    $ascCompliance = @();
    for ($i = 0; $i -lt $request.data.rows.Count; $i++) { 
        $tempObject = New-Object PSObject -Property @{            
            Name            = $request.data.rows[$i][0]
            FailedResources = $request.data.rows[$i][1]
        }
        if($tempObject.Name -and $tempObject.FailedResources) {
            $ascCompliance += $tempObject;
        }
    }

    $ascNonCompliantItems = $null
    $ascNonCompliantResources = $null
    $ascNonCompliantItems = $ascCompliance.count
    if ($ascNonCompliantItems -ne 0) {
        $ascCompliance.FailedResources | ForEach-Object { $ascNonCompliantResources += $_ }
    }
    else { $ascNonCompliantResources = 0 }

    #endregion 

    #region Load HTML files
    # Load email body outline from file
    $body = $null
    $body = Get-Content "$location\htmlBody.html" | Out-String

    # Load html tables
    $body_SubscriptionOwnerRows = @()
    $subownerTableRow = Get-Content $location\Table0_Row_SubOwner.html

    $body_SubscriptionRows = @()
    $subTableRow = Get-Content $location\Table1_Row_SubId.html

    $body_AlertRows = @()
    $alertTableRow = Get-Content $location\Table2_Row_Alerts.html

    $framePolicyTableRow = Get-Content $location\Table2_Frame_Alerts.html

    $body_ASCAlertsRows = @()
    $ascTableRow = Get-Content $location\Table3_Row_ASC.html

    $ascTableFrame = Get-Content $location\Table3_Frame_ASC.html

    $body_ASCConfigRows = @()
    $ascConfigTableRow = Get-Content $location\Table4_Row_ASC_config.html
    #endregion

    #region Process Azure Policy compliance data
    # create Azure Policy compliance object
    $complianceObject = @()
    foreach ($policyAssignment in $policyAssignments) {
        if ($policyAssignment.Results.NonCompliantResources -eq 0) { continue; }
        # Turn off ASC Default policy initiative compliance check
        if($policyAssignment.PolicySetDefinitionId -eq '/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8' -and $policyAssignment.PolicyAssignmentId) {
            continue;
        }

        $assignment = Get-AzureRmPolicyAssignment -Id $policyAssignment.PolicyAssignmentId

        # Get type of assignment
        $policyType = $null
        if ($assignment.Properties.policyDefinitionId -like "*/policySetDefinitions/*") {
            $policyType = "Initiative"
        }
        else {
            $policyType = "Policy"
        }

        # Get assignment scope
        $scope = $null
        $scopeType = $null
        if ($policyAssignment.PolicyAssignmentId -like "*managementgroups*") {
            $string = $policyAssignment.PolicyAssignmentId
            $string = $string.Replace("/providers/microsoft.management/managementgroups/", "")
            $scope = "MG: " + $string -replace '/.*'
            $scopeType = "MG"
        }
        else {
            $scope = $s.Name;
            $scopeType = "SN"
        }
    
        $tempObject = New-Object PSObject -Property @{
            Name                  = $assignment.Properties.displayName
            Scope                 = $scope
            Type                  = $policyType
            Compliance            = 'Non-Compliant'
            NonCompliantResources = $policyAssignment.Results.NonCompliantResources
            NonCompliantPolicies  = $policyAssignment.Results.NonCompliantPolicies
        }
            
        # Count non-compliant resources and policies
        $nonCompliantResource += $policyAssignment.Results.NonCompliantResources;
        $nonCompliantPolicies += $policyAssignment.Results.NonCompliantPolicies;
            
        # add list to object
        $complianceObject += $tempObject
    }
    #endregion

    #region Build subscription information table
    # Create subscription owner overview table
    $tmpRow = $null
    $tmpRow = $subownerTableRow -replace '#SUBOWNERGID_PLACEHOLDER#', $subscriptionownergid_final
    $tmpRow = $tmpRow -replace '#SUBOWNERNAME_PLACEHOLDER#', $subscriptionownername_final
    $tmpRow = $tmpRow -replace '#FACTSID_PLACEHOLDER#', $resourcegrouptagsString
    $tmpRow = $tmpRow -replace '#SUBSCRIPTIONID_PLACEHOLDER#', $s.Id
    $tmpRow = $tmpRow -replace '#SECURITYCONTACTS_PLACEHOLDER#', $AscContactsList
    $tmpRow = $tmpRow -replace '#SECURITYPHONECONTACT_PLACEHOLDER#', $phone
    $body_SubscriptionOwnerRows += $tmpRow
    
    # Add / replace data rows in the subscription owner table
    $body = $body -replace '#SUBSCRIPTIONNAME_PLACEHOLDER#', $s.Name
    $body = $body -replace '#SUBSCRIPTIONOWNERROWS_PLACEHOLDER#', $body_SubscriptionOwnerRows
    #endregion

    #region Build subscription overall compliance data
    # Create subscription overall compliance data overview table
    $tmpRow = $null
    $tmpRow = $subTableRow
    # Azure Policy row
    $tmpRow = $tmpRow -replace '#SUBID_OVERALLCOMPLIANCE#', $(if ($compliance.Results.NonCompliantPolicies -ne 0) { 'Non-Compliant' } else { 'Compliant' })
    $tmpRow = $tmpRow -replace '#SUBID_NONCOMPLIANTPOLICIES#', $(if ($nonCompliantPolicies) { $nonCompliantPolicies }else { 0 })
    $tmpRow = $tmpRow -replace '#SUBID_NONCOMPLIANTRESOURCES#', $(if ($nonCompliantResource) { $nonCompliantResource }else { 0 })
    $tmpRow = $tmpRow -replace '#policyCompliance.png#', $(if ($compliance.Results.NonCompliantPolicies -ne 0) { 'image010.png' } else { 'ok.png' })
    # Azure Security Center row
    $tmpRow = $tmpRow -replace '#SUBID_ASCOVERALLCOMPLIANCE#', $(if ($ascNonCompliantItems -ne 0) { 'Unhealthy' } else { 'Healthy' })
    $tmpRow = $tmpRow -replace '#SUBID_ASCNONCOMPLIANTPOLICIES#', $ascNonCompliantItems
    $tmpRow = $tmpRow -replace '#SUBID_ASCNONCOMPLIANTRESOURCES#', $ascNonCompliantResources
    $tmpRow = $tmpRow -replace '#ascCompliance.png#', $(if ($ascNonCompliantItems -ne 0) { 'image010.png' } else { 'ok.png' })
    $body_SubscriptionRows += $tmpRow

    # Add / replace data rows in the subscription compliance table
    $body = $body -replace '#SUBSCRIPTIONROWS_PLACEHOLDER#', $body_SubscriptionRows
    #endregion

    #region Build Azure Policy detailed compliance table
    $tmpRow = $null
    $body_AlertsRows = $null
    foreach ($al in $complianceObject) {
        $tmpRow = $alertTableRow
        $tmpRow = $tmpRow -replace '#NAME_PLACEHOLDER#', $al.Name

        if ($al.Scope -like "*MG*") {
            $tmpRow = $tmpRow -replace '#scope.png#', 'mg.png'
        }
        else {
            $tmpRow = $tmpRow -replace '#scope.png#', 'sn.png'
        }

        if ($al.Type -eq "Initiative") {
            $tmpRow = $tmpRow -replace '#type.png#', 'initiative.png'
        }
        else {
            $tmpRow = $tmpRow -replace '#type.png#', 'policy.png'
        }

        $tmpRow = $tmpRow -replace '#SCOPE_PLACEHOLDER#', $al.Scope
        $tmpRow = $tmpRow -replace '#TYPE_PLACEHOLDER#', $al.Type
        $tmpRow = $tmpRow -replace '#SETTING_PLACEHOLDER#', $al.Compliance
        $tmpRow = $tmpRow -replace '#NONCOMP_PLACEHOLDER#', $al.NonCompliantResources
        $tmpRow = $tmpRow -replace '#COMP_PLACEHOLDER#', $al.NonCompliantPolicies
        $body_AlertsRows += $tmpRow
    }

    # Substitute the dynamic row in the alerts table
    if ($compliance.Results.NonCompliantPolicies -ne 0) {
        $body = $body -replace '#POLICYTABLE_PLACEHOLDER#', $framePolicyTableRow
        $body = $body -replace '#SEGNALAZIONIROWS_PLACEHOLDER#', $body_AlertsRows
    }
    else {
        $CompliantMessage = @"
<p class="MsoNormal"><span style='font-size:10.5pt'><img width="15" height="15" src="ok.png" alt="4AE51DDF"></span><![endif]><span lang="EN-US" style='font-size:10.5pt;font-family:Arial'>&nbsp;&nbsp; Compliant, nothing to do here. <o:p></o:p></span></p>
"@
        $body = $body -replace '#POLICYTABLE_PLACEHOLDER#', $CompliantMessage
    }
    #endregion

    #region Build Azure Security Center recommendation table
    foreach ($r in $ascCompliance) {
        $tmpRow = $ascTableRow
        $tmpRow = $tmpRow -replace '#ASCNAME_PLACEHOLDER#', $r.Name
        $tmpRow = $tmpRow -replace '#ASCSETTING_PLACEHOLDER#', "Unhealthy"
        $tmpRow = $tmpRow -replace '#ASCNONCOMP_PLACEHOLDER#', $r.FailedResources

        $body_ASCAlertsRows += $tmpRow
    }
    
    # Substitute the dynamic row in the ASC recommendation table
    if ($ascNonCompliantItems -ne 0) {
        $body = $body -replace '#ASCTABLE_PLACEHOLDER#', $ascTableFrame
        $body = $body -replace '#ASCSEGNALAZIONIROWS_PLACEHOLDER#', $body_ASCAlertsRows
    }
    else {
        $CompliantMessage = @"
<p class="MsoNormal"><span style='font-size:10.5pt'><img width="15" height="15" src="ok.png" alt="4AE51DDF"></span><![endif]><span lang="EN-US" style='font-size:10.5pt;font-family:Arial'>&nbsp;&nbsp; Compliant, nothing to do here. <o:p></o:p></span></p>
"@
        $body = $body -replace '#ASCTABLE_PLACEHOLDER#', $CompliantMessage
    }
    #endregion
    
    #region Build Azure Security Center configuration table
    $output = $null
    $Header = @{"Content-Type" = "application/json"; "Authorization" = ("Bearer {0}" -f $OAuthToken.AccessToken) }
    $getACSWorkspaceSettings = "https://management.azure.com/subscriptions/$($s.subscriptionId)/providers/Microsoft.Security/workspaceSettings?api-version=2017-08-01-preview"
    $output = Invoke-RestMethod -Uri $getACSWorkspaceSettings -Method GET -Headers $Header
    if ($output.value.properties.workspaceId) {
        $ACSWorkspaceSettings = ($output.value.properties.workspaceId).Split("/")[8]
    }
    else {
        $ACSWorkspaceSettings = "Default"
    }
 
    $Header = @{"Content-Type" = "application/json"; "Authorization" = ("Bearer {0}" -f $OAuthToken.AccessToken) }
    $getACSAutoProvisioningConfig = "https://management.azure.com/subscriptions/$($s.subscriptionId)/providers/Microsoft.Security/autoProvisioningSettings/default?api-version=2017-08-01-preview"
    $output = Invoke-RestMethod -Uri $getACSAutoProvisioningConfig -Method GET -Headers $Header
    $ACSAutoProvisioningConfig = $output.properties.autoProvision
 
    $Header = @{"Content-Type" = "application/json"; "Authorization" = ("Bearer {0}" -f $OAuthToken.AccessToken) }
    $getACSPricing = "https://management.azure.com/subscriptions/$($s.subscriptionId)/providers/Microsoft.Security/pricings?api-version=2018-06-01"
    $output = Invoke-RestMethod -Uri $getACSPricing -Method GET -Headers $Header
    $ACSPricing = @();
    foreach ($item in $output.value) {
        $tempObject = New-Object PSObject -Property @{            
            Name        = $item.Name
            PricingTier = $item.properties.pricingTier
        }
 
        $ACSPricing += $tempObject;
    }
         
    $tmpRow = $null
    $tmpRow = $ascConfigTableRow
    $tmpRow = $tmpRow -replace '#ASCONFIG_PLACEHOLDER#', "Log Analytics Workspace"
    $tmpRow = $tmpRow -replace '#ASCONFIGVALUE_PLACEHOLDER#', $ACSWorkspaceSettings
    if ($ACSWorkspaceSettings) { $tmpRow = $tmpRow -replace 'warning.png', "ok.png" }
 
    $body_ASCConfigRows += $tmpRow
 
    $tmpRow = $ascConfigTableRow
    $tmpRow = $tmpRow -replace '#ASCONFIG_PLACEHOLDER#', "Autoprovisioning Mode"
    $tmpRow = $tmpRow -replace '#ASCONFIGVALUE_PLACEHOLDER#', $ACSAutoProvisioningConfig 
    if ($ACSAutoProvisioningConfig -like "On") { $tmpRow = $tmpRow -replace 'warning.png', "ok.png" }
         
    $body_ASCConfigRows += $tmpRow
 
    foreach ($item in $ACSPricing) {
        $tmpRow = $ascConfigTableRow
        $tmpRow = $tmpRow -replace '#ASCONFIG_PLACEHOLDER#', "ASC License: $($item.Name)"
        $tmpRow = $tmpRow -replace '#ASCONFIGVALUE_PLACEHOLDER#', $item.PricingTier
        if ($item.PricingTier -eq "Standard") { $tmpRow = $tmpRow -replace 'warning.png', "ok.png" }
             
        $body_ASCConfigRows += $tmpRow
    }
 
    # Substitute the dynamic row in the asc config table
    $body = $body -replace '#ASCSCONFIG_PLACEHOLDER#', $body_ASCConfigRows
    #endregion

    #region Build mail attachments
    $images = @(
        "$location\policy.png",
        "$location\resource.png",
        "$location\image007.png"
    )

    If ($body -like "*initiative.png*") { $images += "$location\initiative.png" }
    If ($body -like "*mg.png*") { $images += "$location\mg.png" }
    If ($body -like "*sn.png*") { $images += "$location\sn.png" }
    If ($body -like "*ok.png*") { $images += "$location\ok.png" }
    If ($body -like "*warning.png*") { $images += "$location\warning.png" }
    If ($body -like "*image010.png*") { $images += "$location\image010.png" }
    #endregion

    #region Send mail
    # read security center cisos and owner from the API
    $output = $null
    $Header = @{"Content-Type" = "application/json"; "Authorization" = ("Bearer {0}" -f $OAuthToken.AccessToken) }
    $getACScontact = "https://management.azure.com/subscriptions/$($s.SubscriptionId)/providers/Microsoft.Security/securityContacts?api-version=2017-08-01-preview"
    $output = Invoke-RestMethod -Uri $getACScontact -Method GET -Headers $Header

    if ($output.value.properties.email) {
        foreach ($recipient in $recipients) {
            #INFO: Creating mail object!
            $MailClient = New-Object System.Net.Mail.SmtpClient $SMTPServer
            $MailClient.Credentials = $cred
            $MailClient.Port = 587
            $MailClient.EnableSsl = $true;

            $Message = New-Object System.Net.Mail.MailMessage
            $Message.IsBodyHTML = $true;
            $Message.To.Add($Recipient)
            $Message.From = $From
            $Message.Subject = $Subject + " - " + $s.name
            $Message.Body = $body
            $Message.Attachments = $images

            try { 
                $MailClient.Send($Message)
                write-output "INFO: Send policy compliance compliance mail for Subscription: $($s.Name) to $($recipient)!"
            }    
            catch {
                "ERR: Send encrypted mail failed!"
                $_.Exception.Message
                $_.Exception.ItemName
                continue
            }
        }
    }
    else {
        write-output "INFO: Subscription: $($s.Name) has no security contacts configured!"
    }
    #endregion
}
write-output "INFO: End of runbook"