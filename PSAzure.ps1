#--ACCOUNTS AND SUBSCRIPTIONS--#
#--Azure Accounts
Install-Module Az
Login-AzAccount
Logout-AzAccount

#--Subscription Selection
#list allsubscriptions
Get-AzSubscription

#get subscriptions in a specific tenant
Get-AzSubscription -TenantId "TENANT_ID"

#choose subscription
Select-AzSubscription -SubscriptionID "SUBSCRIPTION_ID"

#--RESOURCE GROUPS--#
#--Retrieving Resource Groups
#get al resource groups
Get-AzResourceGroup

#Get a specific resource group by name
Get-AzResourceGroup -Name "NAME_RG"

#Get resource groups where the name begin with NAME
Get-AzResourceGroup | where ResourceGroupName -like NAME*

#Show resource groups by location
Get-AzResourceGroup |sort Location,ResourceGroupName | Format-Table -GroupBy Location ResourceGroupName,ProvisionState,Tags

#--Resources with RGs
#Find resources of a type in resource GROUPS with a specific name
Get-AzResource ResourceGroupName "NAME_RG"

#Find resources of a type matchingagains the resource name string
Get-AzResource -ResourceType
"microsoft.web/sites" -ResourceGroupName "NAME_RG"

#creatE a new RG
New-AzResourceGroup -Name "NEW_RG" -Location "LOCATION"

#delete a RG
Remove-AzResourceGroup -Name "RG_TO_DELETE"

#--Moving resources from One RG to another
$resource = Get-AzResource -ResourceType "Microsoft.ClassicCompute/storageAccounts" -ResourceName "STORAGE_ACCOUNT"
Move-AzResource -ResourceId $resource.ResourceId -DestinationResourceGroupName "NEW_RG"

#--Resource Group Tags
#Display tags
(Get-AzResourceGroup -Name "NAME_RG").tags

#get all the Azure resource groups with a specific tag
(Get-AzResourceGroup -Tag @{Owner="NAME OWNER"}).name

#get specific resources with a specific tag
(Get-AzResource -TagName Dept -TagValue Finance).name

#Add tags to an existing RG with no tags
Set-AzResourceGroup -Name EXAMPLE_GROUP -tag @{Dept="IT"; Environment="Test"}

#Add tags to an existing RG with tags | Get tags | append | Update/apply tags
$tags = (Get-AzResourceGroup - Name EXAMPLE_GROUP).tags
$tags += @{Status="Approved"}
Set-AzResourceGroup -Tag $tags -Name EXAMPLE_GROUP

#Add tags to a specific resource without tags
$newtag = Get-AzResource -ResourceName VNET_RESOURCE -ResourceGroupName EXAMPLE_GROUP
Set-AzResource -Tag @{Dept="IT"; Environment="Test"} -ResourceId $newtag.ResourceId -Force

#Apply all tags form existing RG to the resources beneath (This will override all existing tags in the RG)
$groups = Get-AzResourceGroup foreach ($group in $groups) {
    Find-AzResource -ResourceGroupNameEquals $g.ResourceGroupName | 
    foreach-object {Set-AzResource -ResourceId $_.ResourceId -Tag $g.Tags -Force}
}

#remove all tags
Set-AzResourceGroup -Tag @{} -Name RESOURCE_GROUP

#check the policy definitions in your subscription
Get-AzPolicyDefinition

#Create policies > | Create the policy in JSON | pass the file using PS
#from internet
$definition = New-AzPolicyDefinition -Name NAME_POLICY -DisplayName "DISPLAYED NAME_POLICY" -Policy 'https://samplegithub.com/azure_policy.json'
#from local
$definition = New-AzPolicyDefinition -Name NAME_POLICY -DisplayName "DISPLAYED NAME_POLICY" -Policy "c:\policies_folder\azure_policy.json"

#assing policies
$rg = Get-AzResourceGroup -Name "EXAMPLE_GROUP"
New-AzPolicyAssignment -Name NAME_POLICY -Scope $rg.ResourceId -PolicyDefinition $definition

#RCreate a Lock
New-AzResourceLock -LockLevel ReadOnly -LockNotes "NOTES ABOUT LOCK" -LockName "SL-WEBLOCK" -ResourceName "RESOURCE_NAME" -ResourceType "microsoft.web/sites"

#retrieve a Lock
Get-AzResourceLock -LockName "NAME_LOCK" -ResourceName "RESOURCE_NAME" -ResourceType "microsoft.web/sites" -ResourceGroupName "RG_NAME"

#--STORAGE--#
#list storage accounts
Get-AzStorageAccount

#Create a storage account. Requires the RG name, storage account name, valid AZ location and type (SkuName: Standard_LRSm Standard_ZRS, Standard_GRP, Standard_RAGRS, Premium_LRS)
#Optional parameters -Kind, -AccessTier
New-AzStorageAccount -ResourceGroupName "RG_NAME" -Name "STORAGE_NAME" -Location "LOCATION" -SkuName "SKU_OPTION"

#create a storage container in a storage account
New-AzStorageContainer -ResourceGroupName "RG_NAME" -AccountName "STORAGE_ACCT" -ContainerName "CONTAINER_NAME"

#delete a storage account
Remove-AzStorageAccount -ResourceGroupName "RG_NAME" -AccountName "STORAGE_ACCT"

#delete a storage container using storage acct name and container name
Remove-AzStorageContainer -ResourceGroupName "RG_NAME" -AccountName "STORAGE_ACCT" -ContainerName "CONTAINER_NAME"

#--VMS--#
#List all VMs
Get-AzVM

#list VMs in a RS
$rg = "NAME_RG"
get-AzVM -ResourceGroupName $rg

#Get a specific VM
Get-AzVM -ResourceGroupName "RG_NAME" -Name "VM_NAME"

#Create a VM
New-AzVM -Name "VM_NAME"

#--VM OPERATIONS--#
Start-AzVM -ResourceGroupName "RG_NAME" -Name "VM_NAME"
Stop-AzVM -ResourceGroupName "RG_NAME" -Name "VM_NAME"
Restart-AzVM -ResourceGroupName "RG_NAME" -Name "VM_NAME"
Remove-AzVM -ResourceGroupName "RG_NAME" -Name "VM_NAME"

#--NETWORKING--#
#list all networks
Get-AzVirtualNetwork -ResourceGroupName "RG_NAME"

#get information about a VNET
Get-AZVirtualNetwork -Name "VNET_NAME" -ResourceGroupName "RG_NAME"

#list subnets in a VNET
Get-AZVirtualNetwork -Name "VNET_NAME" -ResourceGroupName "RG_NAME" | select subnets

#get all IP addresses from a RG
Get-AzPublicIpAddress -ResourceGroupName "RG_NAME"

#Get all load balancers from a RG
Get-AzLoadBalancer -ResourceGroupName "RG_NAME"

#get all network interfaces of a RG
Get-AzNetworkInterface -ResourceGroupName "RG_NAME"

#get info about a network interface
Get-AzNetworkInterface -Name "NIC_NAME" -ResourceGroupName "RG_NAME"

#-- CREATING NETWORK RESOURCES --#
#creating Subnets
$subnet1 = New-AzVirtualNetworkSubnetConfig -Name "SUBNET1" -AdressPrefix X.X.X.X/X
$subnet2 = New-AzVirtualNetworkSubnetConfig -Name "SUBNET2" -AdressPrefix X.X.X.X/X
#creating a virtual network
$location = "LOCATION"
$vnet = New-AzVirtualNetwork -Name "NEW_VNET" -ResourceGroupName "RG_NAME" -Location $location -AdressPrefix X.X.X.X/X -subnet $subnet1,$subnet2
#testing for a unique domain name
Test-AzDnsAvailability -DomainNameLabel "DNS_NAME" -Location $location
#create a public ip address
$pip = New-AzPublicIpAddress -Name "PUBLIC_IP" -ResourceGroupName "RG_NAME" -DomainNameLabel "DNS_NAME" -Location $location AllocationMethod Dynamic
#create a frontend IP config
$frontendIP = New-AzLoadBalancerFrontendIpConfig -Name "FRONTEND_IP" -PublicIpAddress $pip
#create a backend address pool
$beAddressPool = New-AzLoadBalancerBackendAddressPoolConfig -Name "BACKEND_POOL"
#create a probe
$healthProbe = New-AzLoadBalancerProbeConfig-Name "PROBE_NAME" RequestPath 'PATH' -Protocol http -Port 80 -IntervalInSeconds 15 ProbeCount 2
#create a Load Balancer rule
$lbRule = New-AzLoadBalancerRuleConfig-Name HTTP -FrontendIpConfiguration $frontendIP -BackendAddressPool $beAddressPool -Probe $healthProbe -Protocol Tcp -FrontendPort 80 -BackendPort 80
#create an inbound NAT rule
$inboundNATRule = New-AzLoadBalancerInboundNatRuleConfig-Name "RULE_NAME" -FrontendIpConfiguration $frontendIP -Protocol TCP -FrontendPort 3441 -BackendPort 3389
#create a load balancer
$loadBalancer = New-AzLoadBalancer -ResourceGroupName "RG_NAME" -Name "LB_NAME" -Location $location -FrontendIpConfiguration $frontendIP InboundNatRule $inboundNATRule -LoadBalancingRule $lbRule -BackendAddressPool$beAddressPool -Probe $healthProbe 
#create a network interface
$nic1= New-AzNetworkInterface -ResourceGroupName "RG_NAME" Name "NIC_NAME" -Location $location -PrivateIpAddress XX.X.X.X -Subnet $subnet2 -LoadBalancerBackendAddressPool $loadBalancer.BackendAddressPools[0] -LoadBalancerInboundNatRule $loadBalancer.InboundNatRules[0]

#delete VNet
Remove-AzVirtualNetwork -Name "VNET_NAME" -ResourceGroupName "RG_NAME"
#Delete NIC
Remove-AzNetworkInterface -Name "NIC_NAME" -ResourceGroupName "RG_NAME"
#delete Load Balancer
Remove-AzLoadBalancer -Name "LB_NAME" -ResourceGroupName "RG_NAME"
#delete Public IP
Remove-AzPublicIpAddress -Name "PIP_NAME" -ResourceGroupName "RG_NAME"


#-- AZURE ACTIVE DIRECTORY COMMANDS--#
Install-Module AzureAD
Connect-AzureAd
Disconnect-AzureAD

#AZ users
Get-AzureADUser
Get-AzureADUser -ObjectId "user@domain.com"
Remove-AzureADUser -ObjectId "user@domain.com"

#Assign roles
New-AzRoleAssignment -ResourceGroupName "RG_NAME" -ObjectId "XXXXXXXXXX" -RoleDefinitionName ROLE 
#view roles
Get-AzRoleAssignment -ResourceGroupName "RG_NAME" -ObjectId "XXXXXXXXXX"
