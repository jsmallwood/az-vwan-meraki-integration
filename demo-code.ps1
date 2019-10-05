#Requires -Version 6

<#
    .Author
        Jason Smallwood
        jason@motifworks.com
        www.linkedin.com/in/jasonlsmallwood
        https://github.com/jsmallwood/az-vwan-meraki-integration
    .DESCRIPTION
        The script will create an Azure Virtual WAN with Hubs for each Meraki Appliance in an Organization.
        Currently the script has only been tested with Meraki's in Passthrough or VPN Concentrator Mode.

        Within the Meraki Dashboard under Site-to-Site VPN's you must set the type to either Hub or Mesh before running the script.
        This is due to a limitation in the REST API and using Passthrough mode.

        This script leverages the Invoke-RestMethod within PowerShell 6.
    .TODO
        Test the script with Meraki Appliances configured only in Routed mode.
#>

param(
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [Alias('tenantId')]
        [String] $az_Tenant_ID = '',
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [Alias('subscriptionId')]
        [String] $az_Subscription_ID = '',
    [Parameter(Mandatory = $false,
        ValueFromPipeline = $true)]
        [Alias('resourceGroupName')]
        [String] $az_Resource_Group_Name = 'rg-vwan',
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [Alias('region', 'location')]
        [String] $az_Location = '',
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [Alias('vnetName')]
        [String] $az_Virtual_Network_Name = '',
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [Alias('vwanRG')] 
        [String] $az_Virtual_Network_Resource_Group_Name = '',
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [Alias('vwanName')]
        [String] $az_Virtual_WAN_Name = '',
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [Alias('vhubPrefix', 'hubPrefix')]
        [String] $az_Virtual_Hub_Prefix = '',
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [Alias('gatewayName')]
        [String] $az_Virtual_WAN_Gateway_Name = '',
    [Parameter(Mandatory = $false,
        ValueFromPipeline = $true)]
        [Alias('gatewayCount')]
        [Int] $az_VPN_Gateway_Scale_Unit = 1,
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [Alias('merakiApiKey', 'apiKey')]
        [String] $meraki_API_Key = '',
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [Alias('onpremRanges')]
        [Array] $meraki_On_Premise_Ranges = @("x.x.x.x/x", "x.x.x.x/x")
)


#region Do Not Modify
[String] $az_Location_Code = $az_Location.Replace(" ", "").ToLower()
[String] $az_Storage_Account_Resource_Group_Name = "microsoft-network-$($az_Location_Code)"
[String] $GLOBAL:str_Meraki_Url_Prefix = "https://api.meraki.com/api/v0"
$GLOBAL:obj_Meraki_Headers = @{
    "X-Cisco-Meraki-API-Key" = $meraki_API_Key
    "Content-Type"           = 'application/json'
    "Accept"                 = 'application/json'
}

$vpnSiteAddressSpaces = New-Object string[] $meraki_On_Premise_Ranges.Count
for ($i = 0; $i -lt $meraki_On_Premise_Ranges.Count; $i++) { $vpnSiteAddressSpaces[$i] = $meraki_On_Premise_Ranges[$i] }

[Boolean] $configGenerated = $false
#endregion

#region Utility Functions

Function New-RandomPassword {
    <#
.Synopsis
   Generates one or more complex passwords designed to fulfill the requirements for Active Directory
.DESCRIPTION
   Generates one or more complex passwords designed to fulfill the requirements for Active Directory
.EXAMPLE
   New-SWRandomPassword
   C&3SX6Kn

   Will generate one password with a length between 8  and 12 chars.
.EXAMPLE
   New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
   7d&5cnaB
   !Bh776T"Fw
   9"C"RxKcY
   %mtM7#9LQ9h

   Will generate four passwords, each with a length of between 8 and 12 chars.
.EXAMPLE
   New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
   3ABa

   Generates a password with a length of 4 containing atleast one char from each InputString
.EXAMPLE
   New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
   3ABa

   Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from
   the string specified with the parameter FirstChar
.OUTPUTS
   [String]
.NOTES
   Written by Simon Wï¿½hlin, blog.simonw.se
   I take no responsibility for any issues caused by this script.
.FUNCTIONALITY
   Generates random passwords
.LINK
   http://blog.simonw.se/powershell-generating-random-password-for-active-directory/

#>
    [CmdletBinding(DefaultParameterSetName = 'FixedLength', ConfirmImpact = 'None')]
    [OutputType([String])]
    Param
    (
        # Specifies minimum password length
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RandomLength')]
        [ValidateScript( { $_ -gt 0 })]
        [Alias('Min')]
        [int]$MinPasswordLength = 8,

        # Specifies maximum password length
        [Parameter(Mandatory = $false,
            ParameterSetName = 'RandomLength')]
        [ValidateScript( {
                if ($_ -ge $MinPasswordLength) { $true }
                else { Throw 'Max value cannot be lesser than min value.' } })]
        [Alias('Max')]
        [int]$MaxPasswordLength = 12,

        # Specifies a fixed password length
        [Parameter(Mandatory = $false,
            ParameterSetName = 'FixedLength')]
        [ValidateRange(1, 2147483647)]
        [int]$PasswordLength = 8,

        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '0123456789', '@$^*()<>!#%&'),

        # Specifies a string containing a character group from which the first character in the password will be generated.
        # Useful for systems which requires first char in password to be alphabetic.
        [String] $FirstChar,

        # Specifies number of passwords to generate.
        [ValidateRange(1, 2147483647)]
        [int]$Count = 1
    )
    Begin {
        Function Get-Seed {
            # Generate a seed for randomization
            $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
            $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
            $Random.GetBytes($RandomBytes)
            [BitConverter]::ToUInt32($RandomBytes, 0)
        }
    }
    Process {
        For ($iteration = 1; $iteration -le $Count; $iteration++) {
            $Password = @{ }
            # Create char arrays containing groups of possible chars
            [char[][]]$CharGroups = $InputStrings

            # Create char array containing all chars
            $AllChars = $CharGroups | ForEach-Object { [Char[]]$_ }

            # Set password length
            if ($PSCmdlet.ParameterSetName -eq 'RandomLength') {
                if ($MinPasswordLength -eq $MaxPasswordLength) {
                    # If password length is set, use set length
                    $PasswordLength = $MinPasswordLength
                }
                else {
                    # Otherwise randomize password length
                    $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                }
            }

            # If FirstChar is defined, randomize first char in password from that string.
            if ($PSBoundParameters.ContainsKey('FirstChar')) {
                $Password.Add(0, $FirstChar[((Get-Seed) % $FirstChar.Length)])
            }
            # Randomize one char from each group
            Foreach ($Group in $CharGroups) {
                if ($Password.Count -lt $PasswordLength) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)) {
                        $Index = Get-Seed
                    }
                    $Password.Add($Index, $Group[((Get-Seed) % $Group.Count)])
                }
            }

            # Fill out with chars from $AllChars
            for ($i = $Password.Count; $i -lt $PasswordLength; $i++) {
                $Index = Get-Seed
                While ($Password.ContainsKey($Index)) {
                    $Index = Get-Seed
                }
                $Password.Add($Index, $AllChars[((Get-Seed) % $AllChars.Count)])
            }
            Write-Output -InputObject $( -join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
        }
    }
}
#endregion

#region Meraki Dashboard Functions
Function Get-MerakiApiPrefix {
    param(
        [Parameters(Mandatory = $true,
            ValueFromPipeline = $true)]
        [String] $url
    )

    $GLOBAL:altApiPrefix = ($url | Select-String -Pattern '([^https://])(.*)').Matches[0].Value.Split('.')[0]

    return $GLOBAL:altApiPrefix
}

Function Get-MerakiOrganization {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [String] $meraki_URL_Prefix = $GLOBAL:str_Meraki_Url_Prefix,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [Object] $meraki_Headers = $GLOBAL:obj_Meraki_Headers
    )

    Try {
        $GLOBAL:obj_Meraki_Organization = (Invoke-RestMethod -Method GET -Uri "$meraki_URL_Prefix/organizations" -Headers $meraki_Headers -ErrorAction Stop).ID
    } Catch {
        Write-Error $_
    }

    return $GLOBAL:obj_Meraki_Organization
}

Function Get-MerakiNetworks {
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [Alias('orgid')]
        [String] $meraki_Organization_ID = $GLOBAL:obj_Meraki_Organization,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [Alias('networkid')]
        [AllowNull()]
        [String] $meraki_Network_ID,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [String] $meraki_URL_Prefix = $GLOBAL:str_Meraki_Url_Prefix,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [Object] $meraki_Headers = $GLOBAL:obj_Meraki_Headers
    )

    try {
        If (!($meraki_Network_ID)) {
            $obj_Meraki_Networks = Invoke-RestMethod -Method GET -Uri "$($meraki_URL_Prefix)/organizations/$($meraki_Organization_ID)/networks" -Headers $meraki_Headers
        } Else {
            $obj_Meraki_Networks = Invoke-RestMethod -Method GET -Uri "$($meraki_URL_Prefix)/organizations/$($meraki_Organization_ID)/networks/$($meraki_Network_ID)" -Headers $meraki_Headers
        }

    } catch {
        Write-Host "Unable to get Meraki Networks"
    }

    return $obj_Meraki_Networks
}
Function Get-MerakiOrganizationInventory {
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [String] $meraki_Organization_ID = $GLOBAL:obj_Meraki_Organization,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [String] $meraki_URL_Prefix = $GLOBAL:str_Meraki_Url_Prefix,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [Object] $meraki_Headers = $GLOBAL:obj_Meraki_Headers
    )

    try {
        $GLOBAL:obj_Meraki_Organization_Inventory = Invoke-RestMethod -Method GET -Uri "$($meraki_URL_Prefix)/organizations/$($meraki_Organization_ID)/inventory" -Headers $meraki_Headers
    } catch {
        Write-Host "Unable to get Meraki Organization Inventory"
    }

    return $GLOBAL:obj_Meraki_Organization_Inventory
}
Function Get-MerakiNetworkDevices {
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [Alias('networkid')]
        [AllowNull()]
        [String] $meraki_Network_ID,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [String] $meraki_URL_Prefix = $GLOBAL:str_Meraki_Url_Prefix,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [Object] $meraki_Headers = $GLOBAL:obj_Meraki_Headers
    )

    try {
        $GLOBAL:obj_Meraki_Network_Devices = Invoke-RestMethod -Method GET -Uri "$($meraki_URL_Prefix)/networks/$($meraki_Network_ID)/devices" -Headers $meraki_Headers
    } catch {
        Write-Host "Unable to get Meraki Network Devices"
    }

    return $GLOBAL:obj_Meraki_Network_Devices
}
Function Get-MerakiDeviceManagementInterface {
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [Alias('networkid')]
        [AllowNull()]
        [String] $meraki_Network_ID,
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [Alias('serial')]
        [AllowNull()]
        [String] $meraki_Device_Serial,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [String] $meraki_URL_Prefix = $GLOBAL:str_Meraki_Url_Prefix,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [Object] $meraki_Headers = $GLOBAL:obj_Meraki_Headers
    )

    try {
        $GLOBAL:obj_Meraki_Device_Management_Interface = Invoke-RestMethod -Method GET -Uri "$($meraki_URL_Prefix)/networks/$($meraki_Network_ID)/devices/$($meraki_Device_Serial)/managementInterfaceSettings" -Headers $meraki_Headers
    } catch {
        Write-Host "Unable to get Meraki Device Management Interface"
    }

    return $GLOBAL:obj_Meraki_Device_Management_Interface
}
Function Get-MerakiThirdPartyVPNPeers {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [String] $meraki_Organization_ID = $GLOBAL:obj_Meraki_Organization,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [String] $meraki_URL_Prefix = $GLOBAL:str_Meraki_Url_Prefix,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [Object] $meraki_Headers = $GLOBAL:obj_Meraki_Headers
    )

    try {
        $GLOBAL:obj_Meraki_Third_Party_VPN_Peers = Invoke-RestMethod -Method GET -Uri "$($meraki_URL_Prefix)/organizations/$($meraki_Organization_ID)/thirdPartyVPNPeers" -Headers $meraki_Headers
    } catch {
        Write-Host "Unable to get Meraki Third Party VPN Peers for Organization"
    }

    return $GLOBAL:obj_Meraki_Third_Party_VPN_Peers
}
#endregion

#region Main

    #region Authenticate to Azure Subscription
    Try { 
        Get-AzSubscription -SubscriptionId $az_Subscription_ID -TenantId $az_Tenant_ID -ErrorAction Stop | Set-AzContext -ErrorAction Stop 
    } Catch { Login-AzAccount -TenantId $az_Tenant_ID }
    #endregion

    #region Create Virtual WAN and Components
    Get-AzVirtualHub -ResourceGroupName $az_Resource_Group_Name

    $obj_Virtual_Network = (Get-AzVirtualNetwork -ResourceGroupName $az_Virtual_Network_Resource_Group_Name -Name $az_Virtual_Network_Name)

        #region Create Azure Virtual WAN
        Try {
            If ($null -eq (Get-AzVirtualWAN -ResourceGroupName $az_Resource_Group_Name -Name $az_Virtual_WAN_Name)) {
                New-AzVirtualWan -ResourceGroupName $az_Resource_Group_Name `
                    -Name $az_Virtual_WAN_Name `
                    -AllowVnetToVnetTraffic $true `
                    -AllowBranchToBranchTraffic $true `
                    -Location $az_Location `
                    -ErrorAction Stop
            }
        } Catch {
            Write-Error $_
        } Finally { $obj_Virtual_WAN = Get-AzVirtualWAN -ResourceGroupName $az_Resource_Group_Name -Name $az_Virtual_WAN_Name }
        #endregion

        #region Create Virtual HUB
        Try {
            If ($null -eq (Get-AzVirtualHub -ResourceGroupName $az_Resource_Group_Name)) {
                $az_Virtual_Hub_Name = ($az_Location_Code + "hub" + (Get-Random))

                New-AzVirtualHub -VirtualWan $obj_Virtual_WAN `
                    -ResourceGroupName $az_Resource_Group_Name `
                    -Name $az_Virtual_Hub_Name `
                    -AddressPrefix $az_Virtual_Hub_Prefix `
                    -Location $az_Location `
                    -ErrorAction Stop
            }
        } Catch {
            Write-Error $_
        } Finally {
            If (!($az_Virtual_Hub_Name)) {
                $obj_Virtual_Hub = Get-AzVirtualHub -ResourceGroupName $az_Resource_Group_Name
                $az_Virtual_Hub_Name = $obj_Virtual_Hub.Name
            } Else {
                $obj_Virtual_Hub = Get-AzVirtualHub -ResourceGroupName $az_Resource_Group_Name -Name $az_Virtual_Hub_Name
            }
        }
        #endregion

        #region Connect Virtual Hub with Virtual Network
        Try {
            If ($null -eq (Get-AzVirtualHubVnetConnection -ResourceGroupName $az_Resource_Group_Name -VirtualHubName $az_Virtual_Hub_Name -Name "$($az_Virtual_Hub_Name)-to-$($obj_Virtual_Network.Name)" )) {
                New-AzVirtualHubVnetConnection -ResourceGroupName $az_Resource_Group_Name `
                    -VirtualHubName $az_Virtual_Hub_Name `
                    -Name "$($az_Virtual_Hub_Name)-to-$($obj_Virtual_Network.Name)" `
                    -RemoteVirtualNetwork $obj_Virtual_Network `
                    -ErrorAction Stop
            }
        } Catch {
            Write-Error $_
        } Finally {
            $obj_Virtual_Hub_Connection = Get-AzVirtualHubVnetConnection -ResourceGroupName $az_Resource_Group_Name -VirtualHubName $az_Virtual_Hub_Name -Name "$($az_Virtual_Hub_Name)-to-$($obj_Virtual_Network.Name)"
        }
        #endregion

        #region Create VPN Gateway
        Try {
            If ($null -eq (Get-AzVpnGateway -ResourceGroupName $az_Resource_Group_Name -Name $az_Virtual_WAN_Gateway_Name)) {
                New-AzVpnGateway -ResourceGroupName $az_Resource_Group_Name `
                    -Name $az_Virtual_WAN_Gateway_Name `
                    -VirtualHubName $az_Virtual_Hub_Name `
                    -VpnGatewayScaleUnit $az_VPN_Gateway_Scale_Unit `
                    -ErrorAction Stop
            }
        } Catch {
            Write-Error $_
        } Finally {
            $obj_Virtual_WAN_Gateway = Get-AzVpnGateway -ResourceGroupName $az_Resource_Group_Name -Name $az_Virtual_WAN_Gateway_Name
        }
        #endregion
    #endregion

    #region Create VPN Sites and VPN Connections
    $pre_Shared_Key = (New-RandomPassword -InputStrings abcdefghijklmnopqrstuvwxyz, ABCDEFGHIJKLMNOPQRSTUVWXYZ, 1234567890 -PasswordLength 64)

    Get-MerakiOrganization | Out-Null

    Get-MerakiOrganizationInventory -meraki_Organization_ID $obj_Meraki_Organization -meraki_URL_Prefix $GLOBAL:str_Meraki_Url_Prefix -meraki_Headers $obj_Meraki_Headers | `
            ForEach-Object {

            $meraki_Network_Name = (Get-MerakiNetworks -meraki_Organization_ID $obj_Meraki_Organization -meraki_URL_Prefix $GLOBAL:str_Meraki_Url_Prefix -meraki_Headers $obj_Meraki_Headers -meraki_network_ID $_.networkID).Name
            $meraki_Network_Name = $meraki_Network_Name.Replace(' ', '')

            #region Create VPN Site
                Try {
                    New-AzVpnSite -ResourceGroupName $az_Resource_Group_Name `
                        -Name "vpnSite-$($meraki_Network_Name)" `
                        -Location $az_Location `
                        -VirtualWanName $obj_Virtual_WAN.Name `
                        -VirtualWanResourceGroupName $obj_Virtual_WAN.ResourceGroupName `
                        -IpAddress $_.publicIP `
                        -AddressSpace $vpnSiteAddressSpaces `
                        -DeviceModel $_.model `
                        -DeviceVendor 'Cisco Meraki' `
                        -AsJob `
                        -ErrorAction Stop

                    Do {
                        If (Get-AzVpnSite -ResourceGroupName $az_Resource_Group_Name -Name "vpnSite-$($meraki_Network_Name)" -ErrorAction SilentlyContinue) { Break }
                        Write-Verbose "Waiting for the VPN Site vpnSite-$($meraki_Network_Name) to be Created..."
                        Start-Sleep -Seconds 5
                    } Until ((Get-Job | Where-Object { $_.Command -eq 'New-AzVpnSite' }).State -eq 'Completed')

                    (Get-Job | Where-Object { $_.Command -eq 'New-AzVpnSite' }).State -eq 'Completed' | ForEach-Object { Remove-Job -State 'Completed' }
                } Catch {
                    Write-Error $_
                } Finally {
                    $obj_VPN_Site = (Get-AzVpnSite -ResourceGroupName $az_Resource_Group_Name -Name "vpnSite-$($meraki_Network_Name)")
                }
            #endregion

        #region Create VPN Connections
        Try {
            New-AzVpnConnection -Name "connection-$($meraki_Network_Name)" `
                -ResourceGroupName $az_Resource_Group_Name `
                -ParentResourceName $obj_Virtual_WAN_Gateway.Name `
                -VpnSite $obj_VPN_Site `
                -SharedKey (ConvertTo-SecureString -String $pre_Shared_Key -AsPlainText -Force) `
                -VpnConnectionProtocolType IKEv1 `
                -AsJob `
                -ErrorAction Stop

            Do {
                If (Get-AzVpnConnection -Name "connection-$($meraki_Network_Name)" -ParentResourceName $obj_Virtual_WAN_Gateway.Name -ResourceGroupName $az_Resource_Group_Name -ErrorAction SilentlyContinue) { Break }
                Out-Host -InputObject "Waiting on Connection connection-$($meraki_Network_Name) to be Associated with the VWAN HUB....." -Verbose
                Start-Sleep -Seconds 5
            } Until ((Get-Job | Where-Object { $_.Command -eq 'New-AzConnection' }).State -eq 'Completed')
            (Get-Job | Where-Object { $_.Command -eq 'New-AzConnection' }).State -eq 'Completed' | ForEach-Object { Remove-Job -State 'Completed' }
        } Catch {
            Write-Error $_
        } Finally {
            
            $obj_VPN_Connection = (Get-AzVpnConnection -Name "connection-$($meraki_Network_Name)" -ParentResourceName $obj_Virtual_WAN_Gateway.Name -ResourceGroupName $az_Resource_Group_Name)

            #region Download Azure Virtual WAN VPN Configuration
            If($configGenerated -eq $false) {

                $az_Storage_Account_Name = "config$(Get-Date -format 'MMddyyy')"

                If ($null -eq (Get-AzResourceGroup -Name $az_Storage_Account_Resource_Group_Name -Location $az_Location)) {
                    New-AzResourceGroup -Name $az_Storage_Account_Resource_Group_Name -Location $location
                }

                If ($null -eq (Get-AzStorageAccount -ResourceGroupName $az_Storage_Account_Resource_Group_Name -Name $az_Storage_Account_Name)) {
                    $storageAccount = New-AzStorageAccount `
                        -Name $az_Storage_Account_Name `
                        -ResourceGroupName $az_Storage_Account_Resource_Group_Name `
                        -Location $az_Location `
                        -SkuName Standard_LRS `
                        -Kind BlobStorage `
                        -AccessTier Cool `
                        -EnableHttpsTrafficOnly $true `
                        -Verbose
                } Else {
                    $storageAccount = Get-AzStorageAccount -ResourceGroupName $az_Storage_Account_Resource_Group_Name -Name $az_Storage_Account_Name
                }

                $saKey = (Get-AzStorageAccountKey -ResourceGroupName $storageAccount.ResourceGroupName -Name $storageAccount.StorageAccountName)[1].Value

                $ctx = New-AzStorageContext -StorageAccountName $storageAccount.StorageAccountName -StorageAccountKey $saKey
                
                Try {
                    $container = Get-AzStorageContainer -Name 'vpnsiteconfig' -Context $ctx -ErrorAction Stop
                } Catch {
                    New-AzStorageContainer -Name 'vpnsiteconfig' -Context $ctx
                } Finally { 
                    $container = Get-AzStorageContainer -Name 'vpnsiteconfig' -Context $ctx 
                }

                $sasToken = New-AzStorageAccountSASToken -Service Blob -ResourceType Service, Container, Object -Permission racwdlup -Context $ctx -ExpiryTime (Get-Date).AddDays(+1)   

                Do {
                    Write-Host "Waiting on the VPN Configuration to be Generated and Downloaded...." -Verbose        
                    $sasUrl = Get-AzVirtualWanVpnConfiguration -VirtualWan $obj_Virtual_WAN -StorageSasUrl "$($container.CloudBlobContainer.Uri.AbsoluteUri)/$($az_Storage_Account_Name)$($sasToken)" -VpnSite $obj_VPN_Site
                    $vpnConfigData = (Invoke-RestMethod -Method Get -Uri $sasUrl.SasUrl)
                    
                } Until ($vpnConfigData)

                If($vpnConfigData) { $configGenerated = $true }
                Write-Host "VPN Configuration Downloaded..." -Verbose

                #region Build JSON Body to Create the Meraki Third Party VPN Peers
                    $GLOBAL:json_body = @{
                        peers = @(
                            @{
                            name = "Azure vWAN Gateway 1"
                            publicIp = "$($vpnConfigData.VpnSiteConnections.gatewayConfiguration.IpAddresses.Instance0)"
                            privateSubnets = @("$($vpnConfigData.vpnSiteConnections.hubConfiguration.AddressSpace)", "$($vpnConfigData.vpnSiteConnections.hubConfiguration.ConnectedSubnets)")
                            ipsecPoliciesPreset = "azure"
                            secret = "$($vpnConfigData.VpnSiteConnections.connectionConfiguration.PSK)"
                            networkTags = @('All')
                            },
                            @{
                            name = "Azure vWAN Gateway 2"
                            publicIp = "$($vpnConfigData.VpnSiteConnections.gatewayConfiguration.IpAddresses.Instance1)"
                            privateSubnets = @("$($vpnConfigData.vpnSiteConnections.hubConfiguration.AddressSpace)", "$($vpnConfigData.vpnSiteConnections.hubConfiguration.ConnectedSubnets)")
                            ipsecPoliciesPreset = "azure"
                            secret = "$($vpnConfigData.VpnSiteConnections.connectionConfiguration.PSK)"
                            networkTags = @('All')
                            }
                        )
                    }
                #endregion

                #region Update Meraki Third Party VPN Peers
                    Try {
                        Invoke-RestMethod -Method PUT -Uri "$($GLOBAL:str_Meraki_Url_Prefix)/organizations/$($GLOBAL:obj_Meraki_Organization)/thirdPartyVPNPeers" -Headers $GLOBAL:obj_Meraki_Headers -Body ($GLOBAL:json_body | ConvertTo-Json -Depth 10) -ErrorVariable respError -ErrorAction Stop
                    } Catch { Write-Error $_}
                #endregion
            }
            #endregion
        }
        #endregion    
    }
    #endregion

#endregion
