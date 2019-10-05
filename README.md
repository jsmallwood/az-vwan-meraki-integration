# az-vwan-meraki-integration
Sample code for integrating Azure Virtual WAN with Cisco Meraki appliances at scale.

The current script utilizes PowerShell 6 for the Invoke-RestMethod.

The script will create an Azure Virtual WAN and all components.

The creation of the Azure Virtual WAN can take some time.

Once the Virtual WAN is created and the first connection is created the remaining VPN Sites and Connections happen in rapid succession. 

