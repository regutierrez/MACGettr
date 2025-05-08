# Requires administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
{
  Write-Error "This script requires administrator privileges. Please run as administrator."
  exit
}

#function Enable-InternetSharing
#{
#  param (
#    [string]$PublicConnection,
#    [string]$PrivateConnection
#  )
#
#  try
#  {
#    # Stop the SharedAccess service first
#    net stop SharedAccess
#
#    # Set registry keys for ICS
#    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess\Parameters"
#    if (-not (Test-Path $regPath))
#    {
#      # Create the missing registry keys
#      New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess" -Force
#      New-Item -Path $regPath -Force
#    }
#
#    # Add the EnableRebootPersistConnection registry key
#    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess" -Name "EnableRebootPersistConnection" -Value 1 -PropertyType DWord -Force
#
#    # Set service to start automatically
#    Set-Service SharedAccess -StartupType Automatic
#
#    # Get interface indexes
#    $publicAdapter = Get-NetAdapter -Name $PublicConnection -ErrorAction Stop
#    $privateAdapter = Get-NetAdapter -Name $PrivateConnection -ErrorAction Stop
#
#    # Configure ICS through registry
#    Set-ItemProperty -Path $regPath -Name "SharingMode" -Value "1" -Type DWord
#    Set-ItemProperty -Path $regPath -Name "InternetConnectionSharingEnabled" -Value "1" -Type DWord
#
#    # Set the public and private connections
#    $setupPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Services\SharedAccess\Setup"
#
#    # Check if path exists, if not create it
#    if (-not (Test-Path $setupPath))
#    {
#      # Create each level of the path that might be missing
#      $parentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Services\SharedAccess"
#      if (-not (Test-Path $parentPath))
#      {
#        $grandparentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Services"
#        if (-not (Test-Path $grandparentPath))
#        {
#          New-Item -Path $grandparentPath -Force
#        }
#        New-Item -Path $parentPath -Force
#      }
#      New-Item -Path $setupPath -Force
#    }
#
#    # Set the properties
#    Set-ItemProperty -Path $setupPath -Name "ServiceName" -Value "SharedAccess"
#    Set-ItemProperty -Path $setupPath -Name "PublicConnectionIndex" -Value $publicAdapter.InterfaceIndex -Type DWord
#    Set-ItemProperty -Path $setupPath -Name "PrivateConnectionIndex" -Value $privateAdapter.InterfaceIndex -Type DWord
#
#    # Start the SharedAccess service
#    net start SharedAccess
#
#    Write-Host "Internet Connection Sharing enabled between $PublicConnection (public) and $PrivateConnection (private)" -ForegroundColor Green
#  } catch
#  {
#    Write-Error "Failed to enable Internet Connection Sharing: $_"
#  }
#}

function Verify-EthernetIP
{
  param (
    [string]$AdapterName
  )
    
  try
  {
    $ipConfig = Get-NetIPAddress -InterfaceAlias $AdapterName -AddressFamily IPv4 -ErrorAction Stop
        
    if ($ipConfig)
    {
      $ipAddress = $ipConfig.IPAddress
      Write-Host "Ethernet adapter ($AdapterName) IP address: $ipAddress" -ForegroundColor Green
            
      if ($ipAddress -match "^192\.168\.\d{1,3}\.\d{1,3}$")
      {
        Write-Host "IP address is in the expected 192.168.x.y format" -ForegroundColor Green
        return $true
      } else
      {
        Write-Host "IP address is not in the expected 192.168.x.y format" -ForegroundColor Yellow
        return $false
      }
    } else
    {
      Write-Host "No IPv4 address found for $AdapterName" -ForegroundColor Red
      return $false
    }
  } catch
  {
    Write-Error "Failed to verify Ethernet IP: $_"
    return $false
  }
}

function Get-ConnectedDeviceMAC
{
  param (
    [string]$AdapterName
  )
    
  try
  {
    $ipConfig = Get-NetIPAddress -InterfaceAlias $AdapterName -AddressFamily IPv4 -ErrorAction Stop
    $ipAddress = $ipConfig.IPAddress
        
    $ipParts = $ipAddress.Split('.')
    $ipNetwork = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2])."
        
    Write-Host "Scanning for connected devices on $ipNetwork..." -ForegroundColor Yellow
        
    $connectedDevices = @()
    $arpTable = arp -a
        
    foreach ($line in $arpTable)
    {
      if ($line -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})")
      {
        $deviceIP = $matches[1]
        $deviceMAC = $matches[2]
       
        # get only lines within the same subnet; exclude ff-ff-ff-ff-ff-ff
        if ($deviceIP -like "$ipNetwork*" -and 
          $deviceIP -ne $ipAddress -and 
          $deviceMAC -ne "ff-ff-ff-ff-ff-ff")
        {
          $connectedDevices += [PSCustomObject]@{
            IPAddress = $deviceIP
            MACAddress = $deviceMAC
          }
        }
      }
    }
        
    if ($connectedDevices.Count -gt 0)
    {
      Write-Host "Found $($connectedDevices.Count) device(s) connected to the Ethernet adapter:" -ForegroundColor Green
      return $connectedDevices
    } else
    {
      Write-Host "No devices found connected to the Ethernet adapter" -ForegroundColor Yellow
      return $null
    }
  } catch
  {
    Write-Error "Failed to get connected device MAC addresses: $_"
    return $null
  }
}

# Main script
# $wifiAdapter = Read-Host "Enter the name of your WiFi adapter (e.g., 'Wi-Fi')"
# $ethernetAdapter = Read-Host "Enter the name of your Ethernet adapter (e.g., 'Ethernet')"

# This must be replaced by whatever the name of the ethernet adapter is
# on Control Panel > Network and Internet > Network Connections (or ncpa.cpl)
#$wifiAdapter = "Wi-Fi"
$ethernetAdapter = "Ethernet" 
#Write-Host "`n--- Step 1: Enabling Internet Connection Sharing ---" -ForegroundColor Cyan
#Enable-InternetSharing -PublicConnection $wifiAdapter -PrivateConnection $ethernetAdapter

Write-Host "`n--- Step 2: Verifying Ethernet IP Address ---" -ForegroundColor Cyan
$ipVerified = Verify-EthernetIP -AdapterName $ethernetAdapter

Write-Host "`n--- Step 3: Getting MAC Address of Connected PC ---" -ForegroundColor Cyan
if ($ipVerified)
{
  Get-ConnectedDeviceMAC -AdapterName $ethernetAdapter
} else
{
  Write-Host "Skipping MAC address detection as Ethernet IP verification failed" -ForegroundColor Yellow
}
