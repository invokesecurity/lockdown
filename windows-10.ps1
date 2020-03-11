########################################################
#Invoke-Security
#Windoze10.lockdown
########################################################

##enable automatic updates
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 1 /f
##set password complexity
secedit /export /cfg c:\secpol.cfg
(GC C:\secpol.cfg) -Replace "PasswordComplexity = 0","PasswordComplexity = 1" | Out-File C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
Remove-Item C:\secpol.cfg -Force
##change user password
Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$newPass" -Force)
##harden Windows 10! (SANS SEC505 Scripts)

##Disable UAC via Remote (need to test)
Set-ItemProperty -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
"LocalAccountTokenFilterPolicy"=dword:00000001

#Enable CredentialGuard
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard]
"EnableVirtualizationBasedSecurity"=dword:00000001
"RequirePlatformSecurityFeatures"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"LsaCfgFlags"=dword:00000001

##Network Stuff
Get-NetAdapter
##need to have user look at network interfaces
$Adapter = Get-NetAdapter -Name "Ethernet 1"
##need to set variable that Ethernet 1 = primary interface 

Set-DnsClientServerAddress -InterfaceIndex 1 -ServerAddresses ("208.67.222.222","208.67.220.220")
Set-DnsClientServerAddress -InterfaceIndex 2 -ServerAddresses ("208.67.222.222","208.67.220.220")

##Add OpenDNS 
set-DnsClientServerAddress -InterfaceIndex 9 -ServerAddresses ("208.67.222.222","208.67.220.220")
##Add OpenDNS - Kid Friendly
set-DnsClientServerAddress -InterfaceIndex 9 -ServerAddresses ("208.67.222.123","208.67.220.123")

##DNS to try
$EthAdapters = Get-NetAdapter -Name Ether*
foreach ($EthAdapter in $EthAdapters)
{
    Set-DnsClientServerAddress -ServerAddresses 192.168.0.1, 192.168.0.2 -PassThru -InterfaceAlias $EthAdapter.name -Verbose
}

##LSS as Protected Process
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"RunAsPPL"=dword:00000001