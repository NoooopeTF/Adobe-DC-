#This script blocks the Adobe Genuine Software Integrity Services in the firewall and adds the AMT/NGL keys into the registry to prevent Adobe from forcing you to sign in
#Made by NoooopeTF

#Run PS as Admin
if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        Start-Process PowerShell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        Exit;
    }
}

#Stop and disable Adobe Genuine Software Service
Stop-Service -name agsservice -force
Set-Service -name agsservice -startupType disabled
Get-Service -name agsservice | Select Name, Status, StartType | Out-Host

#Check if Adobe exists in the registry
IF(-Not (Test-Path -Path "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\Activation")){	
	Read-Host "The key HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\Activation does not exist. Please ensure Adobe DC is installed. Press any key to continue"
	Exit
}

try
{
#Prevent Adobe from forcing Sign-In
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\Activation" -Name "IsAMTEnforced" -Value 1 -PropertyType DWORD -Force -ErrorAction stop | Out-Null
Write-Host "IsAMTEnforced set to 1"
}
catch 
{
    
    Write-Warning $Error[0]
    Read-Host "Press any key to exit"
    Exit
}

try
{
    New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\Activation" -Name "IsNGLEnforced" -Value 0 -PropertyType DWORD -Force -ErrorAction stop | Out-Null
    Write-Host "IsNGLEnforced set to 0"
}
catch 
{
    
    Write-Warning $Error[0]
    Read-Host "Press any key to exit"
    Exit
}

try
{
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{369D313E-D964-4121-9B38-3B6DD45314AB}" -Value "v2.31|Action=Block|Active=TRUE|Dir=Out|App=%ProgramFiles% (x86)\\Common Files\\Adobe\\AdobeGCClient\\AGSService.exe|Name=Adobe Genuine Software Service|" -Force -ErrorAction stop | Out-Null
    Write-Host "Adobe Genuine Software Service incoming connections blocked"
}
catch 
{
    
    Write-Warning $Error[0]
    Read-Host "Press any key to exit"
    Exit
}

try
{
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{792CC233-0228-418D-B076-9610DF3EF5D0}" -Value "v2.31|Action=Block|Active=TRUE|Dir=In|App=%ProgramFiles% (x86)\\Common Files\\Adobe\\AdobeGCClient\\AGSService.exe|Name=Adobe Genuine Software Service|" -Force -ErrorAction stop | Out-Null
    Write-Host "Adobe Genuine Software Service outgoing connections blocked"
}
catch 
{
    
    Write-Warning $Error[0]
    Read-Host "Press any key to exit"
    Exit
}

try
{
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{9D4F4AAB-9F95-4446-ADF1-6D540C56883E}" -Value "v2.31|Action=Block|Active=TRUE|Dir=Out|App=%ProgramFiles% (x86)\\Common Files\\Adobe\\AdobeGCClient\\AdobeGCClient.exe|Name=Adobe Genuine Copy Client|" -Force -ErrorAction stop | Out-Null
    Write-Host "Adobe Genuine Copy Client outgoing connections blocked"
}
catch 
{
    
    Write-Warning $Error[0]
    Read-Host "Press any key to exit"
    Exit
}
try
{
#Block Adobe Software Integrity Service in the Firewall
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2AA6BB3A-F267-409C-BFF1-0620B62E094C}" -Value "v2.31|Action=Block|Active=TRUE|Dir=In|App=%ProgramFiles% (x86)\\Common Files\\Adobe\\AdobeGCClient\\AdobeGCClient.exe|Name=Adobe Genuine Copy Client|" -Force -ErrorAction stop | Out-Null
Write-Host "Adobe Genuine Copy Client incoming connections blocked"
}
catch 
{
    
    Write-Warning $Error[0]
    Read-Host "Press any key to exit"
    Exit
}

Read-Host "Process completed"


