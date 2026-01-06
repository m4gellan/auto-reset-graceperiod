$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!($isAdmin)) {
    Write-Error "This script needs to be run with administrator permission."
    exit
}

$definition = @"
using System;
using System.Runtime.InteropServices;
namespace Win32Api
{
    public class NtDll
    {
        [DllImport("ntdll.dll", EntryPoint="RtlAdjustPrivilege")]
        public static extern int RtlAdjustPrivilege(ulong Privilege, bool Enable, bool CurrentThread, ref bool Enabled);
    }
}
"@ 

Add-Type -TypeDefinition $definition -PassThru | Out-Null

$Enabled = $false

[Win32Api.NtDll]::RtlAdjustPrivilege(9, $true, $false, [ref]$Enabled) | Out-Null


$Administrators = [System.Security.Principal.SecurityIdentifier]"S-1-5-32-544"
$RegRights = [System.Security.AccessControl.RegistryRights]::FullControl
$AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow

$RegKeyPath = "SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod"

try {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($RegKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::takeownership)
    
    if ($key) {
        $acl = $key.GetAccessControl()
        $acl.SetOwner($Administrators)
        $key.SetAccessControl($acl)

        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($Administrators, $RegRights, $AccessControlType)
        $acl.SetAccessRule($rule)
        $key.SetAccessControl($acl)
        $key.Close()

        Write-Host "Deletando chave GracePeriod..."
        Remove-Item -Path "HKLM:\$RegKeyPath" -Force -ErrorAction SilentlyContinue
    }
}
catch {
    Write-Host "The key GracePeriod does not exist."
}


Write-Host "Restarting TermService..."
Restart-Service TermService -Force

Write-Host "Done."
