param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Destination
)
$ErrorActionPreference = 'Stop'
$original = Get-Acl -LiteralPath $Source
# Copy access rules and their inheritance protection without changing ownership.
$access = [System.Security.AccessControl.AccessControlSections]::Access
$rules = New-Object System.Security.AccessControl.FileSecurity
$rules.SetSecurityDescriptorSddlForm($original.GetSecurityDescriptorSddlForm($access), $access)
Set-Acl -LiteralPath $Destination -AclObject $rules
$copied = Get-Acl -LiteralPath $Destination
if ($copied.GetSecurityDescriptorSddlForm($access) -ne $original.GetSecurityDescriptorSddlForm($access)) {
    throw 'The staged environment did not retain the original access rules.'
}
