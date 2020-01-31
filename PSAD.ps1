#---ACTIVE DIRECTORY--#
#install module AD
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

#Check users of an AD group, sorted and selected by name and SamAccount
Get-ADGroupMember -Identity ADGROUP | select name,SamAccountname | Format-Table -AutoSize

#check if the user USER is in the ADGroup
Get-ADGroupMember ADGROUP | Where-Object {$_.name -match "USER*"} |select name,SamAccountname | Format-Table -AutoSize

#add a AD user to an AD group
$ad = Get-ADUser -f {name -like "USER*"}
Add-ADGroupMember -Identity ADGROUP -Members $ad.SamAccountName

#check properties of an AD Group
Get-ADGroup ADGROUP

#check properties of an AD user
Get-ADUser $ad -Properties LockedOut | Select-Object LockedOut

#search an user name
Get-ADUser -f {name -like "USER*"}

#unlock account AD
$ad = Get-ADUser -f {name -like "USER*"}
Unlock-ADAccount $ad.SamAccountname
Get-ADUser $ad -Properties LockedOut | Select-Object LockedOut

#unlock account and change password
# $npass = Read-Host "Enter the new password" -AsSecureString
$ad = Get-ADUser -f {name -like "USER*"}
Unlock-ADAccount $ad.SamAccountname
Set-ADAccountPassword $ad.SamAccountName -NewPassword (ConvertTo-SecureString -AsPlainText -String "Mango001" -force)
Set-ADUser $ad.SamAccountName -ChangePasswordAtLogon $true

#disable an  AD account
$ad = Get-ADUser -f {name -like "USER*"}
Disable-ADAccount $ad.SamAccountName

#enable an AD account
$ad = Get-ADUser -f {name -like "USER*"}
enable-ADAccount $ad.SamAccountName

#find empty AD groups
Get-ADGroup -Filter * | where {-not ($_ | Get-ADGroupMember)} | select name