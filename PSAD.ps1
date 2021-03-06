#---ACTIVE DIRECTORY--#
#install module AD
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

#Check users of an AD group, sorted and selected by name and SamAccount
Get-ADGroupMember -Identity ADGROUP | Select-Object name,SamAccountname | Format-Table -AutoSize

#check if the user USER is in the ADGroup
Get-ADGroupMember ADGROUP | Where-Object {$_.name -match "USER*"} |Select-Object name,SamAccountname | Format-Table -AutoSize

#add an AD user to an AD group using a wildcard if you are lazy to check the AD
$ad = Get-ADUser -f {name -like "USER*"}
Add-ADGroupMember -Identity ADGROUP -Members $ad.SamAccountName

#add an AD user to an AD group knowing the SamAccountName 
$ad = Get-ADUser USER
Add-ADGroupMember -Identity ADGROUP -Members $ad.SamAccountName
Get-ADGroupMember ADGROUP | Where-Object {$_.SamAccountname -match "USER"} |Select-Object name,SamAccountname | Format-Table -AutoSize 

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
Get-ADGroup -Filter * | Where-Object {-not ($_ | Get-ADGroupMember)} | Select-Object name

#add a group of users to a DL, first converting email to SAMAccountName and 
#after then adding it with the variable
$usersToDL = Get-Content 'C:\PATH' | Foreach-Object {
    Get-ADUser -Filter "mail -eq '$_'" | Select-Object -ExpandProperty SamAccountName 
} 

Add-ADGroupMember -Identity "#DL_NAME" -Members $usersToDL