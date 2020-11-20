
$profile #to know where is the profile
$profile.AllUsersAllHosts #where is the profile of all users

$MBX = Get-Content .\mailboxes.txt
$User = Get-Content .\users.txt
$ADGroup = Get-Content .\ad_groups.txt
$GP = Get-Content .\ad_groups.txt
$email = @("email1@email.com","email2@email.com")

#---Add user to a MBX
Add-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -AutoMapping $True -Confirm:$False
Add-RecipientPermission $MBX -AccessRights SendAs -Trustee $User -confirm:$False


#---remove user of a MBX
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -InheritanceType All -confirm:$False
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights SendAs -InheritanceType All -confirm:$False
Remove-RecipientPermission $MBX -AccessRights SendAs -Trustee $User


#---Add Multiple users to multiple MBX, you have to create the .txt files in the same folder

foreach ($User in $USR) {
# Add with no automapping 
Add-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -AutoMapping $False -Confirm:$False
Add-RecipientPermission $MBX -AccessRights SendAs -Trustee $User -confirm:$False
}


#---Remove Multiple users of multiple MBX
foreach ($USR in $User) {
Remove-MailboxPermission -Identity $MBX -User $USR -AccessRights FullAccess -InheritanceType All -confirm:$False
Remove-MailboxPermission -Identity $MBX -User $USR -AccessRights SendAs -InheritanceType All -confirm:$False
Remove-RecipientPermission $MBX -AccessRights SendAs -Trustee $USR
}


#---Add user to multiple MBX
foreach ($mbox in $MBX) {
# Add with automapping 
Add-MailboxPermission -Identity $mbox -User $User -AccessRights FullAccess -AutoMapping $True -Confirm:$False
Add-RecipientPermission $mbox -AccessRights SendAs -Trustee $User -confirm:$False
}


#---Remove User of multiple MBX
foreach ($mbox in $MBX) {
Remove-MailboxPermission -Identity $mbox -User $User -AccessRights FullAccess -InheritanceType All -confirm:$False
Remove-MailboxPermission -Identity $mbox -User $User -AccessRights SendAs -InheritanceType All -confirm:$False
Remove-RecipientPermission $mbox -AccessRights SendAs -Trustee $user -confirm:$False
}


#---Add Multiple users to MBX
foreach ($User in $USR) {
# Add with yes/no automapping 
Add-MailboxPermission -Identity $MBX -User $USR -AccessRights FullAccess -AutoMapping $True -Confirm:$False
Add-RecipientPermission $MBX -AccessRights SendAs -Trustee $USR -confirm:$False
}


#---Remove Multiple users to MBX
foreach ($User in $USR) {
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -InheritanceType All -confirm:$False
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights SendAs -InheritanceType All -confirm:$False
Remove-RecipientPermission $MBX -AccessRights SendAs -Trustee $user -confirm:$False
}


#---Re-Add user to a MBX
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -InheritanceType All -confirm:$False
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights SendAs -InheritanceType All -confirm:$False
Remove-RecipientPermission $MBX -AccessRights SendAs -Trustee $user
Add-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -AutoMapping $True -Confirm:$False
Add-RecipientPermission $MBX -AccessRights SendAs -Trustee $User -confirm:$False


#-- Limit permissions in a shared mailbox
Add-MailboxPermission -Identity email1@email.com -User email1@email.com -AccessRights FullAccess
Add-RecipientPermission email1@email.com -AccessRights SendAs -Trustee email1@email.com -confirm:$False


#--- list users in a MBX
Get-Mailbox $MBX -ResultSize:Unlimited | Get-MailboxPermission |Select-Object Identity,User,AccessRights | Where-Object {($_.user -like '*@*')}
Get-Mailbox $MBX | Get-MailboxPermission | Where-Object {$_.user.tostring() -ne "NT AUTHORITY\SELF" -and $_.IsInherited -eq $false} | Select-Object Identity,User,AccessRights

#-- Get the emails of the users in a AD Group
Get-ADGroupMember -Identity $ADGroup -Recursive | Get-ADUser -Properties Mail |Select-Object Mail,Name


#-- Get emails of the users in a shared mailbox
Get-Mailbox $MBX -ResultSize:Unlimited | Get-MailboxPermission |Select-Object Identity,User,AccessRights | Where-Object {($_.user -like '*@*')}


#--- Check room permissions for users
Get-MailBoxFolderPermission -Identity "MAIL@EXAMPLE.COM:\Calendar" | Select-Object FolderName,User,AccessRights | Format-Table -AutoSize


#--- Add user to a calendar with permissions
Add-MailboxFolderPermission -identity MAIL@EXAMPLE.COM:\calendar -AccessRights EDITOR -User USER@EXAMPLE.COM


#-- Show the folder tree that have the shared mailboxes
Get-MailboxFolderStatistics -Identity $MBX -FolderScope Inbox | Select-Object Name,FolderPath 


#-- remove inbox rule
Remove-InboxRule -Mailbox $MBX -Identity 'RULE NAME'


#disable inbox rule
Disable-InboxRule -Identity "RULE NAME" -mailbox shared@domain.com


#-- Create inbox rules
Add-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -AutoMapping $True -Confirm:$False
New-InboxRule "RULE NAME" -Mailbox $MBX -From MAIL@EXAMPLE.COM  -MoveToFolder 'MAIL@EXAMPLE.COM:\Inbox\FOLDER\SUBFOLDER' -StopProcessingRules $false
New-InboxRule "RULE NAME" -Mailbox $MBX -From $email -subjectContainsWords "MATCHED WORDS"  -MoveToFolder 'MAIL@EXAMPLE.COM:\Inbox\FOLDER\SUBFOLDER' -StopProcessingRules $false
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -InheritanceType All -confirm:$False
Get-InboxRule -Mailbox $MBX


#-- Set an out off office message
Set-MailboxAutoReplyConfiguration -Identity USER@EXAMPLE.COM -AutoReplyState Enabled -InternalMessage "MESSAGE"


#Check commands available from a module
get-module -name MODULE -ListAvailable | ForEach-Object {$_.ExportedCommands.Values}

Get-InboxRule -mailbox $MBX
Get-InboxRule -Mailbox $MBX -Identity 1302653358921744385 | Format-List description
disable-InboxRule -Mailbox $MBX -Identity 7512399066404225025 | Format-List description 
Remove-InboxRule -Mailbox $MBX -Identity 15527508064574898177

#check licenses
Connect-MsolService
Get-MsolUser -UserPrincipalName EMAIL | Format-List DisplayName,Licenses
(Get-MsolUser -UserPrincipalName EMAIL).Licenses.ServiceStatus

#--- Check room permissions for users
Get-MailBoxFolderPermission -Identity "mail@example.com:\Calendar" | Select-Object FolderName, User, AccessRights | Format-Table -AutoSize


#--- Add user to a calendar with permissions
Add-MailboxFolderPermission -identity USER@EXAMPLE.COM:\calendar -AccessRights EDITOR -User USER@EXAMPLE.COM

#--- Get commands of a module
Get-Command -Module tmp_xs5ef0fy.rdk

#-- Check DLs, DLs members and add or delete them
Get-DistributionGroup -Identity $ADGroup
Get-DistributionGroupMember -Identity $ADGroup
Add-DistributionGroupMember -Identity $GP -Member $User

#-- get size of the mailbox
Get-MailboxStatistics $MBX | format-list DisplayName, TotalItemSize, ItemCount


#-- Get SamAccountName of a list of emails
Get-Content .\users.txt |
	ForEach-Object{
		Get-ADUser -Filter "EmailAddress -eq '$_'" -Properties SAMAccountName
	} |
	Select-Object SamAccountName


