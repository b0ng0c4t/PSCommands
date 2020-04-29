#This is the script that I’m using to find object in AD by email-address ie. shared@example.com
$M = 'shared@example.com'
Get-ADObject -Properties mail, proxyAddresses -Filter {mail -eq $M -or proxyAddresses -eq $M}  



#---Check the mailbox
$M_List = @(
#"Some.Mailbox@example.com ",
)
foreach ($M in $M_List) 
{
Get-Mailbox $M | select Identity, DisplayName, UserPrincipalName, ResourceType, RecipientTypeDetails, ProhibitSendQuota, PrimarySmtpAddress ,SKUAssigned, HiddenFromAddressListsEnabled, ForwardingAddress, ForwardingSmtpAddress
} 



#Check commands available from a module
get-module -name MODULE -ListAvailable | % {$_.ExportedCommands.Values}



#---Add user to a MBX
$User = 'user@example.com'
$MBX = 'mail@example.com'
Add-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -AutoMapping $True -Confirm:$False
Add-RecipientPermission $MBX -AccessRights SendAs -Trustee $User -confirm:$False



#---remove user of a MBX
$User = 'sample.user@example.com'
$MBX = 'sample.shared@example.com'
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -InheritanceType All -confirm:$False
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights SendAs -InheritanceType All -confirm:$False
Remove-RecipientPermission $MBX -AccessRights SendAs -Trustee $user



#---Add Multiple users to multiple MBX, you have to create the .txt files in the same folder
$MBX = Get-Content .\mailboxes.txt
$USR_list = Get-Content .\users.txt

foreach ($User in $USR_list) {
# Add with no automapping 
Add-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -AutoMapping $False -Confirm:$False
Add-RecipientPermission $MBX -AccessRights SendAs -Trustee $User -confirm:$False
}



#---Remove Multiple users of multiple MBX
$MBX = Get-Content .\mailboxes.txt
$USR_list = Get-Content .\users.txt

foreach ($User in $USR_list) {
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -InheritanceType All -confirm:$False
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights SendAs -InheritanceType All -confirm:$False
Remove-RecipientPermission $MBX -AccessRights SendAs -Trustee $user
}



#---Add user to multiple MBX
$User = 'user@example.com'
$MBX_list = get-content .\mailboxes.txt

foreach ($MBX in $MBX_list) {
# Add with automapping 
Add-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -AutoMapping $True -Confirm:$False
Add-RecipientPermission $MBX -AccessRights SendAs -Trustee $User -confirm:$False
}



#---Remove User of multiple MBX
$User = 'sample.user@example.com'
$MBX_list = get-content .\mailboxes.txt

foreach ($MBX in $MBX_list) {
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -InheritanceType All -confirm:$False
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights SendAs -InheritanceType All -confirm:$False
Remove-RecipientPermission $MBX -AccessRights SendAs -Trustee $user
}



#---Add Multiple users to MBX
$MBX = "mail@example.com"
$USR_list = Get-Content .\users.txt

foreach ($User in $USR_list) {
# Add with yes/no automapping 
Add-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -AutoMapping $False -Confirm:$True
Add-RecipientPermission $MBX -AccessRights SendAs -Trustee $User -confirm:$False
}



#--- list users in a MBX
Get-Mailbox Kundservice@techdata.nu -ResultSize:Unlimited | Get-MailboxPermission |Select-Object Identity,User,AccessRights | Where-Object {($_.user -like '*@*')}



#--- Check room permissions for users
Get-MailBoxFolderPermission -Identity "mail@example.com:\Calendar" | Select FolderName,User,AccessRights | Format-Table -AutoSize



#--- Add user to a calendar with permissions
Add-MailboxFolderPermission -identity USER@EXAMPLE.COM:\calendar -AccessRights EDITOR -User USER@EXAMPLE.COM


#--- remove all rules of a mailbox
Get-InboxRule -Mailbox MAILBOX | Remove-InboxRule -Force -Confirm:$false

#-- Rules in shared mailboxes, admin must be added ass full access to can create it
$User = 'USER'
$MBX = 'SHARED MAILBOX'
Add-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -AutoMapping $True -Confirm:$False
New-InboxRule "NAME NEW RULE" -Mailbox $MBX -From EMAIL@DOMAIN.COM -subjectContainsWords "SOME SUBJECT WORD"  -MoveToFolder 'EMAIL@DOMAIN.COM:\Inbox\SUBFOLDER\DESTINATION FOLDER' -StopProcessingRules $false
Remove-MailboxPermission -Identity $MBX -User $User -AccessRights FullAccess -InheritanceType All -confirm:$False
Get-InboxRule -Mailbox $MBX



#-- Rename AD group
Set-ADGroup -Identity "AD GROUP NAME" -DisplayName "NEW DISPLAY NAME"



#-- Get the emails of the users in a AD Group
Get-ADGroupMember -Identity "AD GROUP" -Recursive | Get-ADUser -Properties Mail | Select-Object Mail