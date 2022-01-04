$myDomainSuffix = "mydomain.onmicrosoft.com"

function assert-MsOnlineConnection {
<#
.SYNOPSIS 
 Make sure you're connected to MSOL service
.DESCRIPTION
 Runs a cmdlet from MSOnline module; if it complains about calling Connect-MsolService, then it will do that 
.NOTES
 Auth: Roger P Seekell
 Date: 2018/2019, 3-5-2021 (PS7)
#>
    try {
        $null = Get-MsolDomain -ErrorAction Stop #we don't want the output
        #$true #returns if above was successful, which it will not if not connected
    } 
    catch {
        if ($_.tostring() -like "*is not recognized as * name of a cmdlet*") {
            Write-Error "It seems you haven't downloaded the MSOnline module.  Please get it by this command: Find-Module msonline | Install-Module"
        }
        elseif ($_.tostring() -like "*call the Connect-MsolService cmdlet before*") {
            Write-Warning "Please look for a credential window to sign into Microsoft Online; it may be behind the other windows."
            Connect-MsolService #and let it prompt the user
        } 
        else {throw $_}
    }
}#end function
#--------------------------

function assert-AzureADConnection {
<#
.SYNOPSIS 
 Make sure you're connected to AzureAD service
.DESCRIPTION
 Runs a cmdlet from AzureAD module; if it complains about calling Connect-AzureAD, then it will do that
 Roger P Seekell (date unknown)
.NOTES
 Auth: Roger P Seekell
 Date: 2018/2019, 3-5-2021 (PS7)
#>
    try {
        if (-not (Get-Module AzureAD)) {
            if ($PSVersionTable.PSVersion -like "7*") {
                Import-Module AzureAD -UseWindowsPowerShell
            }
            else {
                Import-Module AzureAD
            }
        }
        Write-Debug "We're going to run a command to see if you're (still) connected to AzureAD PowerShell"
        $null = Get-AzureADCurrentSessionInfo -ErrorAction Stop
        #$true #returns if above was successful, which it will not if not connected
    } 
    catch {
        if ($_.tostring() -like "*call the Connect-AzureAD cmdlet before*") {
            Write-Warning "Please look for a credential window to sign into Azure AD; it may be behind the other windows."
            $null = Connect-AzureAD -WhatIf:$false #let it prompt the user; hide output; don't let WhatIf apply to it
            if (-not $?) {
                throw "Unable to connect to AzureAD"
            }
        } 
        else {throw $_}
    }
}#end function
#--------------------------

function assert-ExchangeOnlineConnection {
<#
.SYNOPSIS 
 Make sure you're connected to ExchangeOnline service
.DESCRIPTION
 Runs a cmdlet from ExchangeOnline module; if it cannot, then it will run Connect-ExchangeOnline
 If user cancels authentication, then it will stop execution.
 Roger P Seekell (date unknown)
.NOTES
 Auth: Roger P Seekell
 Date: 2018/2019
#>
    Write-Debug "We're going to run a command to see if you're (still) connected to Exchange Online PowerShell"
    try {
        $null = Get-AcceptedDomain #hide output
        #if we were previously connected but lost it, it should come back by running this
    }
    catch { #then need to connect
        Write-Warning "Please look for a credential window to sign into Exchange Online; it may be behind the other windows."
        Connect-ExchangeOnline -showbanner:$false
    }
}#end function
#--------------------------

function Find-AzureADUser {
    <#
    .SYNOPSIS
     Lets one search Azure AD Users more easily
    .DESCRIPTION
     Given a string with two "words", it assumes those to be first and last names and searches accordingly
     If you want to exclude those with a JobTitle of student, then use the switch ExcludeStudent
    .PARAMETER FullName
     A string assumed to include two words, first and last name
    .PARAMETER ExcludeStudent
     Use this to filter out any match with a JobTitle of 'student'
    .EXAMPLE
     Find-AzureADUser "chris stephen"
    .EXAMPLE
     Find-AzureADUser "chris stephen" -ExcludeStudent | select-object displayname, userprincipalname, department, jobtitle
    .NOTES
     Auth: Roger P Seekell
     Date: 8/21/2020
    #>
    param (
        [Parameter(Mandatory)][string]$FullName,
        [switch]$ExcludeStudent
    )
    
    begin { 
        assert-AzureADConnection
    }
    
    process {
        ##future: support one name instead of assuming two

        #split the name into first and last
        $firstLastName = $FullName -split ' '
        $firstName = $firstLastName[0]
        $lastName = $firstLastName[1]
        #plug in first and last into Get-AzureADUser
        $foundUser = Get-AzureADUser -Filter "startswith(Givenname,'$firstName') and startswith(Surname,'$lastName')"
        if ($ExcludeStudent) {
            $foundUser = $foundUser | Where-Object JobTitle -ne "Student"
        }
        #output the results - not unlikely to get more than one
        $foundUser
    }#end process
    
    end {  } #nothing to end with
}#end function
#--------------------------

function Get-AzureAdAdminReport {
<#
.SYNOPSIS
 Lists all users in Azure AD admin roles
.DESCRIPTION
 Gets all the Directory Roles, then gets all the members of each role
 Outputs each role/member pairing, with displayname and email address (UPN)
.EXAMPLE
 Get-AzureAdAdminReport
 Saves a CSV file of all users in Azure AD admin roles to the current directory
.EXAMPLE
 Get-AzureAdAdminReport | Export-Csv -NoTypeInformation -Path 'C:\users\johndoe\OneDrive\Reports\Azure\AzureAdAdmins_2020-08-21-demo.csv'
.NOTES
 Auth: Roger P Seekell
 Date: 8/21/2020
#>

##future: can we tap into PIM and list eligible vs. active roles??

Get-AzureADDirectoryRole | ForEach-Object {
        $role = $_
        Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | 
            Add-Member -MemberType NoteProperty -Name "AdminRole" -Value $role.DisplayName -PassThru
    } | Select-Object adminrole, displayname, UserPrincipalName
}#end function
#--------------------------

function Enable-MailboxAuditing {
<#
.SYNOPSIS
 Sets audit log settings on a mailbox
.DESCRIPTION
 Given an email address (UPN) and a number of days (365 default), sets the mailbox auditing to that amount of time,
 enables auditing, and enables most or all types of auditing
.PARAMETER Identity
 Matches Identity of Get-Mailbox, the name or UPN of a mailbox in Exchange Online
.EXAMPLE
 Enable-MailboxAuditing -UPN roger.seekell@$myDomainSuffix -auditDays 100 -WhatIf
.EXAMPLE
"bob","peggy.carter@$myDomainSuffix" | Enable-MailboxAuditing
.NOTES
 Roger P Seekell, 8-17-2020
 The specific items to audit come from https://github.com/OfficeDev/O365-InvestigationTooling/blob/master/EnableMailboxAuditing.ps1 on 2-25-19
 #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)][string]$Identity,
        [int]$auditDays = 365
    )
    
    begin { 
        Write-Debug "This is the beginning of Enable-MailboxAuditing"
        assert-ExchangeOnlineConnection
     }
    
    process {
        $getMailbox = Get-Mailbox -Identity $Identity
        if ($null -ne $getMailbox) {
            #Write-Verbose 
            [int]$getMailboxAuditDays = $getMailbox.AuditLogAgeLimit.Replace('.00:00:00','')
            if ($getMailboxAuditDays -lt $auditDays) {
                Write-Debug "The current audit age setting is $getMailboxAuditDays days, not enough for $auditDays days"
                if ($PSCmdlet.ShouldProcess($Identity, "Set Auditing from $getMailboxAuditDays days to $auditDays days")) {                    
                    Set-Mailbox $Identity -AuditEnabled $true -AuditLogAgeLimit $auditDays -AuditAdmin Update, MoveToDeletedItems, SoftDelete, HardDelete, SendAs, SendOnBehalf, Create, UpdateFolderPermission -AuditDelegate Update, SoftDelete, HardDelete, SendAs, Create, UpdateFolderPermissions, MoveToDeletedItems, SendOnBehalf -AuditOwner UpdateFolderPermission, MailboxLogin, Create, SoftDelete, HardDelete, Update, MoveToDeletedItems 
                    #the specific items to audit come from https://github.com/OfficeDev/O365-InvestigationTooling/blob/master/EnableMailboxAuditing.ps1 on 2-25-19
                    if ($?) {
                        Write-Verbose "Successfully set mailbox auditing on $Identity"
                    }
                    else {
                        Write-Error "Could not enable mailbox auditing for $Identity"
                    }
                }
            }
            else {
                Write-Verbose "The current audit age setting for $Identity is $getMailboxAuditDays days, already at or more than $auditDays days"
            }
        }
        else {
            #throw "Could not find mailbox for $Identity" - unnecessary
        }
    }#end process block    
    end { 
        Write-Debug "This is the end of Enable-MailboxAuditing"
    }
}#end function
#--------------------------

function Disable-ForwardingRules {
    <#
    .SYNOPSIS
     Looks for rules that are forwarding or redirecting, and disables them
    .DESCRIPTION
     Given a mailbox, looks for rules that forward, redirect, or send text messages.
     If found, it will disable each one.
    .PARAMETER Identity
     Matches Identity of Get-Mailbox, the name or UPN of a mailbox in Exchange Online
    .EXAMPLE
    Disable-ForwardingRules DAVID.LETTERMAN@$myDomainSuffix
    .EXAMPLE
    Disable-ForwardingRules -Identity 'roger.seekell@$myDomainSuffix' -WhatIf
    .NOTES
    Auth: Roger P Seekell
    Date: 8/20/2020
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]
        $Identity
    )
    begin {
        Write-Debug "This is the start of Disable-ForwardingRules"
        assert-ExchangeOnlineConnection
    }
    process {
        $initialInboxRules = Get-InboxRule -Mailbox $Identity | Where-Object Enabled -eq $true |
            Select-Object Name, Description, Enabled, Priority, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, SendTextMessageNotificationTo, MailboxOwnerID | 
            Where-Object {($null -ne $_.ForwardTo) -or ($null -ne $_.redirectto) -or ($null -ne $_.forwardasattachmentto) -or ($_.SendTextMessageNotificationTo -ne @())}
        
        if ($initialInboxRules) { #if we have something
            $inboxRules = @()
            $inboxRules += $initialInboxRules | Where-Object {$_.SendTextMessageNotificationTo}
            $inboxRules += $initialInboxRules | Where-Object {@($_.forwardto) -notlike "*exchangelabs*" -or @($_.forwardAsAttachmentTo) -notlike "*exchangelabs*" -or @($_.RedirectTo) -notlike "*exchangelabs*"}
            #$inboxRules = @($textInboxRules, $externalInboxRules)
            if ($inboxRules.count -gt 0) {
                #now for some correct grammar
                if ($inboxRules.count -gt 1) {
                    Write-Verbose "There are $($inboxRules.count) forwarding rules for the affected user $Identity."
                }
                else {
                    Write-Verbose "There is 1 forwarding rule for the affected user $Identity."
                }
                if ($PSCmdlet.ShouldProcess($Identity)) {
                    $inboxRules | ForEach-Object  {
                        Disable-InboxRule -Mailbox $Identity -Identity $_.Name #so... -Confirm does nothing...
                    }
                    if ($?) {
                        Write-Verbose "Disable-ForwardingRules was successful"
                    }
                    else {
                        Write-Error "Disable-ForwardingRules was not successful"
                    }
                }#end should process
            }
            else {
                Write-Verbose "No invalid forwarding rules found on mailbox $Identity"
            }
        }
        else {
            Write-Verbose "No forwarding rules (of any kind) found on mailbox $Identity"
        }
    }#end process block
    end {
        Write-Debug "This is the end of Disable-ForwardingRules"
    }
}#end function
#--------------------------
    
function Remove-InvalidInboxRule {
<#
.SYNOPSIS
 Looks for invalid or malicious mailbox rules and removes them
.DESCRIPTION
 Given a mailbox identity, looks for inbox rules that are in error, reference "meeting at ATC", take action on all mail, or delete mail
 If any are found, this will remove them.
 It does get the mailbox of every item, but doesn't need to, so that could be a resource drain for a large number of mailboxes.
.PARAMETER Identity
 Matches Identity of Get-Mailbox, the name or UPN of a mailbox in Exchange Online
.EXAMPLE
 Remove-InvalidInboxRule -Identity "roger.seekell@$myDomainSuffix"
.EXAMPLE
 "andrew.martin@$myDomainSuffix", "aryan.diamond@$myDomainSuffix" | Remove-InvalidInboxRule -whatif
.EXAMPLE
 Get-DistributionGroupMember our-CCHeads-All | Remove-InvalidInboxRule
.NOTES
 Roger P Seekell, 12-1-18, 8-17-20
#>
[cmdletbinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)][string]$Identity
    )
    begin { 
        Write-Debug "This is the beginning of Remove-InvalidInboxRule"
        assert-ExchangeOnlineConnection        
    }

    process {
        $inboxRules = @() #clear it just in case
        $getMailbox = Get-Mailbox -Identity $Identity
        if ($null -ne $getMailbox) {
            $inboxRules = Get-InboxRule -Mailbox $Identity | 
            Select-Object Name, inerror, Identity, Description, Enabled, Priority, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, SendTextMessageNotificationTo, MailboxOwnerID | 
            Where-Object Enabled -eq $true

            #future: output these rules somehow for easy review

            $invalidInboxRules = $inboxrules | Where-Object {$_.inerror -eq $true -or $_.description -like "*meeting at atc*" -or $_.description -notlike "If the message*" -or $_.name -like "delete*"}

            if ($null -ne $invalidInboxRules) {
                #now to have proper grammar...
                if ($invalidInboxRules.count) {
                    Write-Verbose "There are $($invalidInboxRules.count) invalid inbox rules for the affected user $Identity."
                }
                else {
                    Write-Verbose "There is 1 invalid inbox rule for the affected user $Identity."
                }
                if ($pscmdlet.shouldProcess($Identity,"Remove invalid mailbox rules")) {
                    $invalidInboxRules | ForEach-Object  {
                        Remove-InboxRule -Identity $_.Identity #-Confirm:$false 
                    }
                    Write-Verbose "Looks like successfully removed mailbox rules from $getMailbox"
                }
            }
            else {
                Write-Verbose "No invalid inbox rules found for $Identity"
            }
        }
        else {
            Write-Error "Could not find the given mailbox: $Identity"
        }
    }#end process block
    end { 
        Write-Debug "This is the end of Remove-InvalidInboxRule"
    }
}#end function
#--------------------------

function Remove-MailboxForwarding {
    <#
    .SYNOPSIS
     If the given mailbox has mailbox forwarding, removes it.
    .DESCRIPTION
     If the given mailbox has mailbox forwarding, removes it.
    .EXAMPLE
     Remove-MailboxForwarding -Identity 'roger.seekell@$myDomainSuffix'
    .EXAMPLE
     Get-Mailbox -Identity ga_* | Remove-MailboxForwarding -WhatIf
    .PARAMETER Identity
     Matches Identity of Get-Mailbox, the name or UPN of a mailbox in Exchange Online
    .NOTES
     Auth: Roger P Seekell
     Date: 11/2018, 12/2018, 02/2019, 08/2019
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)][string]$Identity
    )
    begin { 
        Write-Debug "This is the beginning of Remove-MailboxForwarding"
        assert-ExchangeOnlineConnection        
    }
    process {
        $mailbox = Get-Mailbox -Identity $Identity
        if ($mailbox.forwardingsmtpaddress) { #is not null
            if ($pscmdlet.shouldProcess($Identity)) {
                Set-Mailbox -Identity $Identity -DeliverToMailboxAndForward $false -ForwardingSmtpAddress $null -forwarding $null
                if ($?) {
                    Write-Verbose "Successfully removed forwarding on $Identity mailbox"
                }
                else {
                    Write-Error "Unable to remove mailbox forwarding on $Identity mailbox"
                }
            }
        }
        else {
            Write-Verbose "No forwarding SMTP address found for $Identity"
        }
    }
    end { 
        Write-Debug "This is the end of Remove-MailboxForwarding"
    }
}#end function
#--------------------------

function Remove-MailboxDelegates {
    <#
    .SYNOPSIS
    Removes unwanted mailbox delegates
    .DESCRIPTION
    Given a UPN, finds the mailbox delegates that have permission and removes them
    .PARAMETER
    Matches Identity of Get-Mailbox, the name or UPN of a mailbox in Exchange Online
    .EXAMPLE
    Remove-MailboxDelegates -Identity roger.seekell@$myDomainSuffix -WhatIf
    .EXAMPLE
    Remove-MailboxDelegates -Identity steve.rogers@$myDomainSuffix -Confirm -Verbose
    .NOTES
    Auth: Roger P Seekell
    Date: 8/21/2020, 3/5/2021 (PS7)
    #>
[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory,ValueFromPipeline)]
    [String]
    $Identity
)
begin {
    Write-Debug "This is the start of Remove-MailboxDelegates"
    assert-ExchangeOnlineConnection
}
process {
    $mailboxDelegates = @(Get-MailboxPermission -Identity $Identity | Where-Object {($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*")})
    if ($mailboxDelegates.Count -gt 0) {
        #now for some correct grammar.
        if ($mailboxDelegates.Count -gt 1) {
            Write-Verbose "There are $($mailboxDelegates.count) delegates for the affected user $Identity."
        }
        else {
            Write-Verbose "There is 1 delegate for the affected user $Identity."
        }
        if ($PSCmdlet.ShouldProcess($Identity,"Remove delegate " + $mailboxDelegates.user)) {
            foreach ($delegate in $mailboxDelegates) 
            {
                Remove-MailboxPermission -Identity $Identity -User $delegate.User -AccessRights $delegate.AccessRights -InheritanceType All -ErrorAction continue #-Confirm:$false
            }
            if ($?) {
                Write-Verbose "Remove-MailboxDelegates was successful"
            }
            else {
                Write-Error "Remove-MailboxDelegates was not successful"
            }
        }#end should process
    }
    else {
        Write-Verbose "There are no delegates on the mailbox of $Identity"
    }
}#end process block
end {
    Write-Debug "This is the end of Remove-MailboxDelegates"
}
}#end function
#--------------------------

function Add-MfaGroup {
    <#
    .SYNOPSIS
     Puts user into group that requires MFA
    .DESCRIPTION
     Given some O365-MFA groups, checks if the user is in any of them (except Test)
     If not, adds to O365-MFA-CloudUsers (thus bypassing local AD)
    .EXAMPLE
     Add-MfaGroup -UserName 'roger.seekell@$myDomainSuffix' -Confirm
    .PARAMETER UserName
     Same as ObjectId for Get-AzureADUser, can take a UPN or a GUID
    .NOTES
     Auth: Roger P Seekell
     Date: 8/20/2020
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $UserName
    )
    
    begin{
        Write-Debug "This is the start of Add-MFAGroup"        
        assert-AzureADConnection
        $MfaGroupName = "O365-MFA-CloudUsers"
        $MfaGroupSearch = "O365-MFA"
        $mfaGroupSkip = "o365-mfa-test"
        $aadGroup = Get-AzureADGroup -SearchString $MfaGroupName
        $aadMfaGroups = Get-AzureADGroup -SearchString $MfaGroupSearch | Where-Object displayname -ne $mfaGroupSkip
        
    }
    process{
        ###future: check all MFA groups
        #$inGroupAlready = Get-AzureADUserMembership -ObjectId $UserName | Where-Object displayname -eq "$MfaGroupName"
        $inGroupsAlready = Get-AzureADUserMembership -ObjectId $UserName | Where-Object displayname -In $aadMfaGroups.Displayname
        ###end "future"
        
        if (-not $inGroupsAlready) {
            Write-Debug "User is not in any MFA group"
            if ($PSCmdlet.ShouldProcess($UserName)) {
                $aadUser = Get-AzureADUser -ObjectId $UserName
                if ($aadUser) { #not equal null
                    Add-AzureADGroupMember -ObjectId $aadGroup.ObjectId -RefObjectId $aadUser.objectid
                    if ($?) {
                        Write-Verbose "Success adding $username to $MfaGroupName"
                    }
                    else {
                        Write-Error "Could not add $username to $MfaGroupName"
                    }
                }
                else {
                    Write-Error "Could not find the Azure AD user named $UserName"
                }
            }
        }#end if not in group already
        else {
            Write-Verbose "$UserName is already a member of an MFA Group"
        }
    }#end process block
    end {
        Write-Debug "This is the end of Add-MFAGroup"
    }
    
}#end function
#--------------------------

function Reset-UserPassword {
    <#
    .SYNOPSIS
     Changes the user's password to something long and unknown
    .DESCRIPTION
     Run the Set-AzureADUserPassword with a random password on the given user
    .PARAMETER UserName
     Same as ObjctId for Get-AzureADUser, can take a UPN or a GUID
    .EXAMPLE
     Reset-UserPassword -UserName "steve.rogers@$myDomainSuffix"
    .EXAMPLE
     Reset-UserPassword "steve.rogers@$myDomainSuffix" -Confirm
    .NOTES
     Auth: Roger P Seekell
     Date: 11/2018, 12/2018, 02/2019, 08/2020
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $UserName
    )
    begin {
        Write-Debug "This is the start of Reset-UserPassword"
        assert-AzureADConnection
    }
    process {
        $newPassword = ([System.Web.Security.Membership]::GeneratePassword(16,2))
        $newPassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
        if ($PSCmdlet.ShouldProcess($UserName)) {
            Set-AzureADUserPassword -ObjectId $UserName -Password $newPassword -ForceChangePasswordNextLogin $true
            if ($?) {
                Write-Verbose "Password change for $UserName was successful"
            }
            else {
                Write-Error "Could not change password for $UserName"
            }
        }
    }#end process block
    end {
        Write-Debug "This is the end of Reset-UserPassword"
    }
}#end function
#--------------------------

function Revoke-UserToken {
    <#
    .SYNOPSIS
    Ends all sessions of the given user account
    .DESCRIPTION
    Runs Revoke-AzureADUserALlRefreshToken on the given username
    .PARAMETER UserName
     Same as ObjctId for Get-AzureADUser, can take a UPN or a GUID
    .EXAMPLE
    Revoke-UserToken -UserName 'steve.rogers@$myDomainSuffix' -Verbose
    .NOTES
    Auth: Roger P Seekell
    Date: 08/20/2020 (and sometime before that)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $UserName
    )
    begin {
        Write-Debug "This is the start of Revoke-Token"
        assert-AzureADConnection
    }    
    process {
        if ($PSCmdlet.ShouldProcess($UserName)) {
            Revoke-AzureADUserAllRefreshToken -ObjectId $UserName
            if ($?) {
                Write-Verbose "All sessions of $UserName have been revoked."
            }
            else {
                Write-Error "Could not revoke user sessions for $UserName"
            }
        }
    }#end process block    
    end {
        Write-Debug "This is the end of Revoke-Token"
    }
}#end function
#--------------------------

function Repair-O365Account {
<#
.SYNOPSIS
 Perform remediation tasks on an Office 365 user
.DESCRIPTION
 Given a username, a UPN, runs all the remediation functions in this module
 It will "confirm" to begin and do the less-invasive ones first:
    Looking for bad mailbox rules, enable/extend auditing, check for forwarding and delegates
 It will "confirm" again before doing the most impactful three: 
    Change password, enable MFA, end all sessions
 Verbose is recommended, as it will tell you what each one finds
 Verbose + WhatIf is like a scan so you know the state without taking any actions
.PARAMETER UserName
 Same as ObjctId for Get-AzureADUser, can take a UPN or a GUID    
.PARAMETER All
 Use this to run all remediation steps; without it, no functions will run
.EXAMPLE
 Repair-O365Account -UserName steve.rogers@$myDomainSuffix -All -WhatIf -Verbose
 Will run all the tests, showing what it found and would do, without changing any settings or impacting the user
.EXAMPLE
 Repair-O365Account -UserName steve.rogers@$myDomainSuffix -All
 Will run all remediation functions but give the opportunity to skip the last few that are most impactful
.EXAMPLE
 Get-Mailbox -Identity ga_* | ForEach-Object {Repair-O365Account -UserName $_.primarysmtpaddress -All -Verbose -WhatIf}
 Shows how to pipe a Get-Mailbox query into this cmdlet (hint: use PrimarySmtpAddress)
.NOTES
Auth: Roger P Seekell
Date: 8/21/2020
Inspired by https://github.com/OfficeDev/O365-InvestigationTooling/blob/master/RemediateBreachedAccount.ps1 on 11-5-18
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory,ValueFromPipeline)]
    [string]
    $UserName,
    [switch]$All
)
begin {
    Write-Debug "This is the start of Repair-O365Account"
    #assert-AzureADConnection
    #assert-ExchangeOnlineConnection    
}
process {
    #not pleased with the implementation of "All", yet not sure if/how I want to carve up these actions
    if ($all) {
        if ($PSCmdlet.ShouldContinue($UserName,"Are you ready to run remediation tasks on this user?")) {
            Disable-ForwardingRules -Identity $UserName
            Enable-MailboxAuditing -Identity $UserName
            Remove-InvalidInboxRule -Identity $UserName
            Remove-MailboxDelegates -Identity $UserName
            Remove-MailboxForwarding -Identity $UserName
            if ($PSCmdlet.ShouldContinue("Are you sure you want to continue?","These last three actions will directly impact the user: add MFA, reset password, revoke token")) {
                Add-MfaGroup -UserName $UserName
                Reset-UserPassword -UserName $UserName
                Revoke-UserToken -UserName $UserName
            }
        }
    }
}#end process block
end {
    Write-Debug "This is the end of Repair-O365Account"
}
}#end function
#--------------------------

function add-SharedMailboxUser {
    <#
    .SYNOPSIS
    Give a user full control and send-as on a mailbox
    .DESCRIPTION
    Given a (shared) mailbox and a user, gives that user full control and send-as on that mailbox
    .PARAMETER SharedMailboxId
    The mailbox to affect, identified by a mailbox ID, SMTP address, etc. whatever works for Identity of Get-Mailbox
    .PARAMETER UserSmtpAddress
    The user to grant permission to, identified by a mailbox ID, SMTP address, etc. whatever works for Identity of Get-Mailbox
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $SharedMailboxId,
        # Parameter help description
        [Parameter(Mandatory)]
        [string]
        $userSmtpAddress
    )

    assert-ExchangeOnlineConnection

    Add-MailboxPermission -Identity $SharedMailboxId -AccessRights full -InheritanceType all -AutoMapping:$true -User $userSmtpAddress
    Add-RecipientPermission -Identity $SharedMailboxId -AccessRights sendas -Trustee $userSmtpAddress -Confirm:$false

}#end function
#--------------------------
function new-DistList {
<#
.SYNOPSIS
Creates a distribution (not mail-enabled security) group with the given name, email, and text file of email addresses
#>
Param (
#below is the name of the group, the displayname
$newName = "Roger Test Mail Group",
#below is the email address for the new group
$emailAddress = "rTestMailGroup@$myDomainSuffix",
#below is the path to a text file with one email address per line
$textPath = "C:\users\johndoe\rtestGroupUsers.txt"
)

assert-ExchangeOnlineConnection

if ($null -eq (Get-DistributionGroup -Identity $newName)) {
    #create the group first here
    New-DistributionGroup -Name $newName -Type distribution -PrimarySmtpAddress $emailAddress #-WhatIf

    if (Get-DistributionGroup -Identity $newName) { #if we can find the new group
        #add members here
        Get-Content $textPath | ForEach-Object {
            try {
                if ($_ -notlike "*$myDomainSuffix") {
                    $frontEmail = $_.substring(0,$_.indexof('@'))
                    $addEmail = "$frontEmail@$myDomainSuffix"
                }
                else {
                    $addEmail = $_
                }
                Add-DistributionGroupMember -Identity $newName -Member $addEmail -ErrorAction stop
            }
            catch {
                if ($_.tostring() -notlike "*is already a member of the group*") {
                    Write-Error $_
                }
                else {
                    Write-Error $_.ToString()
                }        
            }

        } #end foreach
    }
    else {
        Write-Error "Something went wrong creating the DG $newName"
    }
}
else {
    Write-Error "Cannot create the DG $newName, as it already exists"
}

}#end function
#--------------------------
function Copy-AntiPhishPolicy {
    <#
    .SYNOPSIS
     Makes a clone of an existing anti-phishing rule/policy
    .DESCRIPTION
     Given an "antiPhishRule" and the new name, makes a copy of that rule and policy.
     What we think of as a policy is actually two objects, a policy and a rule.
     The rule has the name of the policy, the priority, and where it is applied (this is all behind-the scenes in the GUI).
     We colloquially call it a policy, and so I have named this function, but it copies both rule and policy.
     Every parameter of both is copied except for the name and comments, and...
     The new rule will be disabled, but the policy will copy the enabled-state of the source.
     (This is because disabling in the GUI disables the Rule object but not the Policy object.)
     The priority of the new rule will automatically be the lowest (which is the highest number).
    .PARAMETER SourceRule
     The output of Get-AntiPhishRule (see example)
    .PARAMETER NewRuleName
     A string of what you want to call the new rule and policy
    .EXAMPLE
     Copy-AntiPhishPolicy -sourceRule (Get-AntiPhishRule -Identity "Principal Impersonation Policy (High)") -newRuleName "Clone-Principal-Impersonation-Policy-(High)"
    .EXAMPLE
    assert-ExchangeOnlineConnection #make sure we have a connection to Exchange Online
    $newPolicyName = "Principal Impersonation Policy (test copy)"
    $source = Get-AntiPhishRule -Identity "Principal Impersonation Policy (High)"
    if ($source) {
        Copy-AntiPhishPolicy -sourceRule $source -newRuleName $newPolicyName -Confirm
    }
    .NOTES
     Auth: Roger P Seekell
     Date: 8/24/2020
    #>
[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory, ValueFromPipeline)][psobject]$sourceRule,
    [Parameter()][string]$newRuleName
)
begin {
    Write-Debug "This is the beginning of Copy-AntiPhishPolicy"
    assert-ExchangeOnlineConnection #make sure we have a connection to Exchange Online
}

process {
    if ($sourceRule.DistinguishedName -like "*CN=AntiPhishVersioned,CN=Rules,CN=Transport Settings*")
    {        
        $sourcePolicy = Get-AntiPhishPolicy -Identity $sourceRule.AntiPhishPolicy
        $newPolicyName = $newRuleName
        if ($sourcePolicy) {
            if ($PSCmdlet.ShouldProcess($sourceRule.Name, "Clone anti-phishing policy with new name $newRuleName")) {

                $newPolicy = New-AntiPhishPolicy -Enabled $sourcePolicy.Enabled -name $newPolicyName `
                    -adminDisplayName ("Clone: " + $sourcePolicy.AdminDisplayName) `
                    -AuthenticationFailAction $sourcePolicy.AuthenticationFailAction `
                    -EnableMailboxIntelligence $sourcePolicy.EnableMailboxIntelligence `
                    -EnableMailboxIntelligenceProtection $sourcePolicy.EnableMailboxIntelligenceProtection `
                    -EnableOrganizationDomainsProtection $sourcePolicy.EnableOrganizationDomainsProtection `
                    -EnableSimilarDomainsSafetyTips $sourcePolicy.EnableSimilarDomainsSafetyTips `
                    -EnableSimilarUsersSafetyTips $sourcePolicy.EnableSimilarUsersSafetyTips `
                    -EnableTargetedDomainsProtection $sourcePolicy.EnableTargetedDomainsProtection `
                    -EnableTargetedUserProtection $sourcePolicy.EnableTargetedUserProtection `
                    -EnableUnauthenticatedSender $sourcePolicy.EnableUnauthenticatedSender `
                    -EnableUnusualCharactersSafetyTips $sourcePolicy.EnableUnusualCharactersSafetyTips `
                    -ExcludedDomains $sourcePolicy.ExcludedDomains `
                    -ExcludedSenders $sourcePolicy.ExcludedSenders `
                    -ImpersonationProtectionState $sourcePolicy.ImpersonationProtectionState `
                    -MailboxIntelligenceProtectionAction $sourcePolicy.MailboxIntelligenceProtectionAction `
                    -MailboxIntelligenceProtectionActionRecipients $sourcePolicy.MailboxIntelligenceProtectionActionRecipients `
                    -PhishThresholdLevel $sourcePolicy.PhishThresholdLevel `
                    -TargetedDomainProtectionAction $sourcePolicy.TargetedDomainProtectionAction `
                    -targetedDomainActionRecipients $sourcePolicy.TargetedDomainActionRecipients `
                    -TargetedDomainsToProtect $sourcePolicy.TargetedDomainsToProtect `
                    -TargetedUserActionRecipients $sourcePolicy.TargetedUserActionRecipients `
                    -TargetedUserProtectionAction $sourcePolicy.TargetedUserProtectionAction `
                    -TargetedUsersToProtect $sourcePolicy.TargetedUsersToProtect #-Confirm
                    #-EnableAntiSpoofEnforcement $sourcePolicy.EnableAntiSpoofEnforcement `
                    
                if ($newPolicy) {
                    Write-Debug "New Policy clone successful, now to clone the rule that contains the policy"
                    $newRule = New-AntiPhishRule -Name $newRuleName -Enabled $false -AntiPhishPolicy $newPolicy.Id `
                        -SentTo $sourceRule.SentTo -SentToMemberOf $sourceRule.SentToMemberOf `
                        -ExceptIfSentTo $sourceRule.ExceptIfSentTo -ExceptIfSentToMemberOf $sourceRule.ExceptIfSentToMemberOf `
                        -ExceptIfRecipientDomainIs $sourceRule.ExceptIfRecipientDomainIs -RecipientDomainIs $sourceRule.RecipientDomainIs `
                        -Comments "Auto-clone of $($sourceRule.Name) by Roger's PowerShell script on $(Get-Date)" #-Confirm 

                    $newRule #output
                }
                else {
                    Write-Error "Something went wrong copying the policy $($sourceRule.Name)"
                }
            }#end if should process
        }
        else {
            Write-Error "Could not find source policy for source rule"
        }
    }#end if the input object is correct
    else {
        throw "$sourceRule is not a valid Anti-phishing rule; please use Get-AntiPhishRule"
    }
}#end process block
end { 
    Write-Debug "This is the end of Copy-AntiPhishPolicy"
}
}#end function
#--------------------------
