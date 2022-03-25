<#
A set of general-purpose functions useful in a variety of contexts, sometimes called upon by other modules.
Roger P Seekell, ???, 10-1-15, 11-2-17, 10-30-18 (PowerShellAnalyzer)
#>
function get-ComputerNames {
<#
.SYNOPSIS
 Returns an array of "computer name" strings of the same series, such as "000-lab-nn".
.DESCRIPTION
 Given a prefix, start number, and end number, returns a list of computer names with the last number part running the range of the start and end numbers (inclusive). 
.NOTES
 Roger P Seekell, 2011, 2012, 2013
.PARAMETER Prefix
 Mandatory. A string representing the "series" of the computer names to return.  All of the computer names in the returned array will start with this.  e.g. "000-5500-" and leave off the last number. 
.PARAMETER StartNum
 A 0 or positive integer which specifies the lowest number in the computer-name "series" to return, such as 0 or 1.  The NoLeadingZero switch defines how to handle single-digit numbers in a two-digit slot.
 Default = 1
.PARAMETER EndNum
 A positive integer (-gt 0) which specifies the highest number in the computer-name "series" to return, such as 10 or 25. The NoLeadingZero switch defines how to handle single-digit numbers in a two-digit slot.
.PARAMETER NoLeadingZero
 If specified, instead of returning 000-5500-01, it will return 000-5500-1.  So if it is not specified, it will add a leading zero to a single-digit number before appending it to the computer name string.
.PARAMETER Exclude
 The resulting list of computer names will not contain names ending in the numbers specified in this array.
.PARAMETER TestConnection
 If specified, filters out the resulting list of computer names to only those that can be pinged (it will take much longer).
.EXAMPLE
 get-ComputerNames 000-5500- 1 3
 Yields the strings "000-5500-01","000-5500-02","000-5500-03" 
.EXAMPLE
 get-ComputerNames 610-5800-150- 1 31 -TestConnection
 Yields only the strings between "610-5800-150-01" and "610-5800-150-31" that respond to ping.
.EXAMPLE
 get-ComputerNames 123-6494-321- 9 14 -Exclude 10,12
 Returns the computer name strings in the sequence, except for those ending in 10 and 12, like so:
 123-6494-321-09
 123-6494-321-11
 123-6494-321-13
 123-6494-321-14
.INPUTs
 Does not take pipeline input.
.OUTPUTS
 A list/array of strings.
.NOTES
 Can do one or no leading zeros.  There is no way to do 001 or 0001 without changing the -Prefix parameter.  
#>
Param(
    [parameter(Mandatory=$true)][string]$Prefix,
    [int]$StartNum = 1,
    [parameter(Mandatory=$true)][int]$EndNum,
    [switch]$NoLeadingZero,
    [int[]]$Exclude,
    [switch]$TestConnection
)
##other vars
$computerNames = @()
for ([int]$x = $StartNum;$x -le $endNum;$x++) {
    if ($Exclude -contains $x) {
        #then we won't do it; we'll do nothing
    }
    elseif (($x -lt 10)-and ($NoLeadingZero -eq $false)) {
        $computerNames += $Prefix + "0$x"
    }
    else {
        $computerNames += "$Prefix$x"
    }
}
if ($TestConnection) {
    $computerNames | ForEach-Object {
        if (Test-Connection $_ -Quiet -Count 2) {
            $_
        }
    }
}
else {
    $computerNames #return value
}
}#end function
#-------------------------------------
function Test-ADCredential {
<#
.SYNOPSIS 
 Checks whether a certain name and password are valid in a domain.
.DESCRIPTION
 Given a credential (a window asking for username and password), uses PrincipalContext object to validate credentials.
 Will automatically add current domain prefix if not given.
 Returns true or false for whether the credentials are valid, or a warning if a problem with the domain.
.PARAMETER Credential
 An object such as Get-Credential returns.  Can be simply a username, and would then prompt for a password.
.EXAMPLE
 Test-ADCredential johndoe
 Would ask for password for johndoe.  Would hopefully return true if I don't fat-finger the password!
.NOTES
 Copied from http://powershell.com/cs/blogs/tips/archive/2013/05/20/validating-active-directory-user-account-and-password.aspx on 5-21-13
 Help written by Roger P Seekell, 5-21-13
 3-9-21 Test for PS7 and update Credential to make problem-analyzer happy
#>
  param(
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential
  ) 
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $info = $Credential.GetNetworkCredential()
    if ($info.Domain -eq '') { #automatically add domain to credential
        $info.Domain = $env:USERDOMAIN 
    } 
    $TypeDomain = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    try
    {
        $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $TypeDomain,$info.Domain
        $pc.ValidateCredentials($info.UserName,$info.Password)
    }
    catch
    {
        Write-Warning "Unable to contact domain '$($info.Domain)'. Original error:$_"
    }
}#end function 
#---------------------------------------
function get-LocalGroupMember {
<#
.SYNOPSIS
 Remotely checks membership of a local group, assuming adequate permissions
.DESCRIPTION
 Given a computer name and group name, such as administrators, lists those accounts and basic info about them.
 Use -Indirect to show all users and groups nested within the local group. Recommended to pipe results to Format-Table.
.NOTES
 Adapted from http://powershell.com/cs/blogs/tips/archive/2013/12/20/getting-local-group-members.aspx by Roger P Seekell on 12-23-13
 Bug fixes 6-17-15
.PARAMETER ComputerName
 One or more computers to add the given user to the given local group. Default is the localhost (by name).
.PARAMETER Group
 Required. Name of a local group, such as Administrators or "Remote Desktop Users".
.PARAMETER Indirect
 If specified, will show the members of all nested groups in the specified local group (will output users and groups).
.EXAMPLE
 get-LocalGroupMember administrators
 The minimum to run this function.  Lists the members of the local administrators group on localhost computer.
.EXAMPLE
 "000-5500-08", "000-5500-12" | get-LocalGroupMember -Group "Remote Desktop Users"
 Command can take computer names via pipeline.  Group names with spaces must be in quotes. 
 RESULTS:
    Name         : Itinerant Teacher,
    ContextType  : Domain
    Type         : User
    Description  : Meant to view different schools' views of student folders.
    LastLogon    : 12/20/2013 3:25:49 PM
    ComputerName : 000-5500-08
.EXAMPLE
 get-QADComputer 000-5500 | get-LocalGroupMember -Group Administrators -Indirect | Format-Table -AutoSize
 A complex example.  First, this function can take input via pipeline from Get-QADComputer.
 Second, -Indirect will list the users in nested groups up to five levels deep, so that all users within this local group are listed.
 Finally, it is recommended to Format-Table -AutoSize for better viewing of the results, especially with -Indirect potentially returning a lot of results.
#>
Param (
    [parameter(Mandatory=$true)][string]$Group,
    [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)][Alias("cn")][string[]]$ComputerName = @($env:computername),
    [switch]$Indirect = $false
)
begin {
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement    
}
process {
#foreach ($comp in $ComputerName) {
$ComputerName | ForEach-Object {
    try {
        $comp = $_.replace("$","") #take off dollar sign, in case from AD object
        $machine = New-Object DirectoryServices.AccountManagement.PrincipalContext('Machine', $comp)
        $objGroup = [DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($machine, 'SAMAccountName', $Group) 
        
        if ($objGroup) { #make sure group exists
            #we now have the group object, so get the members
            if ($Indirect) {
                $members = @($objGroup.Members) #get all
                for ($x = 1;$x -lt 5; $x++) { #nest up to five levels (not sure how to nest to infinite levels)
                    $members += $objGroup.Members | Where-Object {$null -ne $_.Members} | Select-Object -ExpandProperty members #get the group members
                }
            }
            else {
                $members = $objGroup.Members
            }
            $members | Select-Object -Unique | Add-Member -MemberType NoteProperty -Name ComputerName -Value $comp -PassThru
                
            #close objects
            $objGroup.Dispose()
        }
        else {
            Write-Error "Group '$Group' does not exist on machine '$($machine.Name)'"
        }
        $machine.Dispose()
    }
    catch {
        Write-Warning "$_ On Computer $comp"
    }
} | Select-Object Name, ContextType, @{l="Type";e={$_.gettype().name.replace("Principal","")}}, Description, lastLogon, ComputerName 
}#end process

}#end function
#--------------------
function add-LocalGroupMember {
<#
.SYNOPSIS
 Remotely adds a user to a local group, assuming adequate permissions
.DESCRIPTION 
 Add users to a local group group remotely; firewall must [allow access to] remote pc 
.NOTEs
 You may be tempted to use net localgroup, but remember that it cannot do names longer than 20 characters, but this one can.
 Original: Enjoy! By Maxzor1908 *1/11/2012*
 Adapted by Roger P Seekell on 4-11-13, 7-3
 Allow multiple identity on 3-9-2021 (and test PS7)
.PARAMETER ComputerName
 One or more computers to add the given user to the given local group. Default is the localhost (by name).
.PARAMETER Identity
 A user in the $env:USERDOMAIN domain 
.PARAMETER Group
 Name of a local group, such as Administrators or "Remote Desktop Users".
.PARAMETER Domain
 Normally uses the logged-on-user's domain, but if necessary to use another, can enter it here (such as adding domain user while logged on as local administrator).
.EXAMPLE
 add-LocalGroupUser -ComputerName 000-5500-01 -Identity bob -Group "remote desktop users"
 Will add user DOMAIN\bob to the local group "Remote Desktop Users" on computer 000-5500-01
#>
Param (
    [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)][Alias("cn")][string[]]$ComputerName = @($env:computername),
    [parameter(Mandatory=$true)][string[]]$Identity = "",
    [parameter(Mandatory=$true)][string]$Group = "",
    [string]$Domain = $env:USERDOMAIN
)
<#
$group = Read-Host "Enter the group you want a user to add in"
$user = Read-Host "enter domain user id"
$pc = Read-Host "enter pc number"
#>

process {
$ComputerName | ForEach-Object {
    $comp = $_
    $Identity | ForEach-Object {
        $objUser = [ADSI]("WinNT://$Domain/$_")
        if ($objUser.name) { #test for existence
            $objGroup = [ADSI]("WinNT://$comp/$Group")
            if ($objGroup.name) { #test for existence
                $objGroup.PSBase.Invoke("Add",$objUser.PSBase.Path)
            }
            else {
                Write-Warning "Could not contact $comp or find group called $Group"
            }
        }
        else {
            Write-Warning "Could not find user $env:USERDOMAIN/$_"
        }
    }
}#end foreach
}#end process

}#end function
#--------------------
function remove-LocalGroupMember {
<#
.SYNOPSIS
 Remotely removes a user from a local group, assuming adequate permissions
.DESCRIPTION 
 Remove users from a local group group remotely; firewall must [allow access to] remote pc 
.NOTEs
 You may be tempted to use net localgroup, but remember that it cannot do names longer than 20 characters, but this one can.
 Original: Enjoy! By Maxzor1908 *1/11/2012*
 Adapted by Roger P Seekell on 4-22-13
 Allow multiple identity on 3-9-2021 (and test PS7)
.PARAMETER ComputerName
 One or more computers to remove the given user from the given local group. Default is the localhost (by name).
.PARAMETER Identity
 A user in the $env:USERDOMAIN domain, 
.PARAMETER Group
 Name of a local group, such as Administrators or "Remote Desktop Users".
.EXAMPLE
 remove-LocalGroupUser -ComputerName 000-5500-01 -Identity bob -Group "remote desktop users"
 Will remove user DOMAIN\bob from the local group "Remote Desktop Users" on computer 000-5500-01
#>
Param (
    [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)][Alias("cn")][string[]]$ComputerName = @($env:computername),
    [parameter(Mandatory=$true)][string[]]$Identity = "",
    [parameter(Mandatory=$true)][string]$Group = ""

)

process {
$ComputerName | ForEach-Object {
    $comp = $_
    $Identity | ForEach-Object {
        $objUser = [ADSI]("WinNT://$env:USERDOMAIN/$_")
        if ($objUser.name) { #test for existence
            $objGroup = [ADSI]("WinNT://$comp/$Group")
            if ($objGroup.name) { #test for existence
                $objGroup.PSBase.Invoke("Remove",$objUser.PSBase.Path)
                if ($?) {
                    Write-Verbose "Remove $_ from $Group on $comp success"
                }
            }
            else {
                Write-Warning "Could not contact $comp"
            }
        }
        else {
            Write-Warning "Could not find user $env:USERDOMAIN/$_"
        }
    }
}#end foreach
}#end process

}#end function
#--------------------
function Get-LastBootTime {
    <#
    .SYNOPSIS
        Gets the last boot-up time for the specified servers
    .DESCRIPTION
        Using CIM, connects to the remote computer(s) and returns a DateTime object representing the moment the server last started and the timespan between now and then.
        Able to resolve IP addresses to names.
    .NOTES
        Roger P Seekell, ??, 10-13-15 (switch to CIM), 2-5-21 (add credential param)
        3-9-21 Test for PS7 and update Credential to make problem-analyzer happy
    .PARAMETER ComputerName
        One or more computer name strings to check the last boot time.  Can be piped in directly or by property name.
        Default is localhost.
    .PARAMETER Credential
        If necessary, provide a credential with access to the remote computer - takes a PS Credential
    .INPUTS
        One or more [string] computer names for which to get their hardware specifications.
    .OUTPUTS
        Returns the computer name, the last boot datetime, and the timespan between now and then (string format = days.hours:minutes:seconds.ticks)
    .EXAMPLE
    Get-LastBootTime localhost
    ComputerName                           LastBootTime                          Uptime
    ------------                           ------------                          ------
    000-5500-12                        8/12/2014 7:29:06 AM                  6.05:16:14.1054092
    .EXAMPLE
    Get-LastBootTime remoteComputer -credential domain\remoteuser
    #>
    Param (
        [Parameter(Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
        [alias("CN")]
        [String[]]$ComputerName = @('localhost'),
        [ValidateNotNull()]
            [System.Management.Automation.PSCredential]
            [System.Management.Automation.Credential()]
            $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    Begin{
        #variables
        #$dcom = New-CimSessionOption -Protocol Dcom
    }
    process {
        foreach ($comp in $ComputerName) {
            if ($comp -like "*$") {#if it ends in a dollar sign
                $comp = $comp.substring(0,$comp.length-1) #strip off the last character
            }
            
            #connect via CIM using DCOM (for backwards compatibility)
            $splat = @{ComputerName = $comp}
            if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
                $splat += @{credential=$Credential}
            }
            $sess = New-CimSession @splat -ErrorAction SilentlyContinue
            if ($sess) {
                Get-CimInstance win32_operatingsystem -CimSession $sess | 
                    Select-Object @{l="ComputerName";e={$_.csname}}, LastBootUpTime, @{l="Uptime";e={(Get-Date).Subtract($_.lastbootuptime)}}
            }
            else {
                Write-Error "Could not access $comp due to $($error[0])"
            }
        }
    }#end process
}#end function  
#-------------------------------
function get-ComputerSpecs {
<#
.SYNOPSIS
 Returns OS, RAM, and hard drive specs for one or more computers.
.DESCRIPTION
 This script/function gets specifications about a PC, including OS, RAM, CPU, and hard drive(s), using WMI queries.
.NOTES
 Roger P Seekell, 8-7-12, 12-27, 1-16-14
 Update to CimInstance on 3-9-21 (for PS7)
.PARAMETER ComputerName
 One or more computer name strings to check their specifications.  Can be piped in directly or by property name.
 Default is localhost.
.EXAMPLE
 get-ComputerSpecs
 Returns all the information about the localhost listed in Outputs
.EXAMPLE
 get-ComputerSpecs -Cn VM1, VM2 | format-table * -autosize
 Returns all the information about both remote computers.  It is recommended to format-table with -autosize for better readability.
.INPUTS
 One or more [string] computer names for which to get their hardware specifications.
.OUTPUTS
 Model, 
 Serial number,
 CPU model,
 CPU speed in MHz,
 CPU physical count, 
 logical CPU count, 
 RAM in use, 
 total RAM, 
 primary HD used space, 
 primary HD total space, 
 all other drives used space (null if only one drive), 
 all other drives total space (null if only one drive),
 Machine Name,
 Operating System,
 Service Pack,
 Architecture (32 or 64)
#>
Param(
    [Parameter(Position=0,                          
               ValueFromPipeline=$true,            
               ValueFromPipelineByPropertyName=$true)]            
    [alias("CN")]
    [String[]]$ComputerName = @('localhost')
)

begin{
##variables
$cores = 1 #there has to be one!
$usedRAM = 0 
$totalRAM = 0
$model = "" #string make and model
$used1 = 0 #used1 is first disk
$total1 = 0 #total1 is first disk
}

process{

foreach ($comp in $ComputerName) {
    $CSData = $null #clear every time
    Write-Verbose $comp
    if ($null -ne $comp) {
        #make/model data
        $CSData = Get-CimInstance win32_computerSystem -ComputerName $comp -ErrorAction SilentlyContinue
        if ($CSData) { #if one can reach a basic WMI class, indicating connectivity and proper remote settings
            $model = $CSData.manufacturer.replace("Dell Inc.","Dell").replace("Microsoft Corporation","MS").replace(" Computer Corporation","").replace("Hewlett-Packard","HP")
            $model += " " + $CSData.model.replace("PowerEdge","PE").replace("Virtual Machine", "VM").replace("PC","").replace("Small Form Factor","SFF")
            $model = $model.replace("HP HP","HP").Replace("VMware, Inc. VMware","VMware")
            if ($CSData.NumberOfLogicalProcessors) { #this property not always available
                $cores = $CSData.NumberOfLogicalProcessors
            }
            elseif ($CSData.NumberOfProcessors) { #even this property not always available
                $cores = $CSData.NumberOfProcessors
            }
            #else $cores = 1 (default value)

            #BIOS data
            $BIOSData = Get-CimInstance win32_bios -ComputerName $comp
            $serial = $BIOSData.SerialNumber

            #CPU data
            $CPUData = @(Get-CimInstance win32_processor -ComputerName $comp) #could return multiple objects, one per proc
            $CPUCount = $CPUData.count
            #assuming identical processors...
            $indexofSpeed = $CPUData[0].name.indexof("@")
            #in case doesn't include @ sign for speed
            if ($indexofSpeed -lt 0) {
                $indexofSpeed = $CPUData[0].name.length
            }
            $CPUModel = $CPUData[0].name.substring(0,$indexofSpeed).replace("(R)","").replace("(TM)","").replace("         ","").replace("processor","").replace("CPU","").replace("  "," ").trim() #there are extra spaces all over this bad boy
            $CPUSpeed = $CPUData[0].MaxClockSpeed
        
            #memory data
            $OSData = Get-CimInstance win32_operatingSystem -ComputerName $comp #-Property totalVisibleMemorySize, freePhysicalMemory, caption, ServicePackMajorVersion, osarchitecture
            $usedRAM = ("{0:N2}" -f (($OSData.totalVisibleMemorySize - $OSData.freePhysicalMemory) / 1MB))
            $totalRAM = ("{0:N2}" -f ($OSData.totalVisibleMemorySize / 1MB))
            $OS = $OSData.caption.replace("®","").replace("(R)","").replace("Microsoft ","").replace("Windows","W").replace(", Enterprise Edition"," Ent").replace("Enterprise","Ent").replace(" Edition","").replace("Advanced","Adv").replace("Standard","Std") #.replace("Microsoftr ","").replace("Serverr","Server")
            $SP = "SP$($OSData.ServicePackMajorVersion)"
            $architecture = $OSData.osarchitecture
            if ($null -eq $architecture) { #XP/2000/2003 don't record this, and 16-bit wouldn't have WMI (if they still exist)
                if ($OSData.caption -like "*x64 edition*" -and $CPUData.addressWidth -eq 64) { 
                    $architecture = "64-bit" #have to take their word for it
                }
                else {
                    $architecture = "32-bit"
                }
            }

            #hard drive data
            $logDisks = Get-CimInstance win32_logicalDisk -ComputerName $comp | Where-Object {$_.driveType -eq 3} | Sort-Object deviceID #get fixed disks
            $first = $true #is only true the first iteration of the loop; used to combine results from multiple disks
            $usedM = 0 #usedM is sum of all other disks
            $totalM = 0 #totalM is sum of all other disks
            foreach ($logDisk in $logDisks) {
                if ($first) { #show first disk seperately from others
                    $used1 = "{0:N2}" -f (($logDisk.Size - $logDisk.FreeSpace) / 1GB) 
                    $total1 = "{0:N2}" -f ($logDisk.Size / 1GB) 
                }
                else {
                    $usedM += (($logDisk.Size - $logDisk.FreeSpace) / 1GB) 
                    $totalM += ($logDisk.Size / 1GB) 
                }            
                $first = $false 
            }
            if ($usedM -ne 0) {
                $usedM = "{0:N2}" -f $usedM
                $totalM = "{0:N2}" -f $totalM
            }
            else { #null because only one disk
                $usedM = $null
                $totalM = $null
            }
        
            #final object
            $serverInfo = New-Object System.Object | Select-Object -Property @{label="Model";expression={$model}}, `
                @{label="SerialNumber";expression={$serial}}, `
                @{label="CPUModel";expression={$CPUModel}}, `
                @{label="CPUMHz";expression={$CPUSpeed}}, `
                @{label="CPUCount";expression={$CPUCount}}, `
                @{label="CPULogical";expression={$cores}}, `
                @{label="RAMUsed";expression={$usedRAM}}, `
                @{label="RAMTotal";expression={$totalRAM}}, `
                @{label="HDUsed";expression={$used1}}, `
                @{label="HDTotal";expression={$total1}}, `
                @{label="HD+Used";expression={$usedM}}, `
                @{label="HD+Total";expression={$totalM}}, `
                @{label="MachineName";expression={$CSData.name}}, `
                @{label="OS";expression={$OS}}, `
                @{label="SP";expression={$SP}}, `
                @{label="Architecture";expression={$architecture}}
            
             
            $serverInfo #output
            Write-Debug "Did you get that?"
        }
        else {
            Write-Warning "Could not access $comp WMI class."
        }
    }#end if $comp
    else {
        Write-Debug "No computer object"
    }
}
}#end process
end {
    #can't think of anything
}
}#end function
#---------------------------------------
function convertTo-ByteString {
<#
.SYNOPSIS
 Converts an integer into a "byte string", like 1GB
.DESCRIPTION
 Given an integer value, divides by 1024 until the number is between 0 and 1024, then attaches the appropriate byte measurement.  Using Invoke-Expression will convert back to a number. 
 Returns a string with a number and byte measurement abbreviation, the kind that PowerShell resolves.  See examples.
 The largest possible Value is 9223372036854775807 (according to [int64]::maxvalue). In simple terms, most 19-digit numbers and smaller will work.
.NOTES
 Roger P Seekell, c. 7-9-2012
 Made value mandatory (seems self-explanatory) on 3-9-21
.PARAMETER Value
 Mandatory: The number to convert to a byte string.  It is an Int64, so should handle any size number that can be made into a byte string.
.PARAMETER Round
 How many decimal places to round in the final answer. Can be from 0- [int]::maxvalue, but 20 is a more logical max since [int64] only holds 19 digits.
.EXAMPLE
 convertTo-ByteString -Value 1024 -Round 1
 DESCRIPTION: Returns the string "1.0KB" since 1024 bytes is 1KB, and 1 means rounded to one decimal place
.EXAMPLE
 Invoke-Expression (convertTo-ByteString -Value 1048576)
 DESCRIPTION: Returns 1048576, because convertTo-ByteString 1048576 returns "1.000MB", and Invoke-Expression on that string returns the value of 1MB, which is 1048576.
.EXAMPLE
 convertTo-ByteString -Value (1PB/15TB) -Round 2
 DESCRIPTION: Returns 68.00, because 1PB / 15TB = 68.26666667, but Value is an Int, so its fractional component is truncated.  
#>
Param (
    [Parameter(Mandatory)][int64]$Value,
    [int]$Round = 3
)
[double]$newValue = $Value #will store the final number (decimal between 0 and 1024)
$loopCount = 0 #this number will determine the byte measurement
$suffix = "" #will be the byte measurement suffix
if ($Value -lt 0) {
    Write-Error "Cannot convert negative numbers."
}
else {
    while ($newValue -gt 1000) {
        $loopCount++
        $newValue = $newValue / 1024
        if ($loopCount -eq 5) {
            break #exit the loop, as this is the maximum value
        }
    }
    switch($loopCount) {
        1{$suffix = "KB"}
        2{$suffix = "MB"}
        3{$suffix = "GB"}
        4{$suffix = "TB"}
        5{$suffix = "PB"}
    }#end switch
    ("{0:n$Round}$suffix" -f $newValue).replace(",","")
}#end else
}#end function 
#---------------------------------------
function measure-Path {
<#
.SYNOPSIS
 Finds the total size of the given file or folder
.DESCRIPTION
 Like the File or Folder Properties window, gets the total size of the item and all subitems.  Works on UNC paths also.
 Returns an object with the path (input) and total size.
 Unlike some other cmdlets, this function takes SharePath (as from get-ServerShare) through the pipeline, as well as Path.
.NOTES
 Roger P Seekell, 6-1-12, 6-17-14, 6-19-15 (bug fix)
.PARAMETER Path
 The full path of the folder to get the total size. Also called SharePath and FullName (for piping).
.PARAMETER UnitSize
 What unit to use to present the size.  Default is GB. Accepts any value that PowerShell knows: kb, mb, gb, etc.  An invalid value will cause an ArgumentException.
.EXAMPLE
measure-Path -SharePath \\file1\c$\share

Path                                                  Count                     TotalSize TotalSizeGB
----                                                  -----                     --------- -----------
\\file1\c$\share                                   21390                   13400194864 12.48
.EXAMPLE
gci p:\scripts -Directory | measure-Path -UnitSize kb

Path                                              Count                         TotalSize TotalSizeKB                                     
----                                              -----                         --------- -----------                                     
P:\scripts\ActiveDirectory                           46                            100311 97.96                                           
P:\scripts\Clusters                                   4                              9008 8.80                                            
P:\scripts\Computers                                 68                            415610 405.87                                          
P:\scripts\GroupPolicy                                8                             26582 25.96                                           
.EXAMPLE
measure-Path -UnitSize kb -Path (gci p:\scripts -Directory | select -ExpandProperty fullname)
(alternate of previous example, same results)
.OUTPUTS
 An object with the path (fullname), count of items in that folder, the total size in bytes, and the total size in the specified measurement (default is GB).
#>
Param(
    [parameter(ValueFromPipelineByPropertyName=$true)][alias("SharePath","Fullname")][string[]]$Path = @(),
    [string]$UnitSize = "GB"
)
begin{
    $allowedUnitSizes = "KB", "MB", "GB", "TB", "PB"
    #test parameter
    if ($allowedUnitSizes -notcontains $UnitSize) {
        throw New-Object System.ArgumentException "Invalid UnitSize.  Must be one of these: $allowedUnitSizes"
    }
    $UnitSize = $UnitSize.ToUpper()
}
process{
    $path | ForEach-Object {    
        $currentPath = $_
        $measure = Get-ChildItem $_ -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property length -Sum -ErrorAction SilentlyContinue
        if ($measure) {
            New-Object PSObject | Select-Object @{l="Path";e={$currentPath}}, 
                    @{l="Count";e={$measure.Count}}, 
                    @{l="TotalSize";e={$measure.sum}}, 
                    @{l="TotalSize$UnitSize";e={"{0:N2}" -f ($measure.sum / (Invoke-Expression "1$UnitSize"))}}
        }
        else {
            Write-Debug "No files"
            New-Object PSObject | Select-Object @{l="Path";e={$currentPath}}, 
                    @{l="Count";e={0}}, 
                    @{l="TotalSize";e={0}}, 
                    @{l="TotalSize$UnitSize";e={"0.00"}}
        }
    }#end foreach
}#end process
}#end function
#---------------------------------------
function Search-Script {
<#
.SYNOPSIS
 Searches PS1 files for a word or phrase
.DESCRIPTION
 Given a search phrase and location, will look in the code for the search string, then display matches in a grid view.  Any items selected will be opened in PowerShell ISE.
.NOTES
 Taken from http://powershell.com/cs/blogs/tips/archive/2015/08/20/quickly-finding-scripts.aspx
 Roger P Seekell, 8-20-15, 6-26-17
.PARAMETER SearchPhrase
 Required, what search string to look for in the PowerShell files
.PARAMETER Path
 In what folder to search (limit one). Default is My Documents
.PARAMETER IncludeAllPSFiles
 If specified, will include PowerShell modules (psm1) and manifests (psd1); default is just PowerShell script (PS1) files.  
.EXAMPLE
 Search-Script 'childitem' 
.EXAMPLE
 search-script -SearchPhrase "credential" -Path 'C:\Documents\WindowsPowerShell\'
#>
  param 
  (
    [Parameter(Mandatory = $true)]$SearchPhrase, 
    $Path = [Environment]::GetFolderPath('MyDocuments'),
    [switch]$IncludeAllPSFiles = $false
  )
 $psfilter = "*.ps1"
 if ($IncludeAllPSFiles) {
    $psfilter = "*.ps*1"
 }
    Get-ChildItem -Path $Path  -Filter $psfilter -Recurse -ErrorAction SilentlyContinue | 
        Select-String -Pattern $SearchPhrase -List | 
        Select-Object -Property Path, Line, @{l="dateModified";e={(Get-Item $_.path).LastWriteTime}} | 
        Out-GridView -Title "Choose a Script containing $SearchPhrase to open in ISE" -PassThru | 
        ForEach-Object -Process {
            powershell_ise.exe $_.Path
        }
}#end function
#---------------------------------------

function Get-NewestFile {
<#
.SYNOPSIS
 Returns the newest file(s) in a folder (including nested folders, not including hidden/system)
.DESCRIPTION
 Given a path, goes recursively and finds all the files, sorts by date, and returns the newest one(s), based on the Count parameter
.NOTES
 Created in 2020 by Roger P Seekell
.PARAMETER Path
 The folder full path that you want to scan; default is the current location
.PARAMETER Count
 The number of newest files to return; default is 1
.EXAMPLE
 Get-NewestFile \\itfs\it\Infrastructure\
#>
    param (
        $path = (Get-Location),
        [int]$count = 1
    )
    Get-ChildItem -Path $path -Recurse -File | Where-Object LastWriteTime -lt (Get-Date) | Sort-Object LastWriteTime -Descending | Select-Object -First $count
}#end function
#--------------------------

function Get-FolderStats {
<#
.SYNOPSIS
 Gets info about a folder like total size and newest file
.DESCRIPTION
 Given a path, goes recursively and finds all the files, grabs the newest file, and totals the size taken by all files
.OUTPUTS
 An object with the folder name, its full path, the total size in bytes and the easist unit (convertTo-ByteString), and the newest file and its date
.NOTES
 Created in 2020 by Roger P Seekell
.PARAMETER Path
 The folder full path that you want to scan; default is the current location
.EXAMPLE
 Get-FolderStats \\itfs\it\Infrastructure\
#>
    Param (
        $path = (Get-Location)
    )
    $files = Get-ChildItem -Path $path -Recurse -File
    $size = $files | Measure-Object -Property Length -Sum
    $newest = $files | Where-Object LastWriteTime -lt (Get-Date) | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $byteString = convertTo-ByteString -Value $size.Sum

    #return value
    Get-Item $path | 
        Add-Member -MemberType NoteProperty -Name TotalFiles -Value $files.count -PassThru | 
        Add-Member -MemberType NoteProperty -Name TotalBytes -Value $size.Sum -PassThru | 
        Add-Member -MemberType NoteProperty -Name TotalSize -Value $byteString -PassThru | 
        Add-Member -MemberType NoteProperty -Name NewestFile -Value $newest -PassThru |
        Add-Member -MemberType NoteProperty -Name NewestFileDate -Value $newest.LastWriteTime -PassThru |
        Select-Object -Property name, fullname, TotalFiles, TotalBytes, TotalSize, NewestFile, NewestFileDate
}#end function
#--------------------------

function Get-FolderStatsBulk {
<#
.SYNOPSIS
 Runs Get-FolderStats on multiple items
.DESCRIPTION
 Given one or more paths and an output folder, runs Get-FolderStats on each one and saves each result to a CSV file in the given folder
.PARAMETER Shares
 One or more paths/folders to scan
.PARAMETER OutputFolder
 The folder in which to save all the CSV files 
.EXAMPLE
 Get-FolderStatsBulk -shares \\itfs\it\Infrastructure, \\itfs\it\VDI -outputFolder "C:\users\johndoe\OneDrive\Reports"
 Creates two CSV files in the Reports folder called itfs-it-VDI_2021-03-10.csv and 
 itfs-it-Infrastructure_2021-03-10, in which are rows for each subfolder with the total size and
 newest file (see Get-FolderStats)
#>
Param (
    $shares, #= "\\itfs\IT",
    $outputFolder # = "C:\users\johndoe\OneDrive\Reports"
)
$today = Get-Date -Format "yyyy-MM-dd"

foreach ($share in $shares) {
    $outputFile = $share.substring(2).replace('\','-')
    $outputFile = "$outputFolder\$outputFile`_$today.csv"
    Get-ChildItem $share -Directory | 
        ForEach-Object {Get-FolderStats -path $_.fullname} | 
        Export-Csv -NoTypeInformation -Path $outputFile
}
}#end function
#--------------------------

function start-ProgressCountdown {
<#
.SYNOPSIS
 Shows the progress of a second-based countdown
.DESCRIPTION
 Given a number of seconds, shows a progress bar counting down each second and increasing completion to the end of the countdown.
.NOTES
 Roger P Seekell, 9-18-15 
.PARAMETER Seconds
 The number of seconds in the countdown
.PARAMETER Activity
 The string to display what you're counting down for
.EXAMPLE
 Start-ProgressCountdown 5
 Displays a countdown for five seconds; the progress bar increases by 20% every second.
.EXAMPLE
 Start-ProgressCountdown 8 "Self destruct sequence started"
 Displays a countdown for "Self destruct sequence started" lasting 8 seconds; the progress bar increases 12.5% every second
#>
Param($seconds, $activity = "Counting down")
#$activity = "Counting down"
for ($timer = $seconds;$timer -gt 0;$timer--) {
    Write-Progress -Activity $activity -SecondsRemaining $timer -PercentComplete (($seconds-$timer) * (100/$seconds))
    #where 100 means 100%
    Start-Sleep -Seconds 1
}
Write-Progress -Activity $activity -SecondsRemaining $timer -PercentComplete 100
Start-Sleep -Milliseconds 500 #time to show that it finished
Write-Progress -Activity $activity -Completed
}#end function
#----------------------
function Get-Temppassword {
    <#
    .SYNOPSIS
    Returns a random "password" derived from the given length and set of characters
    .DESCRIPTION
    From a given array of strings, returns a string of the given length comprised of random characters from that array.
    Taken from username anir at http://stackoverflow.com/questions/17195990/trying-to-generate-a-random-password
    Roger P Seekell, 8-22-13, 8-28
    .PARAMETER Length
    How many characters the password will have
    .PARAMETER SourceData
    An array/list of single characters to use in the random password. If not specified, uses upper- and lowercase letters
    and digits.
    .PARAMETER OutputPassword
    If specified, will write the password in verbose, just in case this function was used as a parameter.
    #>
    Param(
    [int]$length=10,
    [string[]]$sourcedata ,
    [switch]$OutputPassword
    )

    if (-not $sourcedata) {
        $sourcedata = (65..90 | ForEach-Object {[char]$_}) #uppercase letters
        $sourcedata += (97..122 | ForEach-Object {[char]$_}) #lowercase letters
        $sourcedata += 0..9 #digits
    }

    For ($loop=1; $loop -le $length; $loop++) {
        $TempPassword+=($sourcedata | Get-Random)
    }

    if ($OutputPassword) {
        #save and restore current verbose preference
        $pref = $VerbosePreference
        $VerbosePreference = 2
        Write-Verbose $TempPassword
        $VerbosePreference = $pref
    }
    return $TempPassword
}#end function 
#--------------------

function Get-QLoggedOnUser {
<#
.Synopsis
Queries a computer to check for interactive sessions with quser

.DESCRIPTION
This script takes the output from the quser program and parses this to PowerShell objects
Converted to function and changed datatype by Roger P Seekell, ?-2014

.NOTES   
Name: Get-LoggedOnUser
Author: Jaap Brasser
Version: 1.2
DateUpdated: 2015-07-07
Source: https://gallery.technet.microsoft.com/scriptcenter/Get-LoggedOnUser-Gathers-7cbe93ea

.LINK
http://www.jaapbrasser.com

.PARAMETER ComputerName
The string or array of string for which a query will be executed

.EXAMPLE
Get-LoggedOnUser -ComputerName server01,server02

Description:
Will display the session information on server01 and server02

.EXAMPLE
'server01','server02' | Get-LoggedOnUser

Description:
Will display the session information on server01 and server02
#>
param(
    [CmdletBinding()] 
    [Parameter(ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true)]
    [string[]]$ComputerName = 'localhost'
)
begin {
    $ErrorActionPreference = 'Stop'

    Function Convert-IdleTimeStringToTimeSpan {
    #added by kbgeoff on Oct. 15, 2013 in Q&A
    param(
        [CmdletBinding()]
        [Parameter(Mandatory=$true,ValueFromPipeline=$false)]
        [String]$IdleTime
    )
    
    Begin {
        $Days, $Hours, $Minutes = 0, 0, 0
    }

    Process {
        if ( $IdleTime -eq "none" ) {
            #do nothing; keep at zero
        }
        elseIf ( $IdleTime -ne '.' ) {
            If ( $IdleTime -like '*+*' ) {
                $Days, $IdleTime = $IdleTime.Split('+')
            }
        
            If ( $IdleTime -like '*:*' ) {
                $Hours, $Minutes = $IdleTime.Split(':')
            }
            Else {
                $Minutes = $IdleTime
            }
        }
    }
        
    End {
        New-Timespan -Days $Days -Hours $Hours -Minutes $Minutes
    }
    }#end internal function
    
}#end of beginning
    
process {
    foreach ($Computer in $ComputerName) {
        try {
            quser /server:$Computer 2>&1 | Select-Object -Skip 1 | ForEach-Object {
                $CurrentLine = $_.Trim() -Replace '\s+',' ' -Split '\s'
                $HashProps = @{
                    UserName = $CurrentLine[0]
                    ComputerName = $Computer
                }

                # If session is disconnected different fields will be selected
                if ($CurrentLine[2] -eq 'Disc') {
                        $HashProps.SessionName = $null
                        $HashProps.Id = $CurrentLine[1]
                        $HashProps.State = $CurrentLine[2]
                        $HashProps.IdleTime = Convert-IdleTimeStringToTimeSpan($CurrentLine[3])
                        $HashProps.LogonTime = $CurrentLine[4..6] -join ' '
                } else {
                        $HashProps.SessionName = $CurrentLine[1]
                        $HashProps.Id = $CurrentLine[2]
                        $HashProps.State = $CurrentLine[3]
                        $HashProps.IdleTime = Convert-IdleTimeStringToTimeSpan($CurrentLine[4])
                        $HashProps.LogonTime = $CurrentLine[5..7] -join ' '
                }

                New-Object -TypeName PSCustomObject -Property $HashProps |
                Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error
            }
        } #end try
        catch {
            if ($_.exception.message -like "No User exists for*") {
                Write-Verbose "No users logged onto $computer"
            }
            else {
                $error[0].ToString()
                Write-Error "Could not access '$Computer': $($_.Exception.Message)"
            }
        }#end catch
    }#end foreach
}#end of process

end {#not needed
}

}#end function
#-------------------------------

Register-ArgumentCompleter -CommandName get-LocalGroupMember, add-LocalGroupMember, remove-LocalGroupMember -ParameterName Group -ScriptBlock {
    Get-LocalGroup | ForEach-Object {"'" + $_.name + "'"}
}
