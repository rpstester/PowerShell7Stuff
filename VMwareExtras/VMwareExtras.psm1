<#
A collection of functions I've written and find useful for vSphere/vCenter
BetterCredentials makes everything better!
Roger P Seekell, 12-23-19, 1-17-20, 5-28-20, 11-5-20, 5-21-21
#>
#requires -module betterCredentials

#constants
$vcenterServer = "e275vcenter2.$env:userDNSDomain"
$reportPath = "C:\users\johndoe\OneDrive\Reports\vmware"
#variables

function connect-VCenterServer {
    $username = "$env:userDNSDomain\johndoe"
    try {
        $login = Get-Credential -username $username
        $null = Connect-VIServer -Server $vCenterServer -Credential $login -ErrorAction stop #hide output
    }
    catch {
        throw $_
    }
}#end function
#--------------------------

function get-VMList {
<#
.SYNOPSIS
 Saves a CSV file of all the VMs in vCenter with several properties (columns)
#>
Param (
    $pathToSave = "$reportPath\vmware-vms-PPPP.csv"
)
$date = (Get-Date -Format "yyyy-MM-dd")
$pathToSave = $pathToSave -replace "PPPP",$date #in case of default

Write-Warning "Saving file to $pathToSave"
connect-VCenterServer

Get-VM -Name * | 
    Select-Object name, powerstate, folder, notes, hardwareversion, numcpu, memorygb,
        @{l="IpAddress";e={$_.guest.ipaddress}},
        @{l="UsedSpaceGBR";e={"{0:n2}" -f $_.usedspacegb}},
        @{l="VmtoolsVersion";e={$_.guest.toolsversion}}, 
        @{l="VmtoolsStatus";e={$_.extensionData.Guest.ToolsVersionStatus}},
        @{l="VmtoolsUpdatePolicy";e={$_.extensionData.Config.Tools.ToolsUpgradePolicy}},
        @{l="GuestOSFamily";e={$_.guest.guestfamily}},
        @{l="OSFullName";e={$_.guest.osfullname}}, 
        @{l="Firmware";e={$_.extensionData.Config.Firmware}}, 
        @{l="SecureBoot";e={$_.extensionData.Config.BootOptions.EfiSecureBootEnabled}}, 
        @{l="esxiHost";e={$_.vmhost.name}}, 
        @{l="esxiHostCluster";e={$_.vmhost.parent.name}}, 
        @{l="esxiHostVersion";e={$_.vmhost.version}}, 
        @{l="datastoreName";e={($_.DatastoreIdList | ForEach-Object {Get-Datastore -Id $_}).name -join ";"}}, 
        @{l="SnapshotCount";e={(Get-Snapshot -VM $_).count}},
        @{l="Tags";e={(Get-TagAssignment -Entity $_).tag.name}} | 
    Export-Csv -NoTypeInformation -Path $pathToSave
}#end function
#--------------------------

function findRemoveSnapshot {
<#
.SYNOPSIS
 Returns a grid view of every snapshot in vCenter, then lets you select one or more and deletes them
#>
connect-VCenterServer

Get-VM | Get-Snapshot | Select-Object VM, ID, created, name, description, sizeGB | Out-GridView -OutputMode Multiple | ForEach-Object {
    Get-VM -Name $_.vm | Get-Snapshot -Id $_.id | Remove-Snapshot -RunAsync -Confirm:$false
    }#end foreach

}#end function
#--------------------------

<# doesn't work in PS7, for now
Doesn't load the "vmstores" PSDrive like in WinPoSh
function find-iso {
connect-VCenterServer

Get-Datastore | Where-Object {$_.State -eq 'Available'} | ForEach-Object {
    New-PSDrive -Location $_ -Name ds -PSProvider VimDatastore -Root '\' > $null
    Get-ChildItem -Path ds: -Recurse -Filter *.iso | Select-Object length, DatastoreFullPath
    Remove-PSDrive -Name ds -Confirm:$false
}#end foreach
}#end function
#--------------------------
#>

function getVMHostMetric {
<#
.SYNOPSIS
 goes through all vmhosts and reports the vCPU, memory usage and the count of VMs
.NOTES
 given to me by Donnie
.EXAMPLE
 getVMHostMetric | Sort-Object memory%used -Descending | Format-Table -auto
.EXAMPLE   
 $vmhosts = @(get-vmhost e275vwh1*)
 $vmhosts += get-vmhost e275vwh12*
 getVMHostMetric -vmhosts $vmhosts | Sort-Object vcpu%allocated -Descending | Format-Table -AutoSize    
#>
Param (
        $vmhosts = (Get-VMHost)
    )
    ForEach ($esxhost in $vmhosts) {  
        #count the VMs first, affects the CPU numbers
        [int]$countVM = ($esxhost | Get-VM).Count
        [int]$vCPU = 0
        if ($countVM -ne 0) { #if there are VMs, run the CPU calculations
            $vCPU = Get-VM -Location $esxhost | Where-Object { $_.PowerState -eq "PoweredOn"} | Measure-Object -Property NumCpu -Sum | Select-Object -ExpandProperty Sum      
        } #else it will remain 0
        $realCPU = (2 * $esxhost.NumCpu)
        
        Write-Debug "$esxhost - vmcount: $countVM; vCPU: $vCPU; RealCPU: $realCPU"  #sanity check    

        $cpuConsumed = ([Math]::Round((($esxhost.CpuUsageMhz)/($esxhost.CpuTotalMhz))*100)).ToString()
        $cpuCoresUsedRatio = [math]::Round((100*$vCPU / $realCPU))
        $CPUratio = "$vCPU/$realCPU Cores"#the string output
        
        #now work on the RAM numbers
        $totalRAM = [Math]::Round($esxhost.MemoryTotalGB)
        $currRAMusage = [Math]::Round($esxhost.MemoryUsageGB) 
        $RAMused = ([Math]::Round((($currRAMusage)/($totalRAM))*100)).ToString()
        $RAMratio = "$currRAMusage GB/$totalRAM GB" #the string output
    
        #final output:
        $esxhost | Select-Object Name,  
            @{N='VMs';E={[int]$countVM}}, 
            @{N='vCpuUsed';E={[int]$vCPU}},
            @{N='hostVCpu';E={$realCPU}},
            @{N='vCPUCoresUsed';E={$CPUratio}},
            @{N='vCPU%Allocated';E={[int]$cpuCoresUsedRatio}},
            @{N='vCPU%Used'; E={[int]$cpuConsumed}},
            @{N='currRamUsage'; E={[int]$currRAMusage}},
            @{N='totalHostRam';E={[int]$totalRAM}},
            @{N='MemoryUsage'; E={$RAMratio}},
            @{N='Memory%Used'; E={[int]$RAMused}}
                    
    }#end foreach
}#end function
#--------------------------
    
    
function selectAvailableHost {
<#
.SYNOPSIS
  Given a VM, its host, and a cluster, determines the best node to which to migrate it
.DESCRIPTION
  Find the connected hosts, get their available resources, and pick the one with the most available resources
  Returns a VMHost
.PARAMETER MyCluster
 The cluster object from "get-cluster" that you want to scan to find the most eligible host
.PARAMETER VM
 The Virtual Machine object (from Get-VM) that you want to place on the most elgible host
.PARAMETER VmHostExclude
 The vm host that you want to exclude from the selection (usually the current host of the given VM)
.EXAMPLE     
  $cluster5 = get-cluster -Name prod_cluster5
  $mpvm = get-vm 000-10x64-mp
  selectAvailableHost -myCluster $cluster5 -vm $mpvm -vmhostExclude $mpvm.vmhost
#>
    Param(
        [Parameter(Mandatory)]$myCluster, 
        [Parameter(Mandatory)]$vmhostExclude, 
        [Parameter(Mandatory)]$vm
    )
    ##get all the hosts in the cluster (repoll the cluster nodes)
    $clusterHosts = Get-VMHost -Location $myCluster
    #get available hosts (not the one to drain, not in maintenance mode or offline)
    $destHosts = $clusterHosts | Where-Object name -ne $vmhostExclude.Name | Where-Object ConnectionState -eq "Connected"
    #allocate RAM as the chief factor, give the VM to the host with most available RAM, but make sure CPU cores are available
    $hostperfs = getVMHostMetric -vmhosts $destHosts
    $prefHost = $hostperfs | Sort-Object memory%used, vcpu%allocated
    $chosenHost = $prefHost[0] #select the first one, which should be the most open
    
    #select the top result from metrics
    return Get-VMHost $chosenHost.name
}#end function
#--------------------------
   
function clear-VMHost {

#this function will drain a node in a cluster by vMotion-ing all VMs to another host
[cmdletbinding(supportsShouldProcess)]
Param(
    [string]$hostnameToDrain = "e275vwhm01",
    [int]$max_vMotion_Simul = 2,
    [switch]$remediate = $false
)
function getPendingJobCount {
    Param (
        [switch]$show
    )
    $count = ($myjob | ForEach-Object {Get-Task -id $_.id -ErrorAction SilentlyContinue} | Where-Object state -ne "success").count    
    if ($show) {
        $oldVerbose = $VerbosePreference
        $VerbosePreference = 2
        Write-Verbose "There are $count running jobs"
        $VerbosePreference = $oldVerbose
    }
    return $count
}
$staggerSeconds = 4
connect-VCenterServer

#assuming you connect to the VIserver

#find the chosen host
$hostToDrain = Get-VMHost -Name "$hostnameToDrain*"
if ($null -eq $hostToDrain) {
    #see if you can get any host
    $anyhost = Get-VMHost
    if ($null -eq $anyhost) {
        #if no hosts at all, try reconnect
        Connect-VIServer $vcenterServer
        #and try to find again
        $hostToDrain = Get-VMHost -Name "$hostnameToDrain*"
    }
    else {
        Write-Error "Connected to vCenter, but could not find the host $hostnameToDrain"
    }
}
if ($null -eq $hostToDrain) {
    Write-Error "Could not find the host $hostnameToDrain, or could not connect to vCenter"
}
else { #so we have a host
    #start maintenance mode (no output)
    $null = Set-VMHost -VMHost $hostToDrain -State Maintenance -RunAsync
    Write-Warning "Host $hostToDrain is entering maintenance mode"
    #find the belonging cluster
    $cluster = Get-Cluster -VMHost $hostToDrain
    #filter to vms on host to drain
    $vmOnHostToDrain = Get-VM -Location $hostToDrain
    #sort by size to do the largest first
    $vmOnHostToDrain = $vmOnHostToDrain | Where-Object name -notlike "vcls*" | Sort-Object powerstate, numcpu, memorygb, name -Descending 
    
    #variable for each job we make
    $myjob = @()

    foreach ($vm in $vmOnHostToDrain) {
        $destination = selectAvailableHost -myCluster $cluster -vmhostExclude $hostToDrain -vm $vm
        #Write-Warning "Moving VM $vm to host $destination"
        if ($PSCmdlet.ShouldProcess($vm, "Migrate to $destination")) {
            Write-Warning "Moving $vm to $destination starting at $(Get-Date)"
            $myjob += Move-VM -VM $vm -Destination $destination -RunAsync
            #$pendingJobCount = getPendingJobCount
            #while ($pendingJobCount -ge $max_vMotion_Simul) {
            while ((getPendingJobCount) -ge $max_vMotion_Simul) {
                Start-Sleep -Seconds $staggerSeconds #stagger a little
                #$pendingJobCount = getPendingJobCount
            }
        }
    } #end foreach vm
    #maintenance mode should complete now

    if ($PSCmdlet.ShouldProcess($hostToDrain,"Complete drain operation")) {
        while (getPendingJobCount -ne 0) {
            Start-Sleep -Seconds $staggerSeconds #stagger a little
        }

        $vmhostState = Get-VMHost "$hostnameToDrain*"
        while ($vmhostState.ConnectionState -ne "Maintenance") {
            Write-Warning "Waiting for $hostnameToDrain to be in Maintenance Mode"
            Start-Sleep -Seconds $staggerSeconds #give a little time to catch up
            $vmhostState = Get-VMHost "$hostnameToDrain*"
        }

        if ($remediate) {
            invoke-VMHostRemediation -hostname $hostToDrain.Name
        }
    }
        
}#end else we have a host
}#end function
#--------------------------

function invoke-VMHostRemediation {
<#
.SYNOPSIS
    Grabs the associated baselines of the given host and updates the host
.DESCRIPTION
    Connect to vCenter, get the host that matches the string, 
    Ensure the host is in maintenance, get the baselines the host inherits,
    Run the update for the host
.PARAMETER Hostname
    The string name of the host to update; will use a wildcard at the end (to shortcut FQDN)
.EXAMPLE
    invoke-VMHostRemediation -hostname e275vwh29.$env:userdnsdomain
.EXAMPLE
    invoke-VMHostRemediation -hostname e275vwh29 -WhatIf
#>
    [cmdletbinding(supportsShouldProcess)]
    Param (
        [Parameter(Mandatory)]
        [string]$hostname 
    )    

    #validate the host before beginning
    connect-VCenterServer
    
    try {
        Import-Module VMware.VumAutomation
    

        #find the chosen host
        $hostToUpdate = Get-VMHost -Name "$hostname*"
    
        if ($null -eq $hostToUpdate) {
            Write-Error "Could not find the host $hostname, or could not connect to vCenter"
        }
        else { #so we have a host - make sure state is ready
            if ($hostToUpdate.ConnectionState -ne "Maintenance") {
                Write-Error "Cannot update $hostToUpdate until in maintenance mode; please correct and retry."
            }    
            else { #so host is in maintenance mode
                $hostBaseline = Get-Baseline -Entity $hostToUpdate -Inherit
                if ($hostBaseline) {
                    if ($PSCmdlet.ShouldProcess($hostToUpdate)) {
                        Update-Entity -Entity $hostToUpdate -Baseline $hostBaseline -RunAsync -Confirm -ClusterDisableHighAvailability $true
                    }
                }
                else {
                    Write-Error "Could not find a baseline by which to update $hostToUpdate"
                }
            }
        }
    }
    catch {
        Write-Error $_.ToString()
    }
}#end function
#--------------------------


function Get-TriggeredAlarm {
<#
.SYNOPSIS
    This function lists the triggered alarms for the specified entity in vCenter
.DESCRIPTION
    List the triggered alarms for the given object
.NOTES
    Author: Kyle Ruddy, @kmruddy, kmruddy.com
    from https://github.com/vmware/PowerCLI-Example-Scripts/blob/master/Scripts/Get-TriggeredAlarm.ps1 on 9-24-20
.PARAMETER VM
    Specifies the name of the VM
.PARAMETER VMHost
    Specifies the name of the VMHost
.PARAMETER Datacenter
    Specifies the name of the Datacenter
.PARAMETER Datastore
    Specifies the name of the Datastore
.EXAMPLE
    Get-TriggeredAlarm -VM VMname 
    Entity  Alarm   AlarmStatus AlarmMoRef  EntityMoRef
    ----    ----    ----        ----        ----
    VMname  Name    Yellow      Alarm-MoRef Entity-MoRef
#>

    [CmdletBinding()]
    param(
        [string]$VM,
        [string]$VMHost,
        [string]$Datacenter,
        [string]$Datastore
    )
    BEGIN {
        connect-VCenterServer
        switch ($PSBoundParameters.Keys) {
            'VM' {$entity = Get-VM -Name $vm -ErrorAction SilentlyContinue}
            'VMHost' {$entity = Get-VMHost -Name $VMHost -ErrorAction SilentlyContinue}
            'Datacenter' {$entity = Get-Datacenter -Name $Datacenter -ErrorAction SilentlyContinue}
            'Datastore' {$entity = Get-Datastore -Name $Datastore -ErrorAction SilentlyContinue}
            default {$entity = $null}
        }
                    
        if ($null -eq $entity) {
            Write-Warning "No vSphere object found."
            break
        }
    }
    PROCESS {
        if ($entity.ExtensionData.TriggeredAlarmState -ne "") {
            $alarmOutput = @()
            foreach ($alarm in $entity.ExtensionData.TriggeredAlarmState) {
                $tempObj = "" | Select-Object -Property Entity, Alarm, AlarmStatus, TriggerTime, AcknowledgedByUser, AcknowledgedTime
                $tempObj.Entity = Get-View $alarm.Entity | Select-Object -ExpandProperty Name
                $tempObj.Alarm = Get-View $alarm.Alarm | Select-Object -ExpandProperty Info | Select-Object -ExpandProperty Name
                $tempObj.AlarmStatus = $alarm.OverallStatus
                $tempObj.TriggerTime = $alarm.Time
                $tempObj.AcknowledgedByUser = $alarm.AcknowledgedByUser
                $tempObj.AcknowledgedTime = $alarm.AcknowledgedTime
                $alarmOutput += $tempObj
            }
            $alarmOutput
        }
    }

}#end function
#-------------------------

function get-vCenterAlerts {
<#
.SYNOPSIS
 runs Get-TriggeredAlarm across all data centers (getting all alerts visible in the vCenter)
#>
    Get-Datacenter | ForEach-Object {Get-TriggeredAlarm -Datacenter $_}
}#end function
#--------------------------


function Get-VmNeedsTuning {
<#
.SYNOPSIS
  Tool that finds VMs with a storage-related problem or warning
.DESCRIPTION
  Checks for VMs that need consolidation, that aren't thick-eager-zeroed, and that occupy more than one datastore
  Common exceptions have been filtered out, such as VMs with snapshots, VMs on a VRTX, and milestone VMs
#>
    connect-VCenterServer

    #find VMs with disks that have parent disks, could be snapshot, or need consolidation
    $vmWithParent = Get-VM | Where-Object {$_ | Get-HardDisk | Where-Object {$_.extensiondata.backing.parent}}
    $vmWithParentAndSnapshot = $vmWithParent | Where-Object {$_ | Get-Snapshot}
    $vmWithParentNoSnapshot = $vmWithParent | Where-Object {$_.name -notin $vmWithParentAndSnapshot.Name}
    $vmWithParentNoSnapshot | Select-Object @{l="Reason";e={"NeedsConsolidation"}}, Name, PowerState, {$_.vmhost.name}

    #find VMs with disks that are not thick-eager-zeroed (does not pertain to non-3PAR storage)
    $vmNotEagerZero = Get-VM | Where-Object {$_ | Get-HardDisk | Where-Object storageformat -ne "eagerzeroedthick" | Where-Object filename -like '`[3p*' | Where-Object capacitygb -gt 2}
    #and don't care about smaller than 2GB
    $vmNotEagerZero | Select-Object @{l="Reason";e={"NotEagerZero"}}, Name, PowerState, {$_.vmhost.name}

    #find VMs that cover more than one datastore:
    $vmMultiDataStore = Get-VM | Where-Object {$_.datastoreidlist.count -gt 1} | Where-Object name -NotLike "*msrs*"
    $vmMultiDataStore | Select-Object @{l="Reason";e={"MultipleDatastore"}}, Name, PowerState, {$_.vmhost.name}
}#end function
#-------------------------
