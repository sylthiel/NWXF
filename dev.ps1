Import-Module BitsTransfer
function Get-NwxInstallation	{
    #AOSH-2019
	param($ComputerName='localhost')
    #by default we assume that the script is ran on the Netwrix machine
    #if it is installed remotely, we can query the specified hostname for the information.
    if($ComputerName -ne 'localhost')    {
        $NWXInstallation = Invoke-Command -ComputerName $ComputerName -scriptblock {Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object {$_.DisplayName -eq "Netwrix Auditor"}}
        $InstallationPath = Invoke-Command -ComputerName $ComputerName -scriptblock{((Get-WmiObject win32_service | ?{$_.Name -eq 'NwCoreSvc'}).PathName.split('"')[1])}
    }
    else {
        $NWXInstallation = Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object {$_.DisplayName -eq "Netwrix Auditor"}
        $InstallationPath = ((Get-WmiObject win32_service | ?{$_.Name -eq 'NwCoreSvc'}).PathName.split('"')[1])
    }
    if (!(Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Netwrix Auditor\DataPathOverride'))	{$WorkingDirectory = 'C:\ProgramData\Netwrix Auditor\'}
	else {$WorkingDirectory = get-item 'HKLM:\SOFTWARE\Wow6432Node\Netwrix Auditor\DataPathOverride\Working Folder'} #CHECK THIS REG KEY
    
    if ($NWXInstallation)   {
        $Installation = [PSCustomObject]@{
            ComputerName = $ComputerName
            DisplayVersion = $NWXInstallation.DisplayVersion
            VersionMajor = $NWXInstallation.VersionMajor
            VersionMinor = $NWXInstallation.VersionMinor
            InstallationPath = ($InstallationPath -replace ('Audit Core\\NwCoreSvc.exe',''))
            WorkingDirectory = $WorkingDirectory  
        }
    }
    ##If we didn't find it, it's not installed
    else { 
        $Installation = $Null
    }
    return $Installation
}
function Get-NwxLogs {
    param($NWXInstallation=$Null, $collectors='', $path = "$env:TEMP"+"\NWXF", $archivelogs=$false, $nwxhealth=$False)
	#$collectors
    #SETTING ADA FOR DEFAULT FOR DEV PURPOSES
    #THIS IS 9.7+
    #VERSION BACKWARDS COMPATABILITY HAS NOT BEEN IMPLEMENTED
	$CurrentPath=$path+'\'+(get-date).ticks
    new-item -path $currentpath -itemtype "directory" -force | out-null
    #just checking that the tempdir we are trying to create doesn't exist for whatever obscure reason
    add-content -path $env:TEMP\NWXF\FrameworkLog.log -value "$(Get-Date) created logdir $TempPath"
    #LOG ALL SUCH ACTIONS 
    if (!$NWXInstallation){
        $NWXInstallation = Get-NwxInstallation
    }  
	$copiedfiles=@()
	foreach ($collector in $collectors)	{
		#$collector
		$TempPath=$currentpath+"\"+$Collector+'\'
		if(!(test-path $TempPath))  {
				new-item -path $TempPath -itemtype "directory" -force | out-null
		}
		$LogPath = Get-NwxLogLocation -NWXInstallation $NWXInstallation -Collector $Collector  
		$success=$True
		Try {
			add-content -path $env:TEMP\NWXF\FrameworkLog.log -value "$(Get-Date) Obtaining logs for $Collector Audit"
			#copy-item ($LogPath) -Destination $TempPath -recurse -force -verbose	
			Start-BitsTransfer -Source $LogPath -Destination $TempPath -Description "Logs" -DisplayName "NWXLE"
			$copiedfiles+=$TempPath
		}
		Catch   {
			add-content -path $env:TEMP\NWXF\FrameworkLog.log -value "$(Get-Date) [ERROR] Failed to obtain logs! "
			add-content -path $env:TEMP\NWXF\FrameworkLog.log -value $_.Exception.Message
			Write-Host -foregroundcolor Red "Error obtaining logs: See NWXF\Frameworklog.log for more information"
			$Success = $False
		} 
		if($Success)   {
			Write-Host -foregroundcolor Green "Success"
			add-content -path $env:TEMP\NWXF\FrameworkLog.log "$(Get-Date) Successfully copied logs to $TempPath"   
		}
	}
	if($archivelogs)	{
		$TempPath=$currentpath+"\Archive\"+$Collector+'\'
		if(!(test-path $TempPath))  {
				new-item -path $TempPath -itemtype "directory" -force | out-null
		}
		$LogPath = Get-NwxLogLocation -NWXInstallation $NWXInstallation -Collector $Collector -Archive $True
		$success=$True
		Try {
			add-content -path $env:TEMP\NWXF\FrameworkLog.log -value "$(Get-Date) Obtaining logs for $Collector Audit"
			#copy-item ($LogPath) -Destination $TempPath -recurse -force -verbose	
			Start-BitsTransfer -Source $LogPath -Destination $TempPath -Description "Logs" -DisplayName "NWXLE"
			$copiedfiles+=$TempPath
		}
		Catch   {
			add-content -path $env:TEMP\NWXF\FrameworkLog.log -value "$(Get-Date) [ERROR] Failed to obtain logs! "
			add-content -path $env:TEMP\NWXF\FrameworkLog.log -value $_.Exception.Message
			Write-Host -foregroundcolor Red "Error obtaining logs: See NWXF\Frameworklog.log for more information"
			$Success = $False
		} 
		if($Success)   {
			Write-Host -foregroundcolor Green "Success"
			add-content -path $env:TEMP\NWXF\FrameworkLog.log "$(Get-Date) Successfully copied logs to $TempPath"   
		}
	}
	if ($nwxhealth)	{
		wevtutil epl 'Netwrix Auditor' ($currentpath+'\health.evtx')
	}
	Write-Host -foregroundcolor Green "Logs copied to folder" $currentpath
	$copiedfiles 
	#Compress-Archi
}
function Get-NwxLogLocation {
    param ($NWXInstallation, $Collector,$archive=$false)
    #Foolproofing $NWXInstallation to $null in case it is not passed, will be calcd inside
    #echo 'nwx is' $NWXInstallation    
    #echo 'collector is' $Collector 
    if (!$NWXInstallation){
        $NWXInstallation = Get-NwxInstallation
    }    
	
    $LogLocationSuffix = @{
		'AD'='\ActiveDirectory'
        'Exch'='\Exchange'
        'NOMBA'='################################'
        'GP'='\GroupPolicy'
        'NLA'='\File Server Auditing\Tracing'  
        'FSA'='#######################################'
        'WSA'='\Windows Server Auditing'
        'ELM'='\Event Log Management'
        'UAVR'='####################################' #<-FIND OUT ABOUT THIS IN 9.8
        'SQL'='\SQL Server Auditing'
        'O365'='\Exchange Online'
        'Azure'='\Azure AD'
        'SP'='\SharePoint Auditing'
        'ArchiveSvc'='\AuditCore\NwArchiveSvc'
        'Management'='\AuditCore\NwManagementSvc'
        'Core'='\AuditCore\NwCoreSvc'
        'Alerts'='\Administrative Console' 
    }    
    if (!$archive) {return $NWXInstallation.WorkingDirectory + 'Logs'+ $LogLocationSuffix[$Collector]}
	else {return $NWXInstallation.WorkingDirectory + 'Logs\' + 'Archive\' + $LogLocationSuffix[$Collector]}
}

