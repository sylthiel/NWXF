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
    #
    #   GET-WORKINGDIRECTORY via REG!!
    #
    $WorkingDirectory = 'C:\ProgramData\Netwrix Auditor\'
    #
    #   GET-WORKINGDIRECTORY via REG!!
    #
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
    $Installation
}
function Get-NwxLogs {
    param($NWXInstallation=$Null, $collectors='AD', $path = "$env:TEMP"+"\NWXF")
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
	Write-Host -foregroundcolor Green "Logs copied to folder" $currentpath
	$copiedfiles 
	#Compress-Archi
}
function Get-NwxLogLocation {
    param ($NWXInstallation, $Collector)
    #Foolproofing $NWXInstallation to $null in case it is not passed, will be calcd inside
    #echo 'nwx is' $NWXInstallation    
    #echo 'collector is' $Collector 
    if (!$NWXInstallation){
        $NWXInstallation = Get-NwxInstallation
    }    
    $LogLocationSuffix = @{
        'AD'='Logs\ActiveDirectory'
        'Exch'='Logs\Exchange'
        'NOMBA'='################################'
        'GP'='Logs\GroupPolicy'
        'NLA'='Logs\File Server Auditing\Tracing'  
        'FSA'='#######################################'
        'WSA'='Logs\Windows Server Auditing'
        'ELM'='Logs\Event Log Management'
        'UAVR'='####################################'
        'SQL'='Logs\SQL Server Auditing'
        'O365'='Logs\Exchange Online'
        'Azure'='Logs\Azure AD'
        'SP'='Logs\SharePoint Auditing'
        'ArchiveSvc'='Logs\AuditCore\NwArchiveSvc'
        'Management'='Logs\AuditCore\NwManagementSvc'
        'Core'='Logs\AuditCore\NwCoreSvc'
        'Alerts'='Logs\Administrative Console'
        'Archive'='#####################################'   
    }    
    return $NWXInstallation.WorkingDirectory + $LogLocationSuffix[$Collector]
}

