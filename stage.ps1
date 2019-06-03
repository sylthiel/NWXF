function new-item {
	$item = new-object PSObject
	$item | add-member -type noteproperty -Name usesDefault -Value $False
	$item | add-member -type noteproperty -Name type -Value ""
	$item | add-member -type noteproperty -Name target -Value ""
	$item | add-member -type noteproperty -Name DPA -Value ""
    $item | Add-Member -type NoteProperty -Name ParentMP -Value ""
	return $item
}
function new-DataSource {
	$dataSource = new-object PSObject
	$tmp = [System.Collections.ArrayList]@()
	$dataSource | add-member -type noteproperty -Name items -Value $tmp
	$dataSource | add-member -type noteproperty -Name sit -Value $False
	$dataSource | add-member -type noteproperty -Name agents -Value $False
	$dataSource | add-member -type noteproperty -Name GUID -Value ""
    $dataSource | add-member -type NoteProperty -Name DSType -Value ""
	return $dataSource
}
function new-MonitoringPlan {
	$monitoringPlan = new-object PSObject
	$tmp = [System.Collections.ArrayList]@()
	$monitoringPlan | add-member -type noteproperty -Name dataSources -Value $tmp
	$monitoringPlan | add-member -type noteproperty -Name name -Value ""
	$monitoringPlan | add-member -type noteproperty -Name GUID -Value ""
	$monitoringPlan | add-member -type noteproperty -Name MP_DPA -Value ""
    $monitoringPlan | Add-Member -Type NoteProperty -Name usesDefaultSQL -Value $True
    $monitoringPlan | Add-Member -type NoteProperty -name SQLUserName -Value ""
	return $monitoringPlan
}
function Get-DSTypeByGUID {
    param ($GUID, $configxml)
    $tmp="'"+$GUID+"'"
    return ($configxml.selectnodes("./nr[1]/n[@n='\NetwrixAuditor']/n[@n='MetaInformation']/n[@n='Collectors']/n[@n=$tmp]/a[@n='ShortName']").v)
}
function get-nwxconfig {
	param($configxml)
	$monitoringPlans = [System.Collections.ArrayList]@()
	$managedObjects = $configxml.SelectNodes('./nr[1]/n/n[@n="ManagedObjects"]/n')
	$managedObjects | % {
		$temp = new-MonitoringPlan
        $temp.usesDefaultSQL=[System.Convert]::ToBoolean($_.selectnodes("./n[@n='ReportingSettings']/a[@n='UseDefault']").v)
        #write-host ($_.selectnodes("./n[@n='ReportingSettings']/a[@n='Enabled']").v)
        if(!$temp.usesDefaultSQL){$temp.SQLUserName = ($_.selectnodes("./n[@n='ReportingSettings']/a[@n='UserName']")).v}
		$temp.GUID = $_.n[0]
		$tempName = $_.selectNodes("./a[@n='Name']")
		$temp.name = $tempName.v
		$tempDPA=$_.selectNodes("./n[@n='AccountInfo']/a[@n='UserName']")
		$temp.MP_DPA=$tempDPA.v
		$tempDataSources = $_.SelectNodes("./n[@n='AuditedSystems']/n")
		$tempDataSources | % {
			$tempDS = new-DataSource
			$TMP=$_.selectnodes("./n[@n='Agents']/a") | select v
			$tempDS.agents=$True
			$TMP=$_.selectnodes("./n[@n='StateInTimeReporting']/a[@n='Enabled']") | select v
			$tempDS.sit=$TMP
			$tempDS.GUID=$_.n[0]
            $tempDS.DSType=Get-DSTypeByGUID -GUID $tempDS.GUID -configxml $configxml	
			$items=$_.SelectNodes("./n[@n='ScopeItems']/n")
			$items | % { 
				$tmpi = new-item
				$tmpi.type=$_.t
				$TMP=$_.selectnodes("./a[@n='audit_item_value']")
				$tmpi.target=$TMP.v
				$TMP=$_.selectnodes("./n[@n='AccountInfo']/a[@n='DefaultAccount']")
				$tmpi.usesDefault=[System.Convert]::ToBoolean($Tmp.v)
				if (!$tmpi.usesDefault)	{
					$TMP=$_.selectnodes("./n[@n='AccountInfo']/a[@n='UserName']")
					$tmpi.DPA=$TMP.v
				}
                $tmpi.ParentMP=$temp.name
				[void]$tempDS.items.add($tmpi)
			}
			[void]$temp.dataSources.add($tempDS)
		}
	[void]$monitoringPlans.add($temp)
	}
	return $monitoringPlans
}
function Get-LegacyAuditSystems {
	param ($configxml)
	$legacyAuditSystems=$configxml.selectnodes("./nr[1]/n[@n='\LegacyAuditSystems']/n/n/n[@n='ManagedObjects']")
	$tmp = [System.Collections.ArrayList]@()
	if($legacyAuditSystems) {
		$MOs = $legacyauditsystems.childnodes
		if ($MOs) {
			$MOs | % {
				$ELM_MP=new-MonitoringPlan
				$ELM_MP.GUID=$_.n[0]
				$tempdpa=$_.selectnodes("./n/a[@n='UserName']")
				#$tempdpa
				$ELM_MP.MP_DPA=$tempdpa.v
				$ELM_MP.name="NwxELM"
				[void]$tmp.add($ELM_MP)
			}
		}		
	}
	return $tmp
}
function Get-NwxSQLSettings {
    param($configxml)
    $SQLSettings=$configxml.selectnodes("./nr[1]/n[@n='\AuditedSystemsAccountsCache']/n/n/n/n/n")
    $NwxSQLSettings="" | select SQLURL, SQLUserName, SSRSURL1, SSRSURL2, SSRSUserName, DDCSQLUserName
    $NwxSQLSettings.SQLURL=($SQLSettings.selectnodes("./a")).v
    $NwxSQLSettings.SQLUserName=($SQLSettings.selectnodes("./n[@n='AccountInfo']/a[@n='UserName']")).v
    $NwxSQLSettings.SSRSURL1=($configxml.selectnodes("./nr[1]/n[@n='\NetwrixAuditor']/n[@n='CommonSettings']/n[@n='ReportingSettings']/a[@n='ReportServerUrl']")).v
    $NwxSQLSettings.SSRSURL2=($configxml.selectnodes("./nr[1]/n[@n='\NetwrixAuditor']/n[@n='CommonSettings']/n[@n='ReportingSettings']/a[@n='ReportManagerUrl']")).v
    $NwxSQLSettings.SSRSUserName=($configxml.selectnodes("./nr[1]/n[@n='\NetwrixAuditor']/n[@n='CommonSettings']/n[@n='ReportingSettings']/a[@n='UserName']")).v
    $NwxSQLSettings.DDCSQLUserName=($configxml.selectnodes("./nr[1]/n[@n='\DDC']/n[@n='SQLSettings']/a[@n='UserName']")).v
    return $NwxSQLSettings
}
function Get-NwxSchTasks {
    param ($configxml)
    $NwxSchTasks = [System.Collections.ArrayList]@()
    $Tasks=Get-ScheduledTask -TaskName *Netwrix* | select TaskName, Author
    $Tasks | % {
        $TmpTask = "" | select "Name", "MP_DPA", "GUID"
        $TmpName = $_.TaskName
        $Tmp=([regex]::Matches($TmpName, '{[-0-9a-z]+}'))
        $TmpTask.GUID=(([System.Convert]::toString($Tmp[1]) -replace "[{}]", ""))
        #switch ($Tmp[0]) {
        #    "{1127fafa-5e4f-e3d6-05d6-ca9317c533bb}" {
        #        $TmpTask.Name="IUT"
        #    }
        #    "{33049cf6-6925-d7bd-ab7e-9cf82eed22e0}" {
        #        $TmpTask.Name="PEN"
        #    }
        #    "{e8f4ac2f-098c-8cc5-22f2-9339d551325a}" {
        #        $TmpTask.Name="ELM"
        #    }
        #}
        $TmpTask.Name=Get-DSTypeByGUID -GUID ($tmp[0] -replace "[{}]", "") -configxml $configxml
        $TmpTask.MP_DPA = $_.Author
        [void]$NwxSchTasks.add($TmpTask)
    }
    return $NwxSchTasks
}
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
   
	if ($NWXInstallation) {
		[System.Xml.XmlDocument]$configxml = new-object System.Xml.XmlDocument
		$configxml.load($WorkingDirectory + 'AuditCore\ConfigServer\Configuration.xml')
	}
    
	#Creating the custom object that hosts Netwrix paths and configurationXML for quick reference. 
	#This needs to call Get-NwxObject to create a PSObject from Configuration.XML And be used for other features 
	
	if ($NWXInstallation)   {
        $Installation = [PSCustomObject]@{
            ComputerName = $ComputerName
            DisplayVersion = $NWXInstallation.DisplayVersion
            #VersionMajor = $NWXInstallation.VersionMajor
            #VersionMinor = $NWXInstallation.VersionMinor
            InstallationPath = ($InstallationPath -replace ('Audit Core\\NwCoreSvc.exe',''))
            WorkingDirectory = $WorkingDirectory
			ConfigurationXML=$configxml
			ConfgiurationXMLPath=$WorkingDirectory + 'AuditCore\ConfigServer\Configuration.xml'
			MonitoringPlans=Get-NwxConfig $configxml
			DefaultSQLSettings=Get-NwxSQLSettings $configxml
			ELM=Get-LegacyAuditSystems $configxml
            SQLSettings=Get-NwxSQLSettings $configxml
            NwxSchTasks=Get-NwxSchTasks $configxml
        }
    }
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
			copy-item ($LogPath) -Destination $TempPath -recurse -force -verbose	
			#copy-item -recurse -force -Source $LogPath -Destination $TempPath
			$copiedfiles+=$TempPath
		}
		Catch   {
			add-content -path $env:TEMP\NWXF\FrameworkLog.log -value "$(Get-Date) [ERROR] Failed to obtain logs! "
			add-content -path $env:TEMP\NWXF\FrameworkLog.log -value $_.Exception.Message
			Write-Host -foregroundcolor Red "Error obtaining logs: See NWXF\Frameworklog.log for more information"
			$Success = $False
		} 
		if($Success)   {
			Write-Host -foregroundcolor Green "Success, copied $LogPath"
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
			copy-item ($LogPath) -Destination $TempPath -recurse -force -verbose	
			$copiedfiles+=$TempPath
		}
		Catch   {
			add-content -path $env:TEMP\NWXF\FrameworkLog.log -value "$(Get-Date) [ERROR] Failed to obtain logs! "
			add-content -path $env:TEMP\NWXF\FrameworkLog.log -value $_.Exception.Message
			Write-Host -foregroundcolor Red "Error obtaining logs: See NWXF\Frameworklog.log for more information"
			$Success = $False
		} 
		if($Success)   {
			Write-Host -foregroundcolor Green "Success, copied $LogPath"
			add-content -path $env:TEMP\NWXF\FrameworkLog.log "$(Get-Date) Successfully copied logs to $TempPath"   
		}
	}
	if ($nwxhealth)	{
		wevtutil epl 'Netwrix Auditor' ($currentpath+'\health.evtx')
	}
	Write-Host -foregroundcolor Green "Logs copied to folder" $currentpath
	$copiedfiles 
}
function Get-NwxLogLocation {
    param ($NWXInstallation, $Collector,$archive=$false)
    #Foolproofing $NWXInstallation to $null in case it is not passed, will be calcd inside
    #echo 'nwx is' $NWXInstallation    
    #echo 'collector is' $Collector 
	#echo ILJ
    if (!$NWXInstallation){
        $NWXInstallation = Get-NwxInstallation
    }    
	
    $LogLocationSuffix = @{
		'AD'='\ActiveDirectory'
        'Exch'='\Exchange'
        'NOMBA'='\Nomba'
        'GP'='\GroupPolicy'
        'NLA'='\DataCollectionCore\NwNLASvc'  
        'FSAWIN'='\DataCollectionCore\NwFileStorageSvc'
		'FSAETC'='\File Server Auditing\Tracing'
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
	else {return $NWXInstallation.WorkingDirectory + 'Logs\' + 'Archive' + $LogLocationSuffix[$Collector]}
}
function Get-NwxServiceAccountUsage {
    param ($NwxInstallation=$Null)
    if (!$NWXInstallation)	{
		$NWXInstallation=Get-NwxInstallation
	}
    if($NwxInstallation.monitoringPlans) {
        Write-Host -BackgroundColor DarkGreen -NoNewLine "Monitoring Plans:"
        $NwxInstallation.monitoringPlans | ft name, MP_DPA
    }
    if($NwxInstallation.monitoringPlans | ? {!$_.usesDefaultSQL}) {
        Write-Host -BackgroundColor DarkGreen -NoNewLine "Monitoring Plans with non-default SQL settings:"
        $NwxInstallation.monitoringPlans | ? {!$_.usesDefaultSQL} | ft Name, SQLUserName
    }
    if ($NwxInstallation.monitoringPlans.dataSources.items | ? {!$_.usesDefault}) {
        Write-Host -BackgroundColor DarkGreen -NoNewLine "Items with non-default credentials:"
        $NwxInstallation.monitoringPlans.dataSources.items | ? {!$_.usesDefault} | ft ParentMP, type, target, DPA
    }
    if ($NwxInstallation.nwxSchTasks) {
        Write-Host -BackgroundColor DarkGreen -NoNewLine "Legacy Netwrix Products (IUT, PEN, ELM)"
        $NwxInstallation.nwxSchTasks | ft Name, GUID, MP_DPA
    }
    if ($NwxInstallation.SQLSettings) {
        Write-Host -BackgroundColor DarkGreen -NoNewLine "`nSQL, DDC, SSRS default settings"
        $NwxInstallation.SQLSettings | fl
    }
}



