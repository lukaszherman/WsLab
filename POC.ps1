param ($configFile = "LabConfig.ps1")

# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}

#region Functions

    function WriteInfo($message){
        Write-Host $message
    }

    function WriteInfoHighlighted($message){
        Write-Host $message -ForegroundColor Cyan
    }

    function WriteSuccess($message){
        Write-Host $message -ForegroundColor Green
    }

    function WriteWarning($message) {
        Write-Host $message -ForegroundColor Yellow
    }

    function WriteError($message){
        Write-Host $message -ForegroundColor Red
    }

    function WriteErrorAndExit($message){
        Write-Host $message -ForegroundColor Red
        Write-Host "Press enter to continue ..."
        Stop-Transcript
        Read-Host | Out-Null
        Exit
    }

    Function CreateUnattendFileBlob{
        #Create Unattend (parameter is Blob)
        param (
            [parameter(Mandatory=$true)]
            [string]
            $Blob,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone,
            [parameter(Mandatory=$false)]
            [string]
            $RunSynchronous
        )

        if ( Test-Path "Unattend.xml" ) {
        Remove-Item .\Unattend.xml
        }
        $unattendFile = New-Item "Unattend.xml" -type File
        $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <settings pass="offlineServicing">
    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <OfflineIdentification>
           <Provisioning>
             <AccountData>$Blob</AccountData>
           </Provisioning>
         </OfflineIdentification>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
       <HideEULAPage>true</HideEULAPage>
       <SkipMachineOOBE>true</SkipMachineOOBE> 
       <SkipUserOOBE>true</SkipUserOOBE> 
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RegisteredOwner>Vulcan</RegisteredOwner>
      <RegisteredOrganization>Vulcan Sp. z o.o.</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <RunSynchronous>
            $RunSynchronous
        </RunSynchronous>
    </component>
	<component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
		<InputLocale>pl-PL</InputLocale>
		<SystemLocale>pl-PL</SystemLocale> 
		<UILanguage>en-US</UILanguage> 
		<UserLocale>pl-PL</UserLocale>
    </component>
  </settings>
</unattend>

"@

        Set-Content $unattendFile $fileContent
        #return the file object
        $unattendFile 
    }

    Function CreateUnattendFileNoDjoin{
        #Create Unattend(without domain join)    
        param (
            [parameter(Mandatory=$true)]
            [string]
            $ComputerName,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone,
            [parameter(Mandatory=$false)]
            [string]
            $RunSynchronous,
            [parameter(Mandatory=$false)]
            [string]
            $AdditionalAccount
        )

            if ( Test-Path "Unattend.xml" ) {
            Remove-Item .\Unattend.xml
            }
            $unattendFile = New-Item "Unattend.xml" -type File
            $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        <RegisteredOwner>Vulcan</RegisteredOwner>
          <RegisteredOrganization>Vulcan Sp. z o.o.</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <RunSynchronous>
            $RunSynchronous
        </RunSynchronous>
    </component>
	<component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
		<InputLocale>pl-PL</InputLocale>
		<SystemLocale>pl-PL</SystemLocale> 
		<UILanguage>en-US</UILanguage> 
		<UserLocale>pl-PL</UserLocale>
    </component>
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        $AdditionalAccount
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE> 
        <SkipUserOOBE>true</SkipUserOOBE> 
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
</unattend>

"@

        Set-Content $unattendFile $fileContent
        #return the file object
        $unattendFile 
    }

    Function CreateUnattendFileWin2012{
        #Create Unattend(traditional Djoin with username/pass)
        param (
            [parameter(Mandatory=$true)]
            [string]
            $ComputerName,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone,
            [parameter(Mandatory=$false)]
            [string]
            $RunSynchronous,
            [parameter(Mandatory=$true)]
            [string]
            $DomainName
        )
        if ( Test-Path "Unattend.xml" ) {
            Remove-Item .\Unattend.xml
        }
        $unattendFile = New-Item "Unattend.xml" -type File
        $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        <RegisteredOwner>Vulcan</RegisteredOwner>
        <RegisteredOrganization>Vulcan Sp. z o.o.</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <RunSynchronous>
            $RunSynchronous
        </RunSynchronous>
    </component>
	<component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
		<InputLocale>pl-PL</InputLocale>
		<SystemLocale>pl-PL</SystemLocale> 
		<UILanguage>en-US</UILanguage> 
		<UserLocale>pl-PL</UserLocale>
    </component>
    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <Identification>
                <Credentials>
                    <Domain>$DomainName</Domain>
                    <Password>$AdminPassword</Password>
                    <Username>Administrator</Username>
                </Credentials>
                <JoinDomain>$DomainName</JoinDomain>
        </Identification>
    </component>
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE> 
        <SkipUserOOBE>true</SkipUserOOBE> 
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
</unattend>

"@

        Set-Content $unattendFile $fileContent
        #return the file object
        $unattendFile 
    }

    Function AdditionalLocalAccountXML{
        #Creates Additional local account unattend piece
        param (
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $AdditionalAdminName
        )
@"
<LocalAccounts>
    <LocalAccount wcm:action="add">
        <Password>
            <Value>$AdminPassword</Value>
            <PlainText>true</PlainText>
        </Password>
        <Description>$AdditionalAdminName admin account</Description>
        <DisplayName>$AdditionalAdminName</DisplayName>
        <Group>Administrators</Group>
        <Name>$AdditionalAdminName</Name>
    </LocalAccount>
</LocalAccounts>
"@
    }

    function  Get-WindowsBuildNumber { 
        $os = Get-CimInstance -ClassName Win32_OperatingSystem 
        return [int]($os.BuildNumber) 
    } 

    Function Set-VMNetworkConfiguration {
        #source:http://www.ravichaganti.com/blog/?p=2766 with some changes
        #example use: Get-VMNetworkAdapter -VMName Demo-VM-1 -Name iSCSINet | Set-VMNetworkConfiguration -IPAddress 192.168.100.1 00 -Subnet 255.255.0.0 -DNSServer 192.168.100.101 -DefaultGateway 192.168.100.1
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,
                    Position=1,
                    ParameterSetName='DHCP',
                    ValueFromPipeline=$true)]
            [Parameter(Mandatory=$true,
                    Position=0,
                    ParameterSetName='Static',
                    ValueFromPipeline=$true)]
            [Microsoft.HyperV.PowerShell.VMNetworkAdapter]$NetworkAdapter,

            [Parameter(Mandatory=$true,
                    Position=1,
                    ParameterSetName='Static')]
            [String[]]$IPAddress=@(),

            [Parameter(Mandatory=$false,
                    Position=2,
                    ParameterSetName='Static')]
            [String[]]$Subnet=@(),

            [Parameter(Mandatory=$false,
                    Position=3,
                    ParameterSetName='Static')]
            [String[]]$DefaultGateway = @(),

            [Parameter(Mandatory=$false,
                    Position=4,
                    ParameterSetName='Static')]
            [Parameter(Mandatory=$false,
                    Position=4,
                    ParameterSetName='DHCP')]
            [String[]]$DNSServer = @(),

            [Parameter(Mandatory=$false,
                    Position=0,
                    ParameterSetName='DHCP')]
            [Switch]$Dhcp
        )

        $VM = Get-CimInstance -Namespace "root\virtualization\v2" -ClassName "Msvm_ComputerSystem" | Where-Object ElementName -eq $NetworkAdapter.VMName 
        $VMSettings = Get-CimAssociatedInstance -InputObject $vm -ResultClassName "Msvm_VirtualSystemSettingData" | Where-Object VirtualSystemType -EQ "Microsoft:Hyper-V:System:Realized"
        $VMNetAdapters = Get-CimAssociatedInstance -InputObject $VMSettings -ResultClassName "Msvm_SyntheticEthernetPortSettingData"

        $networkAdapterConfiguration = @()
        foreach ($netAdapter in $VMNetAdapters) {
            if ($netAdapter.ElementName -eq $NetworkAdapter.Name) {
                $networkAdapterConfiguration = Get-CimAssociatedInstance -InputObject $netAdapter -ResultClassName "Msvm_GuestNetworkAdapterConfiguration"
                break
            }
        }

        $networkAdapterConfiguration.PSBase.CimInstanceProperties["IPAddresses"].Value = $IPAddress
        $networkAdapterConfiguration.PSBase.CimInstanceProperties["Subnets"].Value = $Subnet
        $networkAdapterConfiguration.PSBase.CimInstanceProperties["DefaultGateways"].Value = $DefaultGateway
        $networkAdapterConfiguration.PSBase.CimInstanceProperties["DNSServers"].Value = $DNSServer
        $networkAdapterConfiguration.PSBase.CimInstanceProperties["ProtocolIFType"].Value = 4096

        if ($dhcp) {
            $networkAdapterConfiguration.PSBase.CimInstanceProperties["DHCPEnabled"].Value = $true
        } else {
            $networkAdapterConfiguration.PSBase.CimInstanceProperties["DHCPEnabled"].Value = $false
        }

        $cimSerializer = [Microsoft.Management.Infrastructure.Serialization.CimSerializer]::Create()
        $serializedInstance = $cimSerializer.Serialize($networkAdapterConfiguration, [Microsoft.Management.Infrastructure.Serialization.InstanceSerializationOptions]::None)
        $serializedInstanceString = [System.Text.Encoding]::Unicode.GetString($serializedInstance)

        $service = Get-CimInstance -ClassName "Msvm_VirtualSystemManagementService" -Namespace "root\virtualization\v2"
        $setIp = Invoke-CimMethod -InputObject $service -MethodName "SetGuestNetworkAdapterConfiguration" -Arguments @{
            ComputerSystem = $VM
            NetworkConfiguration = @($serializedInstanceString)
        }
        if($setIp.ReturnValue -eq 0) { # completed
            WriteInfo "`t`t Success"
        } else {
            # unexpected response
            $setIp
        }
    }

    function WrapProcess{
        #Using this function you can run legacy program and search in output string 
        #Example: WrapProcess -filename fltmc.exe -arguments "attach svhdxflt e:" -outputstring "Success"
        [CmdletBinding()]
        [Alias()]
        [OutputType([bool])]
        Param (
            # process name. For example fltmc.exe
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
            $filename,

            # arguments. for example "attach svhdxflt e:"
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=1)]
            $arguments,

            # string to search. for example "attach svhdxflt e:"
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=1)]
            $outputstring
        )
        Process {
            $procinfo = New-Object System.Diagnostics.ProcessStartInfo
            $procinfo.FileName = $filename
            $procinfo.Arguments = $arguments
            $procinfo.UseShellExecute = $false
            $procinfo.CreateNoWindow = $true
            $procinfo.RedirectStandardOutput = $true
            $procinfo.RedirectStandardError = $true


            # Create a process object using the startup info
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $procinfo
            # Start the process
            $process.Start() | Out-Null

            # test if process is still running
            if(!$process.HasExited){
                do{
                   Start-Sleep 1 
                }until ($process.HasExited -eq $true)
            }

            # get output 
            $out = $process.StandardOutput.ReadToEnd()

            if ($out.Contains($outputstring)) {
                $output=$true
            } else {
                $output=$false
            }
            return, $output
        }
    }

    Function BuildVM {
        [cmdletbinding()]
        param(
            [PSObject]$VMConfig,
            [PSObject]$LabConfig
        )
		$csvPath = $VMConfig.CsvPath
		
        WriteInfoHighlighted "Creating VM $($VMConfig.VMName)"
		
		WriteInfo "`t Looking for Parent Disk"
		$serverparent=Get-ChildItem "$csvPath\" -Recurse | Where-Object Name -eq $VMConfig.ParentVHD
			
		if ($serverparent -eq $null){
			WriteErrorAndExit "Server parent disk $($VMConfig.ParentVHD) not found."
		}else{
			WriteInfo "`t`t Server parent disk $($serverparent.Name) found"
		}

		$VMname=$Labconfig.Prefix+$VMConfig.VMName
		$vhdpath="$csvPath\$VMname\Virtual Hard Disks\$VMname.vhdx"
		if(-not(Test-Path "$csvPath\$VMname\Virtual Hard Disks"))
		{
			New-Item -ItemType Directory  "$csvPath\$VMname\Virtual Hard Disks"
		}
			
		
		if($VMConfig.Differencing)
		{
			WriteInfo "`t Creating OS VHD"
			New-VHD -ParentPath $serverparent.fullname -Path $vhdpath
		}
		else
		{
			#Standard VM without differencing disks!			
			WriteInfo "`t Copy OS VHD from sysprep (source $($serverparent.fullname))"
			Copy-Item $serverparent.fullname -Destination $vhdpath
		}
		
        WriteInfo "`t Creating VM"
        $VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $VMConfig.MemoryStartupBytes -path "$csvPath" -SwitchName $SwitchName -Generation 2    

        $VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
		if($VMConfig.MaximumBytes) {$VMTemp | Set-VMMemory -MaximumBytes $VMConfig.MaximumBytes}
        $VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1
		
		WriteInfo "`t Adapter Management1 with IP $($VMConfig.IP)"
		if($VMConfig.IP) {$VMTemp | Get-VMNetworkAdapter -Name Management1 | Set-VMNetworkConfiguration -IPAddress $VMConfig.IP -Subnet $VMConfig.Subnet -DNSServer $VMConfig.DNS -DefaultGateway $VMConfig.DefaultGateway }
		elseif($VMConfig.DNS){ $VMTemp | Get-VMNetworkAdapter -Name Management1 | Set-VMNetworkConfiguration -DNSServer $VMConfig.DNS -Dhcp}
		
        if($VMConfig.VLAN){ $VMTemp | Get-VMNetworkAdapter -Name Management1 | Set-VMNetworkAdapterVlan -VlanId $VMConfig.VLAN -Access }
		
		
		
        if ($VMTemp.AutomaticCheckpointsEnabled -eq $True){
            $VMTemp | Set-VM -AutomaticCheckpointsEnabled $False
        }
		
		$VMTemp | Set-VM -AutomaticStopAction ShutDown
		$VMTemp | Set-VM -CheckpointType Production 

        if($VMConfig.CompatibilityForMigrationEnabled) {$VMTemp | Set-VMProcessor -CompatibilityForMigrationEnabled $true}

        $MGMTNICs=$VMConfig.MGMTNICs
        If($MGMTNICs -eq $null){
            $MGMTNICs = 1
        }

        If($MGMTNICs -gt 8){
            $MGMTNICs=8
        }

        If($MGMTNICs -ge 2){
            2..$MGMTNICs | ForEach-Object {
                WriteInfo "`t Adding Network Adapter Management$_"
                $VMTemp | Add-VMNetworkAdapter -Name "Management$_"
            }
			
					
			WriteInfo "`t Adapter Management2 with IP $($VMConfig.SecondIP)"
			if($VMConfig.SecondIP) {$VMTemp | Get-VMNetworkAdapter -Name Management2 | Set-VMNetworkConfiguration -IPAddress $VMConfig.SecondIP -Subnet $VMConfig.SecondSubnet -DNSServer $VMConfig.SecondDNS}
			if($VMConfig.SecondDefaultGateway) {$VMTemp | Get-VMNetworkAdapter -Name Management2 | Set-VMNetworkConfiguration -DefaultGateway $VMConfig.SecondDefaultGateway }
			if($VMConfig.SecondVLAN){ $VMTemp | Get-VMNetworkAdapter -Name Management2 | Set-VMNetworkAdapterVlan -VlanId $VMConfig.SecondVLAN -Access }
			
        }
        WriteInfo "`t Connecting vNIC to $switchname"
        $VMTemp | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

        #set MemoryMinimumBytes
        if ($VMConfig.MemoryMinimumBytes -ne $null){
            WriteInfo "`t Configuring MemoryMinimumBytes to $($VMConfig.MemoryMinimumBytes/1MB)MB"
            if ($VMConfig.NestedVirt){
                "`t `t Skipping! NestedVirt configured"
            }else{
                Set-VM -VM $VMTemp -MemoryMinimumBytes $VMConfig.MemoryMinimumBytes
            }
        }

        #Set static Memory
        if ($VMConfig.StaticMemory -eq $true){
            WriteInfo "`t Configuring StaticMemory"
            $VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
        }

        #configure number of processors
        if ($VMConfig.VMProcessorCount){
            WriteInfo "`t Configuring VM Processor Count to $($VMConfig.VMProcessorCount)"
            if ($VMConfig.VMProcessorCount -le $NumberOfLogicalProcessors){
                $VMTemp | Set-VMProcessor -Count $VMConfig.VMProcessorCount
            }else{
                WriteError "`t `t Number of processors specified in VMProcessorCount is greater than Logical Processors available in Host!"
                WriteInfo  "`t `t Number of logical Processors in Host $NumberOfLogicalProcessors"
                WriteInfo  "`t `t Number of Processors provided in labconfig $($VMConfig.VMProcessorCount)"
                WriteInfo  "`t `t Will configure maximum processors possible instead ($NumberOfLogicalProcessors)"
                $VMTemp | Set-VMProcessor -Count $NumberOfLogicalProcessors
            }
        }else{
            $VMTemp | Set-VMProcessor -Count 2
        }

        $Name=$VMConfig.VMName
        #add run synchronous commands
        WriteInfoHighlighted "`t Adding Sync Commands"
        $RunSynchronous=""
        if ($VMConfig.EnableWinRM){
            $RunSynchronous+=@'
            <RunSynchronousCommand wcm:action="add">
                <Path>cmd.exe /c winrm quickconfig -q -force</Path>
                <Description>enable winrm</Description>
                <Order>1</Order>
            </RunSynchronousCommand>

'@
            WriteInfo "`t `t WinRM will be enabled"
        }
		
        if ($VMConfig.CustomPowerShellCommands){
            $Order=3
            foreach ($CustomPowerShellCommand in $VMConfig.CustomPowerShellCommands){
                $RunSynchronous+=@"
                <RunSynchronousCommand wcm:action="add">
                    <Path>powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command "$CustomPowerShellCommand"</Path>
                    <Description>run custom powershell</Description>
                    <Order>$Order</Order>
                </RunSynchronousCommand>

"@
                $Order++
            }
            WriteInfo "`t `t Custom PowerShell command will be added"
        }

        if (-not $RunSynchronous){
            WriteInfo "`t `t No sync commands requested"
        }
		

        #Create Unattend file
        if ($VMConfig.Unattend -eq "NoDjoin" -or $VMConfig.SkipDjoin){
            WriteInfo "`t Skipping Djoin"
            if ($VMConfig.AdditionalLocalAdmin){
                WriteInfo "`t Additional Local Admin $($VMConfig.AdditionalLocalAdmin) will be added"
                $AdditionalLocalAccountXML=AdditionalLocalAccountXML -AdditionalAdminName $VMConfig.AdditionalLocalAdmin -AdminPassword $LabConfig.AdminPassword
                $unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -RunSynchronous $RunSynchronous -AdditionalAccount $AdditionalLocalAccountXML -TimeZone $TimeZone
            }else{
                $unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -RunSynchronous $RunSynchronous -TimeZone $TimeZone
            }
        }elseif($VMConfig.Unattend -eq "DjoinBlob" -or -not ($VMConfig.Unattend)){
            WriteInfo "`t Creating Unattend with djoin blob"
            $path="c:\$vmname.txt"
            Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path,$Labconfig); djoin.exe /provision /domain $($labconfig.DomainName).Split(".")[0] /machine $Name /savefile $path } -ArgumentList $Name,$path,$Labconfig
            $blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); Remove-Item $path} -ArgumentList $path
            $unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword -RunSynchronous $RunSynchronous -TimeZone $TimeZone
        }elseif($VMConfig.Unattend -eq "None"){
            $unattendFile=$Null
        }

        #adding unattend to VHD
        if ($unattendFile){
            WriteInfo "`t Adding unattend to VHD"
			if(-not (Test-Path "$PSScriptRoot\Temp\mountdir")){New-Item -ItemType Directory "$PSScriptRoot\Temp\mountdir" -Force}
            Mount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -ImagePath $VHDPath -Index 1
            Use-WindowsUnattend -Path "$PSScriptRoot\Temp\mountdir" -UnattendPath $unattendFile 
            New-item -type directory $PSScriptRoot\Temp\Mountdir\Windows\Panther -ErrorAction Ignore
            Copy-Item $unattendfile $PSScriptRoot\Temp\Mountdir\Windows\Panther\unattend.xml
        }

        if ($unattendFile){
            Dismount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -Save
        }

    }
#endregion

#region Initialization

    Start-Transcript -Path "$PSScriptRoot\Deploy.log"

    $StartDateTime = get-date
    WriteInfoHighlighted "Script started at $StartDateTime"


    ##Load LabConfig....
        . "$PSScriptRoot\$configFile"

#endregion

#region Set variables

    #If (!$LabConfig.DomainName){
    #    WriteErrorAndExit "`t DomainName not detected. Exiting"
    #}


    $DN=$null
	if($LabConfig.DomainName)
	{
		$LabConfig.DomainName.Split(".") | ForEach-Object {
			$DN+="DC=$_,"
		}
		$LabConfig.DN=$DN.TrimEnd(",")
	}

    WriteInfoHighlighted "List of variables used"
    WriteInfo "`t Prefix used in lab is $($labconfig.prefix)"

    $SwitchName=($labconfig.prefix+$LabConfig.SwitchName)
    WriteInfo "`t Switchname is $SwitchName" 

    WriteInfo "`t Workdir is $PSScriptRoot"

    #Grab TimeZone
    $TimeZone=(Get-TimeZone).id

    #Grab number of processors
    (Get-CimInstance win32_processor).NumberOfLogicalProcessors  | ForEach-Object { $global:NumberOfLogicalProcessors += $_}

#endregion

#region Some Additional checks and prereqs configuration


	#Check if running inside Failover Cluster
	$isInCluster = $(if((Get-WMIObject -Class MSCluster_ResourceGroup -Namespace root\mscluster -ErrorAction SilentlyContinue) -ne $null){$true}else {$false})
	if($isInCluster)
	{
		$servers = Get-ClusterNode
	}
	else
	{
		$servers = "localhost"
	}
	

    # Checking for Compatible OS
        WriteInfoHighlighted "Checking if OS is Windows 10 1511 (10586)/Server 2016 or newer"
        $BuildNumber=Get-WindowsBuildNumber
        if ($BuildNumber -ge 10586){
            WriteSuccess "`t OS is Windows 10 1511 (10586)/Server 2016 or newer"
        }else{
            WriteErrorAndExit "`t Windows 10/ Server 2016 not detected. Exiting"
        }



    #Check if Hyper-V is installed
        WriteInfoHighlighted "Checking if Hyper-V is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq "Enabled"){
            WriteSuccess "`t Hyper-V is Installed"
        }else{
            WriteErrorAndExit "`t Hyper-V not installed. Please install hyper-v feature including Hyper-V management tools. Exiting"
        }

        WriteInfoHighlighted "Checking if Hyper-V Powershell module is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell).state -eq "Enabled"){
            WriteSuccess "`t Hyper-V is Installed"
        }else{
            WriteErrorAndExit "`t Hyper-V tools are not installed. Please install Hyper-V management tools. Exiting"
        }

    #Create Switches

        WriteInfoHighlighted "Creating Switch"
        WriteInfo "`t Checking if $SwitchName already exists..."

        if ((Get-VMSwitch -Name $SwitchName -ErrorAction Ignore) -eq $Null){
            WriteErrorAndExit "`t $SwitchName not exists. Exiting"
        }


    ####Testing if lab already exists.
    ###    WriteInfo "Testing if lab already exists."
	###	if ((Get-VM -ComputerName $servers  -Name ($LabConfig.DC) -ErrorAction SilentlyContinue) -ne $null){
	###		$LABExists=$True
	###		WriteInfoHighlighted "`t Lab already exists. If labconfig contains additional VMs, they will be added."
	###	}

    #Generate DSC Config
        if ($VMConfig.DSCMode -eq 'Pull'){
            WriteInfo "`t Setting DSC Mode to Pull"
            PullClientConfig -ComputerName $VMConfig.VMName -DSCConfig $VMConfig.DSCConfig -OutputPath "$PSScriptRoot\temp\dscconfig" -DomainName $LabConfig.DomainName
        }

	if($labconfig.DC)
	{
		$DC=Get-VM -ComputerName $servers -Name ($labconfig.DC) -ErrorAction SilentlyContinue
		
		if($DC)
		{
			#Credentials for Session
			$username = "$($($labconfig.DomainName).Split(".")[0])\$($Labconfig.DomainAdminName)"
			$password = $LabConfig.AdminPassword
			$secstr = New-Object -TypeName System.Security.SecureString
			$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
			$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
		}
	}
	
#endregion


#region Provision VMs

    #DSC config for LCM (in case Pull configuration is specified)
        WriteInfoHighlighted "Creating DSC config to configure DC as pull server"

        [DSCLocalConfigurationManager()]
        Configuration PullClientConfig 
        {
            param
                (
                    [Parameter(Mandatory=$true)]
                    [string[]]$ComputerName,

                    [Parameter(Mandatory=$true)]
                    [string[]]$DSCConfig,

                    [Parameter(Mandatory=$true)]
                    [string[]]$DomainName
                )
            Node $ComputerName {
                Settings{

                    AllowModuleOverwrite = $True
                    ConfigurationMode = 'ApplyAndAutoCorrect'
                    RefreshMode = 'Pull'
                    RebootNodeIfNeeded = $True
                    ActionAfterReboot = 'ContinueConfiguration'
                    }

                    ConfigurationRepositoryWeb PullServerWeb { 
                    ServerURL = "http://$($LabConfig.DC).$($DomainName):8080/PSDSCPullServer.svc"
                    AllowUnsecureConnection = $true
                    RegistrationKey = '14fc8e72-5036-4e79-9f89-5382160053aa'
                    ConfigurationNames = $DSCConfig
                    }

                    ReportServerWeb PullServerReports {
                    ServerURL = "http://$($LabConfig.DC).$($DomainName):8080/PSDSCPullServer.svc"
                    RegistrationKey = '14fc8e72-5036-4e79-9f89-5382160053aa'
                    }

                    $DSCConfig | ForEach-Object {
                        PartialConfiguration $_
                        {
                        RefreshMode = 'Pull'
                        ConfigurationSource = '[ConfigurationRepositoryWeb]PullServerWeb'
                        }
                    }
            }
        }


    #process $labconfig.VMs and create VMs (skip if machine already exists)
        WriteInfoHighlighted 'Processing $LabConfig.VMs, creating VMs'
        foreach ($VMConfig in $LABConfig.VMs.GetEnumerator()){
            if (!(Get-VM -ComputerName $servers  -Name "$($VMConfig.vmname)" -ErrorAction SilentlyContinue)){
                # Ensure that Configuration is set and use Simple as default
                if(-not $VMConfig.configuration) {
                    $VMConfig.configuration = "Simple"
                }

                #create VM with Simple configuration
                    if ($VMConfig.configuration -eq 'Simple'){
                        BuildVM -VMConfig $($VMConfig) -LabConfig $labconfig
						
						#compose VM name
                            $VMname=$VMConfig.VMName
						#add "HDDs"
                                If (($VMConfig.HDDNumber -ge 1) -and ($VMConfig.HDDNumber -ne $null)) {
                                    $HDDs= 1..$VMConfig.HDDNumber | ForEach-Object { New-VHD -Path "$($VMConfig.csvPath)\$VMname\Virtual Hard Disks\HDD-$_.VHDX" -Dynamic -Size $VMConfig.HDDSize}
                                    WriteInfoHighlighted "`t Adding Virtual HDD Disks"
                                    $HDDs | ForEach-Object {
                                        $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                        Add-VMHardDiskDrive -Path $_.path -VMName $VMname
                                        WriteInfo "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                                    }
                                }
                    }

                #create VM with S2D configuration 
                    if ($VMConfig.configuration -eq 'S2D'){
                        #build VM
                            BuildVM -VMConfig $VMConfig -LabConfig $labconfig
                        #compose VM name
                            $VMname=$VMConfig.VMName

                        #Add disks
                            #add "SSDs"
                                If (($VMConfig.SSDNumber -ge 1) -and ($VMConfig.SSDNumber -ne $null)){         
                                    $SSDs= 1..$VMConfig.SSDNumber | ForEach-Object { New-vhd -Path "$csvPath\$VMname\Virtual Hard Disks\SSD-$_.VHDX" -Dynamic -Size $VMConfig.SSDSize}
                                    WriteInfoHighlighted "`t Adding Virtual SSD Disks"
                                    $SSDs | ForEach-Object {
                                        $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                        Add-VMHardDiskDrive -Path $_.path -VMName $VMname
                                        WriteInfo "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                                    }
                                }
                            #add "HDDs"
                                If (($VMConfig.HDDNumber -ge 1) -and ($VMConfig.HDDNumber -ne $null)) {
                                    $HDDs= 1..$VMConfig.HDDNumber | ForEach-Object { New-VHD -Path "$csvPath\$VMname\Virtual Hard Disks\HDD-$_.VHDX" -Dynamic -Size $VMConfig.HDDSize}
                                    WriteInfoHighlighted "`t Adding Virtual HDD Disks"
                                    $HDDs | ForEach-Object {
                                        $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                        Add-VMHardDiskDrive -Path $_.path -VMName $VMname
                                        WriteInfo "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                                    }
                                }
                    }


            }
			else
			{
				WriteSuccess "`t$($VMConfig.vmname) already exists."
			}
        }

#endregion

#region Finishing
    WriteInfoHighlighted "Finishing..." 

    #a bit cleanup
        if(Test-Path "$PSScriptRoot\temp") {
			Remove-Item -Path "$PSScriptRoot\temp" -Force -Recurse
		}
        if (Test-Path "$PSScriptRoot\unattend.xml") {
            remove-item "$PSScriptRoot\unattend.xml"
        }

    #list VMs 
        Get-VM -ComputerName $servers  | Where-Object name -like "$($labconfig.Prefix)*"  | Where-Object {$_.Name -in $LABConfig.VMs.VMName} | ForEach-Object { WriteSuccess "Machine $($_.VMName) provisioned" }

    #write how much it took to deploy
        WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

    Stop-Transcript

    WriteSuccess "Press enter to continue ..."
    Read-Host | Out-Null
#endregion
