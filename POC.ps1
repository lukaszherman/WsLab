param (
    [parameter(Mandatory=$true)]
    [string]
    $configFile
    )

# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -configFile $configFile" -Verb RunAs 
    exit
}

#region Functions

    function WriteInfo($message){
        Write-Host "$(Get-Date):: $message"
    }

    function WriteInfoHighlighted($message){
        Write-Host "$(Get-Date):: $message" -ForegroundColor Cyan
    }

    function WriteSuccess($message){
        Write-Host "$(Get-Date):: $message" -ForegroundColor Green
    }

    function WriteWarning($message) {
        Write-Host "$(Get-Date):: $message" -ForegroundColor Yellow
    }

    function WriteError($message){
        Write-Host "$(Get-Date):: $message" -ForegroundColor Red
    }

    function WriteErrorAndExit($message){
        Write-Host "$(Get-Date):: $message" -ForegroundColor Red
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
      <RegisteredOwner>TakieTam</RegisteredOwner>
      <RegisteredOrganization>TakieTam</RegisteredOrganization>
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
        <RegisteredOwner>TakieTam</RegisteredOwner>
          <RegisteredOrganization>TakieTam</RegisteredOrganization>
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
			
		if ($null -eq $serverparent){
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
        If($null -eq $MGMTNICs){
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
        if ($null -ne $VMConfig.MemoryMinimumBytes){
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
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($localAdminPassword)
        $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        if ($VMConfig.Unattend -eq "NoDjoin" -or $VMConfig.SkipDjoin){
            WriteInfo "`t Skipping Djoin"
            if ($VMConfig.AdditionalLocalAdmin){
                WriteInfo "`t Additional Local Admin $($VMConfig.AdditionalLocalAdmin) will be added"
                $AdditionalLocalAccountXML=AdditionalLocalAccountXML -AdditionalAdminName $VMConfig.AdditionalLocalAdmin -AdminPassword $UnsecurePassword
                $unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $UnsecurePassword -RunSynchronous $RunSynchronous -AdditionalAccount $AdditionalLocalAccountXML -TimeZone $TimeZone
            }else{
                $unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $UnsecurePassword -RunSynchronous $RunSynchronous -TimeZone $TimeZone
            }
        }elseif($VMConfig.Unattend -eq "DjoinBlob" -or -not ($VMConfig.Unattend)){
            WriteInfo "`t Creating Unattend with djoin blob"
            $path="c:\$vmname.txt"
            Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path,$Labconfig); djoin.exe /provision /domain $($labconfig.DomainName).Split(".")[0] /machine $Name /savefile $path } -ArgumentList $Name,$path,$Labconfig
            $blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); Remove-Item $path} -ArgumentList $path
            $unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $UnsecurePassword -RunSynchronous $RunSynchronous -TimeZone $TimeZone
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

    $DN=$null
	if($LabConfig.DomainName)
	{
		$LabConfig.DomainName.Split(".") | ForEach-Object {
			$DN+="DC=$_,"
		}
		$LabConfig.DN=$DN.TrimEnd(",")
	}

    WriteInfoHighlighted "List of variables used"
    if($labconfig.prefix){WriteInfo "`t Prefix used in lab is $($labconfig.prefix)"}

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
	$isInCluster = $(if($null -ne (Get-CimInstance -NameSpace 'root\mscluster' -Class "MSCluster_ResourceGroup" -ErrorVariable ProcessError -ErrorAction SilentlyContinue)){$true}else {$false})
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

        if ($Null -eq (Get-VMSwitch -Name $SwitchName -ErrorAction Ignore)){
            WriteErrorAndExit "`t $SwitchName not exists. Exiting"
        }

    #Generate DSC Config
        if ($VMConfig.DSCMode -eq 'Pull'){
            WriteInfo "`t Setting DSC Mode to Pull"
            PullClientConfig -ComputerName $VMConfig.VMName -DSCConfig $VMConfig.DSCConfig -OutputPath "$PSScriptRoot\temp\dscconfig" -DomainName $LabConfig.DomainName
        }

	if($labconfig.DC){
		$DC=Get-VM -Name ($labconfig.DC) -ErrorAction SilentlyContinue
		
		if($DC){
			#Credentials for Session
            WriteSuccess "`t Domain Controller $($labconfig.DC) found on local hyper-v node"

			$username = "$($($labconfig.DomainName).Split(".")[0])\$($Labconfig.DomainAdminName)"
            if(-Not $LabConfig.DomainAdminPassword){
                $password = Read-Host "Enter domain admin password" -AsSecureString
            }
            else {
                $password = $LabConfig.DomainAdminPassword
            }
			
			$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $password

            WriteInfo "`t Checking connectivity and login/password validation for domain controller $($DC.Name)"
            Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock{Write-Host $env:computername} -ErrorVariable WrongPassword
            if ($null -eq $WrongPassword)
            {
                WriteErrorAndExit $WrongPassword
            }
		}
        else {
            WriteErrorAndExit "Domain controller $($labconfig.DC) not found on $($env:computername) (Check the name or migrate it to current host)"
        }
	}

    WriteInfo "`t Set local admin password for new unattended VMs"
    $localAdminPassword = Read-Host "Enter defaul local admin password" -AsSecureString
	
#endregion


#region Provision VMs

    #process $labconfig.VMs and create VMs (skip if machine already exists)
        $vmCreated = @()
        WriteInfoHighlighted 'Processing $LabConfig.VMs, creating VMs'
        foreach ($VMConfig in $LABConfig.VMs.GetEnumerator()){
            if (!(Get-VM -ComputerName $servers  -Name "$($VMConfig.vmname)" -ErrorAction SilentlyContinue)){

                #create VM 
                BuildVM -VMConfig $($VMConfig) -LabConfig $labconfig
                
                #compose VM name
                $VMname=$VMConfig.VMName
                #add "HDDs"
                If (($VMConfig.HDDNumber -ge 1) -and ($null -ne $VMConfig.HDDNumber)) {
                    $HDDs= 1..$VMConfig.HDDNumber | ForEach-Object { New-VHD -Path "$($VMConfig.csvPath)\$VMname\Virtual Hard Disks\HDD-$_.VHDX" -Dynamic -Size $VMConfig.HDDSize}
                    WriteInfoHighlighted "`t Adding Virtual HDD Disks"
                    $HDDs | ForEach-Object {
                        $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                        Add-VMHardDiskDrive -Path $_.path -VMName $VMname
                        WriteInfo "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                    }
                }

                #configure HostResourceProtection on all VM CPUs
                WriteInfo "`t Configuring EnableHostResourceProtection on $($VMConfig.VMName) VM processors"
                Set-VMProcessor -EnableHostResourceProtection $true -VMName $VMConfig.VMName -ErrorAction SilentlyContinue

                if($VMConfig.CpuPriority){
                    WriteInfo "`t Configuring CpuPriority ($($VMConfig.CpuPriority)) on $($VMConfig.VMName) VM processors"
                    Set-VMProcessor -RelativeWeight $VMConfig.CpuPriority -VMName $VMConfig.VMName -ErrorAction SilentlyContinue
                }

                if($isInCluster){
                    # Add as cluster resource and move to best node
                    WriteInfo "`t Add $($VMConfig.VMName) to Hyper-V Cluster"
                    Add-ClusterVirtualMachineRole -VirtualMachine $VMConfig.VMName
                    WriteInfo "`t Move $($VMConfig.VMName) to best possible node"
                    Move-ClusterVirtualMachineRole -Name $VMConfig.VMName -MigrationType Quick

                    # Set VM priority
                    #  High (3000)
                    #  Medium (2000): The default setting
                    #  Low (1000)
                    #  No Auto Start (0)
                    $vmPriority = $VMConfig.HyperVPriority
                    if( $vmPriority -eq "Low" ){
                        (Get-ClusterGroup $VMConfig.VMName).Priority=1000
                        WriteInfo "`t VM priority set to Low for VM $($VMConfig.VMName)"
                    } elseif( $vmPriority -eq "High" ){
                        (Get-ClusterGroup $VMConfig.VMName).Priority=3000
                        WriteInfo "`t VM priority set to High for VM $($VMConfig.VMName)"
                    } elseif( $vmPriority  -is [int] ){
                        (Get-ClusterGroup $VMConfig.VMName).Priority=$vmPriority
                        WriteInfo "`t VM priority set to $vmPriority for VM $($VMConfig.VMName)"
                    } else {
                        WriteInfo "`t Leaving default VM priority for $($VMConfig.VMName)"
                    }
                }

                $vmCreated += $VMConfig.VMName
            }
			else
			{
				WriteSuccess "$($VMConfig.vmname) already exists."
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

    #write how much it took to deploy
        WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"


    WriteSuccess "Press enter to start VMs and change to static MACs ..."
    Read-Host | Out-Null

    #region Startup
        #start all vms and check for MAC addressess conflicts, set static MACs
        $StartDateTime = get-date
        WriteInfoHighlighted "VM startup started at $StartDateTime"

        WriteInfo "Gathering data about new VMs"
        $VMs = Get-VM -ComputerName $servers -Name $vmCreated -ErrorAction SilentlyContinue

        # starting VMs
        WriteInfo "Starting new VMs"
        foreach($vm in $VMs)
        {
            if($vm.State -eq "Off")
            {
                WriteInfo "Starting VM $($vm.Name)"
                Start-VM $vm
                WriteInfo "Waiting 5 second to perform next VM"
                Start-Sleep -Seconds 5
            } 
            else {
                WriteInfo "VM $($vm.Name)) is in $($vm.State) state"
            }
        }

        if($LabConfig.MacAddressesCheckClusters)
        {

            # Waiting to start all VMs
            $uptimeCondition = 5
            WriteInfo "Waiting till all started VMs will have uptime at least $uptimeCondition minutes."
            foreach($vm in $VMs)
            {
                WriteInfo "Checking uptime for $($vm.Name) ($($vm.ComputerName))"
                while($vm.Uptime.TotalMinutes -lt $uptimeCondition)
                {
                    WriteInfo "$($vm.Name) ($($vm.ComputerName)) uptime is $($vm.Uptime.TotalMinutes) minutes. Sleeping for 30 seconds..."
                    Start-Sleep -Seconds 30
                }
            }

            WriteInfo "MAC addresses check started"
            # Check MAC addresses conflicts
            do {
                $repeatCheck = $False
                $allVmsMAC = @()

                WriteInfo "Gathering data about new VMs"
                $VMs = Get-VM -ComputerName $servers -Name $vmCreated -ErrorAction SilentlyContinue

                foreach($cl in $LabConfig.MacAddressesCheckClusters)
                {
                    WriteInfo "Gathering data from $cl"
                    foreach($server in (Get-ClusterNode -Cluster $cl))
                    {
                        Invoke-Command -ComputerName $server -ScriptBlock{get-VM | Get-VMNetworkAdapter | SELECT VMName, MacAddress,IPAddresses} -AsJob
                    }
                }

                WriteInfo "Waiting for jobs completions"
                $allVmsMAC += (Get-Job | Wait-Job | Receive-Job)
                Get-Job | Remove-Job 
                
                WriteInfo "Looking for MAC conflicts"
                $allVmsMACUnique = $allVmsMAC.MacAddress | Select-Object -Unique
                $duplicatedMacs = Compare-Object -ReferenceObject $allVmsMAC.MacAddress -DifferenceObject $allVmsMACUnique
                $duplicatedMacs = $duplicatedMacs | ForEach-Object {$_.InputObject}
                $allVmsMAC | ForEach-Object {if($_.MacAddress -in $duplicatedMacs) {Write-Host "$($_.MacAddress) `t$($_.VmName) `t$($_.IPAddresses)"}}
                
                $repeatCheck = $VMs | Get-VMNetworkAdapter | ForEach-Object { if($_.MacAddress -in $duplicatedMacs) {
                        Write-Host "Solving MAC conflict for $($_.MacAddress) `t$($_.VmName) `t$($_.IPAddresses)"
                        WriteInfo "$($_.VmName) shutting down"
                        stop-vm $_.VmName -ComputerName $servers
                        WriteInfo "`t Move $($_.VmName) to best possible node"
                        Move-ClusterVirtualMachineRole -Name $_.VmName -MigrationType Quick
                        WriteInfo "$($_.VmName) starting"
                        start-vm $_.VmName -ComputerName $servers
                        WriteInfo "$($_.VmName) started"
                        return $True
                    }
                }
            } while ($repeatCheck)

            WriteInfo "MAC addresses check finished. Changing to static MAC addresses"

            # changing MAC address to static
            foreach($vm in $VMs)
            {
                $MacAddress = $vm | Get-VMNetworkAdapter | where-object {$_.DynamicMacAddressEnabled -eq $True}
	            if($MacAddress)
                {
                    WriteInfo "$($vm.name) shutting down"
                    $vm | stop-vm
                    WriteInfo "$($vm.name) changing to static MAC address."
                    $vm | Set-VMNetworkAdapter -StaticMacAddress $MacAddress.MacAddress
                    WriteInfo "$($vm.name) starting"
                    $vm | start-vm
                    WriteInfo "$($vm.name) started"
                }
            }
        }
        
        #write how much it took to deploy
        WriteInfo "Startup finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

    #endregion

    Stop-Transcript
    
    WriteSuccess "Press enter to continue ..."
    Read-Host | Out-Null
#endregion
