# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

$LabConfig=@{ 
	DomainAdminName='Administrator'; 
	AdminPassword='Demo.123'; 
	SwitchName = 'PocSwitch'; 
	DCEdition='4'; Internet=$true; 
	DomainNetbiosName='POC'; 
	DomainName='POC.local'; 
	DC='POC-DC';
	AdditionalNetworksConfig=@(); VMs=@()
}

$csv = "C:\HyperV"
$dns = @("192.168.0.100")
$netIpAddress = "192.168.0"
$subnet24 = "255.255.255.0"
$gw = "192.168.0.1"
$rdp = "reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f > Unattend_remoteDesktop.log"
$telnet = "dism /online /Enable-Feature /FeatureName:TelnetClient > Unattend_dismTelnet.log"
$rdpFirewall = "Netsh advfirewall firewall set rule group='remote desktop' new enable=yes > Unattend_RdpFirewall.log"
$win2019gui = 'Win2019_GUI_Standard_2021_02.vhdx'
$win2019core = 'Win2019_CORE_Datacenter_2021_02.vhdx'


$LABConfig.VMs += @{
	VMName = "POC-DC" ; 
    ParentVHD = $win2019gui; 
	HDDNumber = 1; HDDSize= 16GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 1024MB ; MaximumBytes= 16384MB ;
	CsvPath = $csv ; 
	Unattend="NoDjoin" ; 
	IP = "${netIpAddress}.100"; Subnet = $subnet24; DNS = "1.1.1.1"; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}



$LABConfig.VMs += @{ 
	VMName = "POC-SOFS1A" ; 
    ParentVHD = $win2019core; 
	HDDNumber = 2; HDDSize= 150GB ; 
	VMProcessorCount = 1 ; 
	MemoryStartupBytes= 2048MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.111"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}
$LABConfig.VMs += @{ 
	VMName = "POC-SOFS1B" ; 
    ParentVHD = $win2019core; 
	HDDNumber = 2; HDDSize= 150GB ; 
	VMProcessorCount = 1 ; 
	MemoryStartupBytes= 2048MB ; 
	CsvPath = $csv ; 
	IP = "${netIpAddress}.112"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}
$LABConfig.VMs += @{ 
	VMName = "POC-SOFS1C" ; 
    ParentVHD = $win2019core; 
	HDDNumber = 2; HDDSize= 150GB ; 
	VMProcessorCount = 1 ; 
	MemoryStartupBytes= 2048MB ; 
	CsvPath = $csv ; 
	IP = "${netIpAddress}.113"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}

$LABConfig.VMs += @{ 
	VMName = "POC-DB01A" ; 
    ParentVHD = $win2019core; 
	HDDNumber = 1; HDDSize= 64GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 2048MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.121"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}
$LABConfig.VMs += @{ 
	VMName = "POC-DB01B" ; 
    ParentVHD = $win2019core; 
	HDDNumber = 1; HDDSize= 64GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 2048MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.122"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}



<# $LABConfig.VMs += @{ 
	VMName = "POC-DB02A" ; 
    ParentVHD = $win2019core; 
	HDDNumber = 1; HDDSize= 64GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 2048MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.131"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}
$LABConfig.VMs += @{ 
	VMName = "POC-DB02B" ; 
    ParentVHD = $win2019core; 
	HDDNumber = 1; HDDSize= 64GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 2048MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.132"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
} #>


$LABConfig.VMs += @{ 
	VMName = "POC-WAC" ; 
    ParentVHD = $win2019gui; 
	HDDNumber = 1; HDDSize= 16GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 1024MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.101"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}


<# $LABConfig.VMs += @{ 
	VMName = "POC-Jenkins1" ; 
    ParentVHD = $win2019gui; 
	HDDNumber = 1; HDDSize= 16GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 1024MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.102"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}
$LABConfig.VMs += @{ 
	VMName = "POC-Jenkins2" ; 
    ParentVHD = $win2019gui; 
	HDDNumber = 1; HDDSize= 16GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 1024MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.103"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}
$LABConfig.VMs += @{ 
	VMName = "POC-Jenkins3" ; 
    ParentVHD = $win2019gui; 
	HDDNumber = 1; HDDSize= 16GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 1024MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.104"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}
$LABConfig.VMs += @{ 
	VMName = "POC-Jenkins4" ; 
    ParentVHD = $win2019gui; 
	HDDNumber = 1; HDDSize= 16GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 1024MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.105"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
} #>
$LABConfig.VMs += @{ 
	VMName = "POC-Jenkins5" ; 
    ParentVHD = $win2019gui; 
	HDDNumber = 1; HDDSize= 16GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 1024MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.106"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}

$LABConfig.VMs += @{ 
	VMName = "POC-ARR1" ; 
    ParentVHD = $win2019gui; 
	HDDNumber = 1; HDDSize= 16GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 1024MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.141"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}


$LABConfig.VMs += @{ 
	VMName = "POC-AP1" ; 
    ParentVHD = $win2019core; 
	HDDNumber = 1; HDDSize= 16GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 1024MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.151"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}

$LABConfig.VMs += @{ 
	VMName = "POC-AP2" ; 
    ParentVHD = $win2019core; 
	HDDNumber = 1; HDDSize= 16GB ; 
	VMProcessorCount = 2 ; 
	MemoryStartupBytes= 1024MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.152"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}



$LABConfig.VMs += @{ 
	VMName = "POC-DevOps1" ; 
    ParentVHD = $win2019gui; 
	HDDNumber = 1; HDDSize= 64GB ; 
	VMProcessorCount = 3 ; 
	MemoryStartupBytes= 2048MB ;
	CsvPath = $csv ; 
	IP = "${netIpAddress}.199"; Subnet = $subnet24; DNS = $dns; DefaultGateway = $gw;
	CustomPowerShellCommands=`
        $rdp, `
        $telnet,`
        $rdpFirewall
}