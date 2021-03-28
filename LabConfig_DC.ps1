$LabConfig=@{
	DomainAdminName='Administrator'; 
	AdminPassword='Demo.123';
	
	SwitchName = 'PocSwitchTest';
}

$csv = "D:\HyperV"
$netIpAddress = "192.168.123"

$win2019gui = 'Win2019_GUI_Standard_2021_02.vhdx'
$win2019core = 'Win2019_CORE_Datacenter_2021_02.vhdx'

$rdp = "reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f > Unattend_remoteDesktop.log"
$telnet = "dism /online /Enable-Feature /FeatureName:TelnetClient > Unattend_dismTelnet.log"
$rdpFirewall = "Netsh advfirewall firewall set rule group='remote desktop' new enable=yes > Unattend_RdpFirewall.log"


$LABConfig.VMs += ,@{
	VMName = "POC123-DC" ; 
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
