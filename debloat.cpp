#include <iostream>
#include <cstdlib>
#include <string>

using namespace std;

int main(){

	bool choiceMade = false;
	string checkpoint, choice;
	
	cout << "Make sure your PC has downloaded every update from Windows Update and Microsoft Store before running this\n";
	cout << "Checkpoint code? If the script is running for the first time enter \'0\'\n";
	
	while (!choiceMade)
	
	{
		getline (cin, checkpoint);
		
		if (checkpoint == "0")
		
		{
			choiceMade = true;
			cout << "Remove Windows Defender? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v SmartScreenEnabled /t REG_SZ /d \"Off\" /f");
				system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AppHost\" /v \"EnableWebContentEvaluation\" /t REG_DWORD /d \"0\" /f");
				system("reg add \"HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\PhishingFilter\" /v \"EnabledV9\" /t REG_DWORD /d \"0\" /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\" /v SpyNetReporting /t REG_DWORD /d 0 /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f");
				system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sense\" /f");
				system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService\" /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\MRT\" /v \"DontReportInfectionInformation\" /t REG_DWORD /d 1 /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\MRT\" /v \"DontOfferThroughWUAU\" /t REG_DWORD /d 1 /f");
				system("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"SecurityHealth\" /f");
				system("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run\" /v \"SecurityHealth\" /f");
				system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SecHealthUI.exe\" /v Debugger /t REG_SZ /d \"%windir%\\System32\\taskkill.exe\" /f");
				system("install_wim_tweak /o /c Windows-Defender /r");
			}
			
			cout << "Remove Windows Store? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("powershell -command \"Get-AppxPackage -AllUsers *store* | Remove-AppxPackage\"");
				system("install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r");
				system("install_wim_tweak /o /c Microsoft-Windows-Store /r");
				system("reg add \"HKLM\\Software\\Policies\\Microsoft\\WindowsStore\" /v RemoveWindowsStore /t REG_DWORD /d 1 /f");
				system("reg add \"HKLM\\Software\\Policies\\Microsoft\\WindowsStore\" /v DisableStoreApps /t REG_DWORD /d 1 /f");
				system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AppHost\" /v \"EnableWebContentEvaluation\" /t REG_DWORD /d 0 /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\PushToInstall\" /v DisablePushToInstall /t REG_DWORD /d 1 /f");
				system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f");
				system("sc delete PushToInstall");
			}
			
			cout << "Remove Music, TV...? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
				system("powershell -command \"Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage\"");
				
			cout << "Remove Xbox and Game DVR? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("powershell -command \"Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage\"");
				system("sc delete XblAuthManager");
				system("sc delete XblGameSave");
				system("sc delete XboxNetApiSvc");
				system("sc delete XboxGipSvc");
				system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\xbgm\" /f");
				system("schtasks /Change /TN \"Microsoft\\XblGameSave\\XblGameSaveTask\" /disable");
				system("schtasks /Change /TN \"Microsoft\\XblGameSave\\XblGameSaveTaskLogon\" /disable");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\" /v AllowGameDVR /t REG_DWORD /d 0 /f");
			}
			
			cout << "Remove Sticky Notes? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
				system("powershell -command \"Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage\"");
			
			cout << "Remove Maps? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("powershell -command \"Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage\"");
				system("sc delete MapsBroker");
				system("sc delete lfsvc");
				system("schtasks /Change /TN \"\Microsoft\\Windows\\Maps\\MapsUpdateTask\" /disable");
			}
			
			cout << "Remove Alarms and Clock? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
				system("powershell -command \"Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage\"");
				system("powershell -command \"Get-AppxPackage -AllUsers *people* | Remove-AppxPackage\"");
			
			cout << "Remove Mail, Calendar? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
				system("powershell -command \"Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage\"");
				system("powershell -command \"Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage\"");
			
			cout << "Remove OneNote? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
				system("powershell -command \"Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage\"");
				system("powershell -command \"Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage\"");
			
			cout << "Remove Photos? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
				system("powershell -command \"Get-AppxPackage -AllUsers *photo* | Remove-AppxPackage\"");
				
			cout << "Remove Camera? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
				system("powershell -command \"Get-AppxPackage -AllUsers *camera* | Remove-AppxPackage\"");
				
			cout << "Remove Weather, News...? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
				system("powershell -command \"Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage\"");
			
			cout << "Remove Calculator? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
				system("powershell -command \"Get-AppxPackage -AllUsers *calc* | Remove-AppxPackage\"");
			
			cout << "Remove Sound Recorder? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
				system("powershell -command \"Get-AppxPackage -AllUsers *soundrec* | Remove-AppxPackage\"");
			
			cout << "Remove Microsoft Edge? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("install_wim_tweak /o /c Microsoft-Windows-Internet-Browser /r");
				system("install_wim_tweak /o /c Adobe-Flash /r");
			}
			
			cout << "Remove Contact Support, Get Help? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r");
				system("powershell -command \"Get-AppxPackage *GetHelp* | Remove-AppxPackage\"");
			}
			
			cout << "Remove Connect? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
				system("install_wim_tweak /o /c Microsoft-PPIProjection-Package /r");
			
			cout << "Disable system restore? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("powershell -command \"Disable-ComputerRestore -Drive \"C:\\\"\"");
				system("powershell -command \"vssadmin delete shadows /all /Quiet\"");
				system("powershell -command \"reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore\" /v \"DisableConfig\" /t \"REG_DWORD\" /d \"1\" /f\"");
				system("powershell -command \"reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore\" /v \"DisableSR \" /t \"REG_DWORD\" /d \"1\" /f\"");
				system("powershell -command \"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" /v \"DisableConfig\" /t \"REG_DWORD\" /d \"1\" /f\"");
				system("powershell -command \"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" /v \"DisableSR \" /t \"REG_DWORD\" /d \"1\" /f\"");
			}
			
			cout << "Reboot Windows, rerun the script and enter \'1\'\n";
		}

		else if (checkpoint == "1")
		
		{
			choiceMade = true;
			cout << "Turn off Windows error reporting? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\" /v Disabled /t REG_DWORD /d 1 /f");
				system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\" /v Disabled /t REG_DWORD /d 1 /f");
			}
			
			cout << "Disable forced updates? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" /v NoAutoUpdate /t REG_DWORD /d 0 /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" /v AUOptions /t REG_DWORD /d 2 /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" /v ScheduledInstallDay /t REG_DWORD /d 0 /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" /v ScheduledInstallTime /t REG_DWORD /d 3 /f");
			}
			
			cout << "Remove OneDrive? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("taskkill /F /IM onedrive.exe");
				cout << "32bit or 64bit Windows? 32/64 ";
				getline (cin, choice);
				
				while (choice != "32" && choice != "64")
				
				{
					cout << "Insert \"32\" or \"64\": ";
					getline (cin, choice);
				}
				
				if (choice == "32")
					system("\"%SYSTEMROOT%\\System32\\OneDriveSetup.exe\" /uninstall");
				
				else if (choice == "64")
					system("\"%SYSTEMROOT%\\SysWOW64\\OneDriveSetup.exe\" /uninstall");
				
				system("rd \"%USERPROFILE%\\OneDrive\" /Q /S");
				system("rd \"C:\\OneDriveTemp\" /Q /S");
				system("rd \"%LOCALAPPDATA%\\Microsoft\\OneDrive\" /Q /S");
				system("rd \"%PROGRAMDATA%\\Microsoft OneDrive\" /Q /S");
				system("reg delete \"HKEY_CLASSES_ROOT\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\" /f");
				system("reg delete \"HKEY_CLASSES_ROOT\\Wow6432Node\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\" /f");
				system("del /Q /F \"%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe\"");
			}
			
			cout << "Remove telemetry and other unnecessary services? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("sc delete DiagTrack");
				system("sc delete dmwappushservice");
				system("sc delete WerSvc");
				system("sc delete OneSyncSvc");
				system("sc delete MessagingService");
				system("sc delete wercplsupport");
				system("sc delete PcaSvc");
				system("sc delete InstallService");
				system("sc config wlidsvc start=demand");
				system("sc delete wisvc");
				system("sc delete RetailDemo");
				system("sc delete diagsvc");
				system("sc delete shpamsvc");
				system("for /f \"tokens=1\" %I in (\'reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\" /k /f \"wscsvc\" ^| find /i \"wscsvc\"\"); do (reg delete %I /f)");
				system("for /f \"tokens=1\" %I in (\'reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\" /k /f \"OneSyncSvc\" ^| find /i \"OneSyncSvc\"\"); do (reg delete %I /f)");
				system("for /f \"tokens=1\" %I in (\'reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\" /k /f \"MessagingService\" ^| find /i \"MessagingService\"\"); do (reg delete %I /f)");
				system("for /f \"tokens=1\" %I in (\'reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\" /k /f \"PimIndexMaintenanceSvc\" ^| find /i \"PimIndexMaintenanceSvc\"\"); do (reg delete %I /f)");
				system("for /f \"tokens=1\" %I in (\'reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\" /k /f \"UserDataSvc\" ^| find /i \"UserDataSvc\"\"); do (reg delete %I /f)");
				system("for /f \"tokens=1\" %I in (\'reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\" /k /f \"UnistoreSvc\" ^| find /i \"UnistoreSvc\"\"); do (reg delete %I /f)");
				system("for /f \"tokens=1\" %I in (\'reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\" /k /f \"BcastDVRUserService\" ^| find /i \"BcastDVRUserService\"\"); do (reg delete %I /f)");
				system("for /f \"tokens=1\" %I in (\'reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\" /k /f \"Sgrmbroker\" ^| find /i \"Sgrmbroker\"\"); do (reg delete %I /f)");
				system("sc delete diagnosticshub.standardcollector.service");
				system("reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Siuf\\Rules\" /v \"NumberOfSIUFInPeriod\" /t REG_DWORD /d 0 /f");
				system("reg delete \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Siuf\\Rules\" /v \"PeriodInNanoSeconds\" /f");
				system("reg add \"HKLM\\SYSTEM\\ControlSet001\\Control\\WMI\\AutoLogger\\AutoLogger-Diagtrack-Listener\" /v Start /t REG_DWORD /d 0 /f");
				system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v AITEnable /t REG_DWORD /d 0 /f");
				system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v DisableInventory /t REG_DWORD /d 1 /f");
				system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v DisablePCA /t REG_DWORD /d 1 /f");
				system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v DisableUAR /t REG_DWORD /d 1 /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter\" /v \"EnabledV9\" /t REG_DWORD /d 0 /f");
				system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v \"EnableSmartScreen\" /t REG_DWORD /d 0 /f");
				system("reg add \"HKCU\\Software\\Microsoft\\Internet Explorer\\PhishingFilter\" /v \"EnabledV9\" /t REG_DWORD /d 0 /f");
				system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\CompatTelRunner.exe\" /v Debugger /t REG_SZ /d \"%windir%\\System32\\taskkill.exe\" /f");
			}
			
			cout << "Disable sync? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\SettingSync\" /v DisableSettingSync /t REG_DWORD /d 2 /f");
				system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\SettingSync\" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f");
			}
			
			cout << "Remove unnecessary scheduled tasks? y/n ";
			getline (cin, choice);
			
			while (choice != "n" && choice != "y")
			
			{
				cout << "Insert \"y\" or \"n\": ";
				getline (cin, choice);
			}
			
			if (choice == "y")
			
			{
				system("schtasks /Change /TN \"Microsoft\\Windows\\AppID\\SmartScreenSpecific\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\AitAgent\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\StartupAppTask\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Autochk\\Proxy\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\CloudExperienceHost\\CreateObjectTask\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\BthSQM\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\Uploader\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\DiskFootprint\\Diagnostics\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\FileHistory\\File History (maintenance mode)\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Maintenance\\WinSAT\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\PI\\Sqm-Tasks\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Power Efficiency Diagnostics\\AnalyzeSystem\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Shell\\FamilySafetyMonitor\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Shell\\FamilySafetyRefresh\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Shell\\FamilySafetyUpload\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Windows Error Reporting\\QueueReporting\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\WindowsUpdate\\Automatic App Update\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\License Manager\\TempSignedLicenseExchange\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\WindowsUpdate\\Automatic App Update\" /disable");
				system("schtasks /Change /TN \"Microsoft\\Windows\\Clip\\License Validation\" /disable");
				system("schtasks /Change /TN \"\Microsoft\\Windows\\ApplicationData\\DsSvcCleanup\" /disable");
				system("schtasks /Change /TN \"\Microsoft\\Windows\\Power Efficiency Diagnostics\\AnalyzeSystem\" /disable");
				system("schtasks /Change /TN \"\Microsoft\\Windows\\PushToInstall\\LoginCheck\" /disable");
				system("schtasks /Change /TN \"\Microsoft\\Windows\\PushToInstall\\Registration\" /disable");
				system("schtasks /Change /TN \"\Microsoft\\Windows\\Shell\\FamilySafetyMonitor\" /disable");
				system("schtasks /Change /TN \"\Microsoft\\Windows\\Shell\\FamilySafetyMonitorToastTask\" /disable");
				system("schtasks /Change /TN \"\Microsoft\\Windows\\Shell\\FamilySafetyRefreshTask\" /disable");
				system("schtasks /Change /TN \"\Microsoft\\Windows\\Subscription\\EnableLicenseAcquisition\" /disable");
				system("schtasks /Change /TN \"\Microsoft\\Windows\\Subscription\\LicenseAcquisition\" /disable");
				system("del /F /Q \"C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SettingSync\\*\"");
			}
		}
		
		else
			cout << "Checkpoint not valid ";
			
	}
	
	return EXIT_SUCCESS;
}
