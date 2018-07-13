from subprocess import run
import os

dir_path = os.path.dirname(os.path.realpath(__file__))

print('Make sure your PC has downloaded every update from Windows Update and Microsoft Store before running this script')
print('Checkpoint code? If the script is running for the first time enter \'0\'')
choiceMade = False

while choiceMade == False:

	checkpoint = input()

	if checkpoint == '0':

		choiceMade = True
		print('Remove Windows Defender? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f')
			run('reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f')
			run('reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f')
			run('reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f')
			run('reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f')
			run('reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f')
			run('reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f')
			run('reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f')
			run('install_wim_tweak /o /c Windows-Defender /r') #AAAAAAAAAAAAAAAAAA

		print('Remove Windows Store? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			#POWERSHELL Get-AppxPackage -AllUsers *store* | Remove-AppxPackage
			run('install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r')
			run('install_wim_tweak /o /c Microsoft-Windows-Store /r')
			run('reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f')
			run('reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f')
			run('reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f')
			run('reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f')
			run('sc delete PushToInstall')

		print('Remove Music, TV...? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			print('POWERSHELL Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage')

		print('Xbox and Game DVR? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			#POWERSHELLGet-AppxPackage -AllUsers *xbox* | Remove-AppxPackage
			run('sc delete XblAuthManager')
			run('sc delete XblGameSave')
			run('sc delete XboxNetApiSvc')
			run('sc delete XboxGipSvc')
			run(r'reg delete "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /f')
			run('schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable')
			run('schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f')


		print('Remove Sticky Notes? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			print('POWERSHELL Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage')

		print('Remove Maps? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			#POWERSHELL Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage
			run('sc delete MapsBroker')
			run('sc delete lfsvc')
			run('schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable')
			

		print('Remove Alarms and Clock? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			print('POWERTSHELL Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage Get-AppxPackage -AllUsers *people* | Remove-AppxPackage')

		print('Remove Mail, Calendar...? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			print('POWERSHELL Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage')

		print('Remove OneNote? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			print('PS Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage')

		print('Remove Photos? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			print('Get-AppxPackage -AllUsers *photo* | Remove-AppxPackage')

		print('Remove Camera? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			print('PS Get-AppxPackage -AllUsers *camera* | Remove-AppxPackage')

		print('Remove Weather, News...? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			print('Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage')

		print('Remove Calculator? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			print('Get-AppxPackage -AllUsers *calc* | Remove-AppxPackage')

		print('Remove Sound Recorder? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			print('Get-AppxPackage -AllUsers *soundrec* | Remove-AppxPackage')

		# Secondo l'ordine qui ci sarebbe paint/vr
		print('Remove Microsoft Edge? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('install_wim_tweak /o /c Microsoft-Windows-Internet-Browser /r')
			run('install_wim_tweak /o /c Adobe-Flash /r')

		print('Remove Contact Support, Get Help? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r')
			run('Get-AppxPackage *GetHelp* | Remove-AppxPackage')
			

		print('Remove Connect? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('install_wim_tweak /o /c Microsoft-PPIProjection-Package /r')

		print('Disable system restore? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			#TUTTO IN POWERSHELL
			run('Disable-ComputerRestore -Drive "C:\"')
			run('vssadmin delete shadows /all /Quiet')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f')
			run('reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f')
			run('reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f')
			
		print('Reboot Windows, rerun the script and enter \'2\'')

	elif checkpoint == '2':

		choiceMade = True
		print('Turn off Windows error reporting? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f')
			run('reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f')

		print('Disable forced updates? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f')

		print('Disable license checking? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f')

		print('Disable sync? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f')
			run('reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f')

		print('Disable Windows tips? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f')
			run('reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f')
			run('reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f')
			run('reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f')
			run('reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f')

		print('Remove OneDrive? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('taskkill /F /IM onedrive.exe')
			print('32bit or 64bit Windows? 32/64')
			choice = input()
			while choice != '32' and choice != '64':
				print('Insert "32" or "64')
				choice = input()
			if choice == '32':
				run('"%SYSTEMROOT%\System32\OneDriveSetup.exe" /uninstall')
			elif choice == '64':
				run('"%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe" /uninstall')
			run('rd "%USERPROFILE%\OneDrive" /Q /S')
			run('rd "C:\OneDriveTemp" /Q /S')
			run('rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S')
			run('rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S')
			run('reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f')
			run('reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f')
			run('del /Q /F "%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe"')

		print('Remove telemetry and other unnecessary services? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('sc delete DiagTrack')
			run('sc delete dmwappushservice')
			run('sc delete WerSvc')
			run('sc delete OneSyncSvc')
			run('sc delete MessagingService')
			run('sc delete wercplsupport')
			run('sc delete PcaSvc')
			run('sc delete InstallService')
			run('sc config wlidsvc start=demand')
			run('sc delete wisvc')
			run('sc delete RetailDemo')
			run('sc delete diagsvc')
			run('sc delete shpamsvc')
			run('for /f "tokens=1" %I in (\'reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"\') do (reg delete %I /f)')
			run('for /f "tokens=1" %I in (\'reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"\') do (reg delete %I /f)')
			run('for /f "tokens=1" %I in (\'reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"\') do (reg delete %I /f)')
			run('for /f "tokens=1" %I in (\'reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"\') do (reg delete %I /f)')
			run('for /f "tokens=1" %I in (\'reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"\') do (reg delete %I /f)')
			run('for /f "tokens=1" %I in (\'reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"\') do (reg delete %I /f)')
			run('for /f "tokens=1" %I in (\'reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"\') do (reg delete %I /f)')
			run('for /f "tokens=1" %I in (\'reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"\') do (reg delete %I /f)')
			run('sc delete diagnosticshub.standardcollector.service')
			run('reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f')
			run('reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f')
			run('reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f')
			run('reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f')
			run('reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f')
			run('reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f')
			run('reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f')
			run('reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f')
			run('reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f')
			run('reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f')

		print('Remove unnecessary scheduled tasks? y/n')
		choice = input()
		while choice != 'n' and choice != 'y':
			print('Insert "y" or "n"')
			choice = input()
		if choice == 'y':
			run('schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable')
			run(r'schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable')
			run(r'schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable')
			run('schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable')
			run('schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable')
			run('schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable')
			run('schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable')
			run('schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable')
			run('schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable')
			run('schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable')
			run('schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable')
			run('schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable')
			run('schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable')
			run('del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*"')

	else:
		print('Checkpoint not valid')
