@echo off
cd /d "%~dp0"
fsutil dirty query %systemdrive% >nul
if %errorlevel% == 0 (goto gotadmin) else (goto E)
:E
nsudo -U:E -P:E -UseCurrentConsole "%~0" %*
exit /b
:gotadmin
REM schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /DISABLE
REM ================================ start atlas ================================
echo disable scheduled tasks (atlas-new)
:: https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/language-packs-known-issue
schtasks /Change /Disable /TN "\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation"
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Control Panel\International" /v "BlockCleanupOfUnusedPreinstalledLangPacks" /t REG_DWORD /d "1" /f

:: Breaks setting Lock Screen
schtasks /Change /Disable /TN "\Microsoft\Windows\Shell\CreateObjectTask"

:: other atlas
schtasks /Change /Disable /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance"
schtasks /Change /Disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork"
schtasks /Change /Disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon"
:: ==== WindowsUpdate ====
schtasks /Change /Disable /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start"
:: ==== WaaSMedic ====
schtasks /Change /Disable /TN "\Microsoft\Windows\WaaSMedic\PerformRemediation"
:: ==== UpdateOrchestrator ====
schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Report policies"
schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\ScheduLe Maintenance Work"
::Schedule Scan = need TI (Access denied)
REM schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task"
schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work"
schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Work"
schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask"
schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker"
:: =====================
schtasks /Change /Disable /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks"
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates"
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser"
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\SmartRetry"
schtasks /Change /Disable /TN "\Microsoft\Windows\International\Synchronize Language Settings"
schtasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic"
schtasks /Change /Disable /TN "\Microsoft\Windows\Multimedia\Microsoft\Windows\Multimedia"

schtasks /Change /Disable /TN "\Microsoft\Windows\Wininet\CacheTask"
schtasks /Change /Disable /TN "\Microsoft\Windows\Device Setup\Metadata Refresh"
schtasks /Change /Disable /TN "\MicrosoftEdgeUpdateBrowserReplacementTask"
schtasks /Change /Disable /TN "\MicrosoftEdgeUpdateTaskMachineCore"
schtasks /Change /Disable /TN "\MicrosoftEdgeUpdateTaskMachineUA"
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask"
schtasks /Change /Disable /TN "\Microsoft\Windows\Registry\RegIdleBackup"
REM ================================ End atlas ================================
:: enabled by microsoft to prevent users and apps from running Windows Explorer process elevated
SchTasks /Change /Disable /TN CreateExplorerShellUnelevatedTask
echo disable tasks
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\appuriverifierdaily" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\appuriverifierinstall" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\AppID\EDP Policy Manager" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Bluetooth\UninstallDeviceTask" /DISABLE
REM Microsoft Passport Tasks	C:\Windows\system32\ngctasks.dll
schtasks /Change /TN "\Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\CertificateServicesClient\CryptoPolicyTask" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\CertificateServicesClient\KeyPreGenTask" /DISABLE

REM DIMS Job DLL	C:\Windows\system32\dimsjob.dll
schtasks /Change /TN "\Microsoft\Windows\CertificateServicesClient\SystemTask" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\CertificateServicesClient\UserTask" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\CertificateServicesClient\UserTask-Roam" /DISABLE

REM pstask Task	C:\Windows\System32\pstask.dll
schtasks /Change /TN "\Microsoft\Windows\Chkdsk\ProactiveScan" /DISABLE

REM Data Integrity Scan Task	C:\Windows\System32\discan.dll
schtasks /Change /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Check And Scan" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery" /DISABLE

REM  Launch language cleanup tool	C:\Windows\system32\lpremove.exe
schtasks /Change /TN "\Microsoft\Windows\MUI\LPRemove" /DISABLE

REM pnppolicy Task	C:\Windows\System32\pnppolicy.dll	
schtasks /Change /TN "\Microsoft\Windows\Plug and Play\Device Install Group Policy" /DISABLE
REM Plug and Play User Interface DLL C:\Windows\System32\pnpui.dll
schtasks /Change /TN "\Microsoft\Windows\Plug and Play\Device Install Reboot Required" /DISABLE
REM Generalize driver state in order to prepare the system to be bootable on any hardware configuration.C:\Windows\System32\drvinst.exe
schtasks /Change /TN "\Microsoft\Windows\Plug and Play\Sysprep Generalize Drivers" /DISABLE

REM Software Protection Platform Client Extension Dll	C:\Windows\System32\sppcext.dll
schtasks /Change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" /DISABLE

REM SysMain Service Host	C:\Windows\system32\sysmain.dll
schtasks /Change /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" /DISABLE

REM Working set swap assessment maintenance task	C:\Windows\system32\sysmain.dl
schtasks /Change /TN "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /DISABLE

REM Performance Monitor	C:\Windows\system32\wdc.dll
schtasks /Change /TN "\Microsoft\Windows\Task Manager\Interactive" /DISABLE

REM Windows Diagnostic Infrastructure	C:\Windows\System32\wdi.dll
schtasks /Change /TN "\Microsoft\Windows\WDI\ResolutionHost" /DISABLE

REM Microsoft Color Matching System DLL	C:\Windows\System32\mscms.dll
schtasks /Change /TN "\Microsoft\Windows\WindowsColorSystem\Calibration Loader" /DISABLE

REM Windows WiFi Sync Provider DLL	C:\Windows\System32\WiFiCloudStore.dll
schtasks /Change /TN "\Microsoft\Windows\WlanSvc\CDSSync" /DISABLE

REM XblGameSave Standby Task	C:\Windows\System32\XblGameSaveTask.exe
REM schtasks /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /DISABLE
echo.
echo --- Disable Application Impact Telemetry Agent task
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /DISABLE
echo --- Disable sending information to Customer Experience Improvement Program
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
echo --- Disable Microsoft Compatibility Appraiser task
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
echo --- Disable "Disable apps to improve performance" reminder
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
echo.
schtasks /Change /TN "\Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /DISABLE
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /DISABLE
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Location\Notifications" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Location\WindowsActionDialog" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /DISABLE
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefreshTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /DISABLE
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /DISABLE
echo.
echo --- Disable Customer Experience Improvement Program
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
echo.
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /DISABLE
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /DISABLE
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /DISABLE
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /DISABLE
schtasks /Change /TN "Microsoft\Windows\ApplicationData\DsSvcCleanup" /DISABLE
schtasks /Change /TN "Microsoft\Windows\PushToInstall\LoginCheck" /DISABLE
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Subscription\EnableLicenseAcquisition" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Subscription\LicenseAcquisition" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /DISABLE
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /DISABLE
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" 
rem ================================ Windows Scheduled Tasks ================================
rem https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup
rem schtasks /Change /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor" /Enable
rem schtasks /Run /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor"
schtasks /Delete /TN "Adobe Flash Player PPAPI Notifier" /F
schtasks /Delete /TN "Driver Easy Scheduled Scan" /F
schtasks /Delete /TN "GPU Tweak II" /F
schtasks /Delete /TN "klcp_update" /F
schtasks /Delete /TN "StartDVR" /F
schtasks /Delete /TN "StartCN" /F
schtasks /Delete /TN "TrackerAutoUpdate" /F
schtasks /Delete /TN "Yandex Browser system update" /F
schtasks /Delete /TN "Yandex Browser update" /F
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /DISABLE
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /DISABLE
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /DISABLE
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /DISABLE
schtasks /Change /TN "Microsoft\Windows\ApplicationData\CleanupTemporaryState" /DISABLE
schtasks /Change /TN "Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" /DISABLE
schtasks /Change /TN "Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /DISABLE
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /DISABLE
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /DISABLE
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\HelloFace\FODCleanupTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /DISABLE
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /DISABLE
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /DISABLE
schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /DISABLE
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /DISABLE
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackgroundUploadTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackupTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Speech\HeadsetButtonPress" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /DISABLE
REM schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /DISABLE
REM schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /DISABLE
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /DISABLE
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /DISABLE
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /DISABLE
schtasks /Change /TN "Microsoft\Windows\USB\Usb-Notifications" /DISABLE
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /DISABLE
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /DISABLE
:: disable devicecensus.exe webcam telemtry
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /DISABLE
rem ===============================================================
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /DISABLE
schtasks /Change /TN "USER_ESRV_SVC_QUEENCREEK" /DISABLE
for %%i in (GWX FamilySafety UpdateOrchestrator Media Office NvTm NvProfile Intel OneDrive) do for /f "tokens=1 delims=," %%a in ('schtasks /query /fo csv ^>nul 2^>^&1^| findstr /v "TaskName"^| findstr "%%i"') do schtasks /Change /TN "%%a" /DISABLE
:: Disable Nvidia tasks/services
schtasks /Change /TN NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
schtasks /Change /TN NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
schtasks /Change /TN NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
REM *** Office ***
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE
schtasks /End /TN "Microsoft\Office\OfficeBackgroundTaskHandlerRegistration"
schtasks /Change /TN "Microsoft\Office\OfficeBackgroundTaskHandlerRegistration" /DISABLE
schtasks /End /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack2016"
schtasks /Change /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE
schtasks /End /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn2016"
schtasks /Change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE
pause