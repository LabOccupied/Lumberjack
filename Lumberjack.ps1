using namespace System.Management.Automation.Host
$ErrorActionPreference = "Stop"
    Clear-Host
    Write-Host "==============================================================="
    Write-Host " Enter the file path of the Support Files. "
    Write-Host "==============================================================="
    Write-Host "`r`n (They must be extracted from the cab file and you should not include the trailing '\') `n`n For Example: C:\Cases\1234567\SupportFiles"

#Get File Path of Support logs from user prompt and declare variables
$SupportLogsPath = Read-Host  -Prompt " `r`n `r`n Enter File Path" 
$MPRegistry = $SupportLogsPath + '\MPRegistry.txt'
$SystemInfo = $SupportLogsPath + '\SystemInfo.txt'
$FileVersion = $SupportLogsPath + '\FileVersions.txt'
$MPOperationalEvents = $SupportLogsPath + '\MPOperationalEvents.txt'
$MPStateInfo = $SupportLogsPath + '\MPStateInfo.txt'
$WdatpInfo = $SupportLogsPath + '\WdatpInfo.txt'

$SystemInfoResultList = [System.Collections.ArrayList](Get-Content $SystemInfo | Select-String 'OS Name', 'OS Version', 'System Manufacturer', 'System Model', 'BIOS', 'Time Zone', 'Total Physical Memory')

$MPRegistryResults = [System.Collections.ArrayList](Get-Content $MPRegistry | Select-String 'ASSignatureVersion', 'AVSignatureVersion', ' EngineVersion', ' InstallLocation', 'Current configuration options for location "system policy"')

$IsServiceRunning = Get-Content $MPRegistry -Raw | Select-String 'IsServiceRunning'
$PassiveMode = Get-Content $MPRegistry | Select-String ' PassiveMode ' | Select-Object -First 1
$AntiVirus = Get-Content $MPRegistry -Raw | Select-String 'DisableAntiVirus'
$AntiSpyware = Get-Content $MPRegistry -Raw | Select-String 'DisableAntiSpyware'
$TamperProtection = Get-Content $MPRegistry | Select-String 'TamperProtection ' | Select-Object -First 1
$PuaProtection = Get-Content $MPRegistry | Select-String 'PUAProtection' | Select-Object -First 1
$DisableRealtimeMonitoring = Get-Content $MPRegistry | Select-String ' DisableRealtimeMonitoring ' | Select-Object -First 1
$CheckForSigB4Scan = Get-Content $MPRegistry | Select-String ' CheckForSignaturesBeforeRunningScan ' | Select-Object -First 1
$ScanParameters = Get-Content $MPRegistry | Select-String ' ScanParameters ' | Select-Object -First 1



Try{
$WdatpInfoResults = Get-Content $WdatpInfo | Select-String 'senseID' -ErrorAction Stop
} Catch {$WdatpInfoResults = $null}
Try{
$WdatpOrgID = Get-Content $WdatpInfo | Select-String 'senseGuid' -ErrorAction Stop
} Catch {$WdatpOrgID = $null}
$MpRegOrgID = Get-Content $MPRegistry | Select-String 'SenseOrgId' | Select-Object -First 1





function Show-Menu {
    param (
        [string]$Title = 'Lumber Jack'
    )
    Clear-Host
    Write-Host "============================== $Title =============================="  
    Write-Host "   Here's some quick info about the device you've gathered logs from."
    Write-Host "   If you'd like to do more, pick an option below."
    Write-Host "========================================================================="


#Print quick info
    Foreach ($i in $SystemInfoResultList) {
Write-Host '    ' -NoNewLine; Write-Host $i}
   
   Try{
   If ($IsServiceRunning.ToString() -Like '*(0X1)*') {
   Write-Host '    Defender Service is Running' -ForegroundColor Green }
   Elseif ($IsServiceRunning.ToString() -Like '*(0X0)*') {
   Write-Host '    Defender Service is NOT Running' -BackgroundColor Red }
   Else {Write-Host $IsServiceRunning}
   } Catch {}

   Try{
   If ($PassiveMode.ToString() -Like '*0X0*') {
   Write-Host '    Defender is NOT in Passive Mode' -ForegroundColor Green }
   Elseif ($PassiveMode.ToString() -Like '*0X1*') {
   Write-Host '    Defender is in Passive Mode' -BackgroundColor Red }
   Else {Write-Host $PassiveMode}
   } Catch {}

   Try{
   If ($AntiVirus.ToString() -Like '*0X0*') {
   Write-Host '    AntiVirus is ENABLED' -ForegroundColor Green }
   Elseif ($AntiVirus.ToString() -Like '*0X1*') {
   Write-Host '    AntiVirus is DISABLED' -BackgroundColor Red }
   Else {Write-Host $AntiVirus}
   } Catch {}

   Try{
   If ($AntiSpyware.ToString() -Like '*0x0*') {
   Write-Host '    AntiSpyware is ENABLED' -ForegroundColor Green }
   Elseif ($AntiSpyware.ToString() -Like '*0x1*') {
   Write-Host '    AntiSpyware is DISABLED' -BackgroundColor Red }
   Else {Write-Host $AntiSpyware}
   } Catch {}

   Try{
   If ($PuaProtection.ToString() -Like '*0X0*') {
   Write-Host '    PUA Protection is DISABLED' -ForegroundColor Red }
   Elseif ($PuaProtection.ToString() -Like '*0X1*') {
   Write-Host '    PUA Protection is ENABLED' -ForegroundColor Green}
   Elseif ($PuaProtection.ToString() -Like '*0X2*') {
   Write-Host '    PUA Protection is in AUDIT MODE' -ForegroundColor Yellow}
   Else {Write-Host $PuaProtection}
   } Catch {}


   Try{
   If ($TamperProtection.ToString() -Like '*0x0*') {
   Write-Host '    Tamper Protection is DISABLED' -ForegroundColor Red }
   Elseif ($TamperProtection.ToString() -Like '*0x4*') {
   Write-Host '    Tamper Protection is DISABLED' -ForegroundColor Red }
   Elseif ($TamperProtection.ToString() -Like '*0x1*') {
   Write-Host '    Tamper Protection is ENABLED' -ForegroundColor Green }
   Elseif ($TamperProtection.ToString() -Like '*0X2*') {
   Write-Host '    Tamper Protection is OFF Kill-bitted' -ForegroundColor Red }
   Elseif ($TamperProtection.ToString() -Like '*0X6*') {
   Write-Host '    Tamper Protection is OFF Kill-bitted' -ForegroundColor Red }
   Elseif ($TamperProtection.ToString() -Like '*0X5*') {
   Write-Host '    Tamper Protection is ENABLED via MDE' -ForegroundColor Green }
   Else {Write-Host $TamperProtection}
   } Catch {}


   Try{
   If ($DisableRealtimeMonitoring.ToString() -Like '*0x0*') {
   Write-Host '    Realtime Monitoring is ENABLED' -ForegroundColor Green }
   Elseif ($DisableRealtimeMonitoring.ToString() -Like '*0x1*') {
   Write-Host '    Realtime Monitoring is DISABLED' -ForegroundColor Red }
   } Catch{}



   Foreach ($i in $MPRegistryResults) {
   If ($i.ToString() -Like '*null*') {Continue}
If ($i.ToString() -Like '*Current configuration options for location "system policy"*'){Break}
Elseif ($i.ToString() -NotLike '*Current configuration options for location "system policy"*'){
Write-Host $i}
}

   Try{
Write-Host '    MDE Machine ID:                          ' -NoNewLine; Write-Host $WdatpInfoResults.ToString().substring(62, 40)
} Catch {Write-Host "(null)"}


If ($MpRegOrgID.ToString() -NotLike '*null*'){
Write-Host '    MDE Org ID:                              ' -NoNewLine; Write-Host $MpRegOrgID.ToString().substring(62.36)
}
Else {Write-Host '    MDE Org ID:                              ' -NoNewLine; Write-Host $MpRegOrgID.ToString().substring(61.7)}







    Write-Host "`r`n `r`n  What would you like to do?"
    Write-Host "`r ================================="
    Write-Host "`r 1: Press '1' ASR rules" 
    Write-Host "`r`n 2: Press '2' Scanning & RTP"
    Write-Host "`r`n 3: Press '3' Exclusions"
    Write-Host "`r`n 4: Press '4' Definition of logs"
    Write-Host "`r`n 5: Press '5' View other log set"    
    Write-Host "`r`n Q: Press 'Q' to quit `r`n"
}


do
 {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    '1' {
    
#Declaring Hash Table of current ASR Rules and their descriptions per https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules
$ASRs = @{
'7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
'56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
'9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from the Windows local security authority subsystem'
'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
'01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion'
'5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
'3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
'75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
'26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
'92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
}






#Filter desired content of MPRegistry log to find ASR rule IDs
$ASRResultList = [System.Collections.ArrayList](Get-Content $MPRegistry | Select-String '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', '56a863a9-875e-4185-98a7-b882c64b5ce5', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a', 
'9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', '01443614-cd74-433a-b99e-2ecdc07bfc25', '5beb7efe-fd9a-4556-801d-275e5ffc04cc', 'd3e037e1-3eb8-44c8-a917-57927947596d',
'3b576869-a4ec-4529-8536-b80a7769e899', '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', '26190899-1602-49e8-8b27-eb1d0a1ce869', 'e6db77e5-3df2-4cf1-b95a-636979351e5b', 'd1e49aac-8f56-4280-b9ba-993a6d77406c',
'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', 'c1db55ab-c21a-4637-bb3f-a12568109d35', 'Current configuration options for location "system policy"', 'Current configuration options for location "mdm policy"',
'Current configuration options for location "mdm policy"', 'Current configuration options for location "preferences"', 'Current configuration options for location "effective policy"')




#Iterate through results and write to screen
ForEach ($Item in $ASRResultList){

#Checks which section of log is being read
If ($Item.ToString() -Like '*Current configuration options for location "effective policy"*') {

Write-Host "================================================================================================"; Write-Host "`r`n ASR Rules found in the Effective Policy (Policy that is actually present on the machine) - `r`n" -ForegroundColor Green }

If ($Item.ToString() -Like '*Current configuration options for location "system policy"*') {

Write-Host "================================================================================================"; Write-Host "`r`n ASR Rules found in the System Policy (Policy that is applied via SCCM, GPO, or Local Policy) - `r`n" -ForegroundColor Green }

Elseif ($Item.ToString() -Like '*Current configuration options for location "mdm policy"*') {

Write-Host "================================================================================================"; Write-Host "`r`n ASR Rules found in the MDM Policy (Policy that is applied via Intune) - `r`n" -ForegroundColor Green }

Elseif ($Item.ToString() -Like '*Current configuration options for location "preferences"*') {

Write-Host "================================================================================================"; Write-Host "`r`n ASR Rules found in the 'Preferences' section (Policies applied via Defender GUI or PowerShell) - `r`n" -ForegroundColor Green }


#Checks for status of ASRs and writes to screen
If ($Item.ToString() -Like '*: 2*'){
Write-Host `r`n $ASRs[$Item.ToString().substring(4, 36)] "Set to" -ForegroundColor White -NoNewline; Write-Host " Audit" -ForegroundColor Green
}
Elseif ($Item.ToString() -Like '*: 1*'){
Write-Host `r`n $ASRs[$Item.ToString().substring(4, 36)] "Set to" -ForegroundColor White -NoNewline; Write-Host " Enabled" -ForegroundColor Green
}
Elseif ($Item.ToString() -Like '*: 0*'){
Write-Host `r`n $ASRs[$Item.ToString().substring(4, 36)] "Set to" -ForegroundColor White -NoNewline; Write-Host " Disabled" -ForegroundColor Red
}
Elseif ($Item.ToString() -Like '*: 6*'){
Write-Host `r`n $ASRs[$Item.ToString().substring(4, 36)] "Set to" -ForegroundColor White -NoNewline; Write-Host " Warn" -ForegroundColor Yellow
}
Elseif ($Item.ToString() -Like '*: 5*'){
Write-Host `r`n $ASRs[$Item.ToString().substring(4, 36)] -ForegroundColor White -NoNewline; Write-Host " Not Configured" -ForegroundColor Red
}
}


    } '2' {
    


$ScanDay = Get-Content $MPRegistry | Select-String 'Scan_scheduleDay'



Write-Host '================================================================================================'
Write-Host "                              Effective scan settings found" -ForegroundColor Green
Write-Host '================================================================================================'



if ($ScanDay.Tostring() -Like '*0x0*'){
Write-Host 'Scheduled Scan day is' -NoNewline; Write-Host ' Every Day'}
Elseif ($ScanDay.Tostring() -Like '*0x1*'){
Write-Host 'Scheduled Scan day is' -NoNewline; Write-Host ' Sunday'}
Elseif ($ScanDay.Tostring() -Like '*0x2*'){
Write-Host 'Scheduled Scan day is' -NoNewline; Write-Host ' Monday'}
Elseif ($ScanDay.Tostring() -Like '*0x3*'){
Write-Host 'Scheduled Scan day is' -NoNewline; Write-Host ' Tuesday'}
Elseif ($ScanDay.Tostring() -Like '*0x4*'){
Write-Host 'Scheduled Scan day is' -NoNewline; Write-Host ' Wednesday'}
Elseif ($ScanDay.Tostring() -Like '*0x5*'){
Write-Host 'Scheduled Scan day is' -NoNewline; Write-Host ' Thursday'}
Elseif ($ScanDay.Tostring() -Like '*0x6*'){
Write-Host 'Scheduled Scan day is' -NoNewline; Write-Host ' Friday'}
Elseif ($ScanDay.Tostring() -Like '*0x7*'){
Write-Host 'Scheduled Scan day is' -NoNewline; Write-Host ' Saturday'}
Elseif ($ScanDay.Tostring() -Like '*0x8*'){
Write-Host 'Scheduled Scan day is' -NoNewline; Write-Host ' Never'}


$Text = Get-Content $MPRegistry | Select-String ' Scan_ScheduleTime ' 
$Regex = '(?ms)\: (.+?) \('
$OutputText = [regex]::Matches($Text,$Regex) |
foreach {$_.groups[1].value }
Write-Host 'Scheduled time is ' -NoNewLine; Write-Host $OutputText -NoNewline; ' minutes after midnight'


If ($CheckForSigB4Scan.ToString() -Like '*0x0*') {
Write-Host 'Check for signature updates before scans is set to ' -NoNewline; Write-Host 'FALSE' -ForegroundColor Red }
Elseif ($CheckForSigB4Scan.ToString() -Like '*0X1*') {
Write-Host 'Check for signature updates before scans is set to ' -NoNewline; Write-Host 'TRUE' -ForegroundColor Green }


If ($ScanParameters.ToString() -Like '*0X1*') {
Write-Host 'Scheduled scan type is QUICK SCAN'}
Elseif ($ScanParameters.ToString() -Like '*0X2*') {
Write-Host 'Scheduled scan type is FULL SCAN'}






Write-Host "`n`n`n"
    } '3' {
    

    
$Text = Get-Content $MPRegistry -Raw


Write-Host "================================================================================================"; Write-Host "`r`n Extension Exclusions Found: " -ForegroundColor Green
$Regex = '(?ms)\[Exclusions\\Extensions\](.+?)\[Exclusions'

$OutputText = [regex]::Matches($Text,$Regex) |
foreach {$_.groups[1].value }
Write-Host $OutputText 


Write-Host "================================================================================================"; Write-Host "`r`n IP Address Exclusions Found: " -ForegroundColor Green
$Regex = '(?ms)\[Exclusions\\IpAddresses\](.+?)\[Exclusions'

$OutputText = [regex]::Matches($Text,$Regex) |
foreach {$_.groups[1].value }
Write-Host $OutputText 


Write-Host "================================================================================================"; Write-Host "`r`n Path Exclusions Found: " -ForegroundColor Green
$Regex = '(?ms)\[Exclusions\\Paths\](.+?)\[Exclusions\\Processes\]'

$OutputText = [regex]::Matches($Text,$Regex) |
foreach {$_.groups[1].value }
Write-Host $OutputText 



Write-Host "================================================================================================"; Write-Host "`r`n Process Exclusions Found: " -ForegroundColor Green
$Regex = '(?ms)\[Exclusions\\Processes\](.+?)\[Exclusions\\TemporaryPaths\]'

$OutputText = [regex]::Matches($Text,$Regex) |
foreach {$_.groups[1].value }
Write-Host $OutputText 



Write-Host "================================================================================================"; Write-Host "`r`n Temporary Path Exclusions Found: `r`n" -ForegroundColor Green
$Regex = '(?ms)\[Exclusions\\TemporaryPaths\](.+?)\[Features\]'

$OutputText = [regex]::Matches($Text,$Regex) |
foreach {$_.groups[1].value }
Write-Host $OutputText 



    } '4' {
    Write-Host "Application.evtx" -f Green;  Write-Host "Windows Application Log (%SystemRoot%\System32\Winevt\Logs\Application.evtx).  
";  Write-Host "Random xxxx6a15ebb0630617cc49519dabd3169c68df06 file names" -f Green;  Write-Host "- Dynamic Security Intelligence Updates (aka Definition Updates) can be listed by running mpcmdrun.exe -listalldynamicsignatures.  They’re SHA1 hashes on the blob content.  Blobs are used for various purposes by the cloud/client communication (think of these as surgical metadata/information – similar to what we’re encoding in the VDM files, but directly related to what the client queried for).  You can clear these out by running "MpCmdRun.exe -RemoveDefinitions -DynamicSignatures"  
";  Write-Host "Cache_filename_dump-*.bin" -f Green;  Write-Host  " This is a text file showing the dump of the persisted cache file. The header of the cache file also contains Trusted USN information.  
";  Write-Host "Cbs.log" -f Green;  Write-Host " The Windows Update history log. Used to troubleshoot patch/setup/servicing/upgrade issues. The Devices & Deployment team can assist in analyzing this particular log.  
";  Write-Host "customDncList" -f Green;  Write-Host "  DNC stands for 'Do Not Call List'. This file includes a hashed list of urls that SHOULDN’T be looked up every time when Web Content Filtering is enabled. This should only be present on machines where Web Content Filtering is enabled or was once enabled. Not human readable.  
";  Write-Host "customSupportedUris" -f Green;  Write-Host "  Related to the Bloom filter used by 'Network Protection' (which is used also by Smartscreen). This is the Network Protection organization specific bloomfilter. Entries in this bloomfilter correspond to entries in the customer’s URL Indicators in the MDATP Portal. Includes URLS from MCAS as well. Not human readable.  
";  Write-Host "customSettings" -f Green;  Write-Host "  This file contains organization and tenant specific settings for Network Protection, mainly whether or not Web Content Filtering is turned on (forceServiceDetermination) and what applications should be included in web content filtering.    
";  Write-Host "Diagerr.xml" -f Green;  Write-Host "  Output from a tool called MBR2GPT documented here https://docs.microsoft.com/en-us/windows/deployment/mbr-to-gpt#logs.  File is located in '\Windows\Panther\UnattendGC'.  
";  Write-Host "DiagWRN.xml" -f Green;  Write-Host "  Output from a tool called MBR2GPT documented here https://docs.microsoft.com/en-us/windows/deployment/mbr-to-gpt#logs.  File is located in '\Windows\Panther\UnattendGC'.  
";  Write-Host "FileVersions.txt" -f Green;  Write-Host "  Contains the versions of the various binaries that make up our product. Contains the build and branch info of the OS. This information is helpful to decode the trace logs.  
";  Write-Host "FltmcInfo.txt" -f Green;  Write-Host "  Lists loaded filter drivers (you can run this manually using fltmc.exe).  
";  Write-Host "IFEO.txt" -f Green ;  Write-Host "  Image File Execution Options reg key (HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options) - This is where we store Exploit Protection settings.  
";  Write-Host "Microsoft-Windows-Security-Mitigations%4KernelMode" -f Green;  Write-Host "  Exploit Protection Event Log.  
";  Write-Host "Microsoft-Windows-Security-Mitigations%4UserMode" -f Green;  Write-Host "  Exploit Protection Event Log.  
";  Write-Host "MitigationPolicies.xml" -f Green;  Write-Host "  Lists the current Exploit Protection policy settings that are configured on the system - pulls from IFEO Reg key.  
";  Write-Host "MpCmdRun.log" -f Green;  Write-Host "  This is a history of 'mpcmdrun.exe' being typed in via command prompt.  Logs of MpCmdRun running in various privileges – running tasks like signature update, service enabling/disabling etc.  
";  Write-Host "MpCmdRun-NetworkService.log" -f Green;  Write-Host "  Lists scheduled scans and signature updates done under the NetworkService security principal.  
";  Write-Host "MpCmdRun-System.log" -f Green;  Write-Host "  Lists scheduled scans and signature updates done under the LocalSystem security principal.  
";  Write-Host "MPDetection-DATE-TIME.log" -f Green;  Write-Host "  Records an event every time malware is detected and Service/Engine versions.  
";  Write-Host "MPLog-DATE-TIME.log" -f Green;  Write-Host "  A log of scanned resources, threats detected, and signature update versions.  Generated by the antimalware engine. Captures critical events from Defender.  
";  Write-Host "MPOperationalEvents.txt" -f Green;  Write-Host "  Windows Defender Operational log in text format. Pulls all events into a single file for easy troubleshooting/analysis.  
";  Write-Host "MPRegistry.txt" -f Green;  Write-Host "  The various configurations that dictate how our product should behave. Look under 'effective policy' (should be the first section).  
";  Write-Host "MpSigStub.log" -f Green;  Write-Host "  Logs from our signature update bootstrapper application, MpSigStub.exe.  
";  Write-Host "MpSigStub-NetworkService.log" -f Green;  Write-Host "  Logs from our signature update bootstrapper application, MpSigStub.exe, running under the Network Service account.  
";  Write-Host "MPStateInfo.txt" -f Green;  Write-Host "  State of the various components like RTP, IOAV etc.  
";  Write-Host "MPWHCEvents.txt" -f Green;  Write-Host "  Health center events that we trigger.  
";  Write-Host "MpWppTracing-*.bin" -f Green;  Write-Host "  Trace logging from our product. Captured when running 'MpCmdRun.exe -Trace [x] [x]'  
";  Write-Host "Mrt.txt" -f Green;  Write-Host "  Log captured when running the Microsoft Windows Malicious Software Removal Tool.  
";  Write-Host "networkProtectionSettings" -f Green;  Write-Host "  This file contains settings sent to ALL network Protection users, and contains sampling rates for various telemetry events, as well as geo specific URLs for SmartScreen server endpoints. Human readable JSON.  
";  Write-Host "PrinterInfo.txt" -f Green;  Write-Host "  Print Registry info from (HKLM\SYSTEM\CurrentControlSet\Control\Print), (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print), & (HKLM\System\CurrentControlSet\Services\spooler).  Click here to learn more about Windows Printing.  
";  Write-Host "ReAgent.xml" -f Green;  Write-Host "  Windows RE Recovery https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options  
";  Write-Host "SecurityHealthRegistry.txt" -f Green;  Write-Host "  Registry settings for (HKLM\Software\Microsoft\Windows Security Health).  
";  Write-Host "Setupact.txt" -f Green;  Write-Host "  File from '\Windows\Panther\UnattendGC'.  
";  Write-Host "Setuperr.txt" -f Green;  Write-Host "  File from '\Windows\Panther\UnattendGC'.  
";  Write-Host "supportedUris" -f Green;  Write-Host "  This is the Network Protection 'normal' bloomfilter. Entries in this bloomfilter are considered malicious/phishing/techscam/etc by the smartscreen server. Periodically updated on clients, like virus definitions. Not human readable.  
";  Write-Host "System.evtx" -f Green;  Write-Host "  Windows System Event Log (%SystemRoot%\System32\Winevt\Logs\System.evtx)  
";  Write-Host "SystemInfo.txt" -f Green;  Write-Host "  This is output of the built-in 'Systeminfo.exe' program that displays Operating System configuration information.  
";  Write-Host "TaskSchedulerInfo-Internal.log" -f Green;  Write-Host "  Defender Scheduled Tasks.  
";  Write-Host "TaskSchedulerInfo-Windows.xml" -f Green;  Write-Host "  Defender Scheduled Tasks in xml format.  
";  Write-Host "topTraffic" -f Green;  Write-Host "  A hashed list of URLs that are considered topTraffic sites. Serves no direct protection purpose, just for internal telemetry purposes. Not human readable 
";  Write-Host "WdatpInfo.txt" -f Green;  Write-Host "  MDATP Registry key settings (HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection) & (HKLM\System\CurrentControlSet\Services\sense).  
";  Write-Host "WindowsUpdate.log" -f Green;  Write-Host "  Lists Windows Update agent activity.  WSUS & Microsoft Update log events here.  Note, UNC file share definition updates will not be found in this log.  
";  Write-Host "***WSCInfo.txt will be blank on server 20016/2019 
" -f Green;  Write-Host "WSCInfo.txt" -f Green;  Write-Host "  Lists your installed AntivirusProduct & AntiSpywareProduct, including 3rd party A/V. You can run the following PowerShell command to list your a/v product:   Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct 
";  Write-Host "WSCRegistry.txt" -f Green;  Write-Host "  Registry settings for (HKLM\SOFTWARE\Microsoft\Security Center) & (HKLM\System\CurrentControlSet\Services\wscsvc). 
";  Write-Host "Captured files (SCEP) - small differences 
" -f Green;  Write-Host "MPRegistry.txt" -f Green;  Write-Host "  The various configurations that dictate how our product should behave. Look under 'effective policy' (should be the first section).  
";  Write-Host "MPSystemEvents.txt" -f Green;  Write-Host "  Microsoft Antimalware events in text format pulled from the System Event log. Pulls all events into a single file for easy troubleshooting/analysis.  
";  Write-Host "NisWfpInfo.log" -f Green;  Write-Host "  Output of the Windows Filtering Platform registration state for the Network Inspection service. It can be ignored. 

"
    } '5' {



      Clear-Host
    Write-Host "==============================================================="
    Write-Host " Enter the file path of the Support Files. "
    Write-Host "==============================================================="
    Write-Host "`r`n (They must be extracted from the cab file and you should not include the trailing '\') `n`n For Example: C:\Cases\1234567\SupportFiles"

#Get File Path of Support logs from user prompt and declare variables
$SupportLogsPath = Read-Host  -Prompt " `r`n `r`n Enter File Path" 
$MPRegistry = $SupportLogsPath + '\MPRegistry.txt'
$SystemInfo = $SupportLogsPath + '\SystemInfo.txt'
$FileVersion = $SupportLogsPath + '\FileVersions.txt'
$MPOperationalEvents = $SupportLogsPath + '\MPOperationalEvents.txt'
$MPStateInfo = $SupportLogsPath + '\MPStateInfo.txt'
$WdatpInfo = $SupportLogsPath + '\WdatpInfo.txt'

$SystemInfoResultList = [System.Collections.ArrayList](Get-Content $SystemInfo | Select-String 'OS Name', 'OS Version', 'System Manufacturer', 'System Model', 'BIOS', 'Time Zone', 'Total Physical Memory')

$MPRegistryResults = [System.Collections.ArrayList](Get-Content $MPRegistry | Select-String 'ASSignatureVersion', 'AVSignatureVersion', ' EngineVersion', ' InstallLocation', 'Current configuration options for location "system policy"')

$IsServiceRunning = Get-Content $MPRegistry -Raw | Select-String 'IsServiceRunning'
$PassiveMode = Get-Content $MPRegistry | Select-String ' PassiveMode ' | Select-Object -First 1
$AntiVirus = Get-Content $MPRegistry -Raw | Select-String 'DisableAntiVirus'
$AntiSpyware = Get-Content $MPRegistry -Raw | Select-String 'DisableAntiSpyware'
$TamperProtection = Get-Content $MPRegistry | Select-String 'TamperProtection ' | Select-Object -First 1
$PuaProtection = Get-Content $MPRegistry | Select-String 'PUAProtection' | Select-Object -First 1
$DisableRealtimeMonitoring = Get-Content $MPRegistry | Select-String ' DisableRealtimeMonitoring ' | Select-Object -First 1
$CheckForSigB4Scan = Get-Content $MPRegistry | Select-String ' CheckForSignaturesBeforeRunningScan ' | Select-Object -First 1
$ScanParameters = Get-Content $MPRegistry | Select-String ' ScanParameters ' | Select-Object -First 1



Try{
$WdatpInfoResults = Get-Content $WdatpInfo | Select-String 'senseID' -ErrorAction Stop
} Catch {$WdatpInfoResults = $null}
Try{
$WdatpOrgID = Get-Content $WdatpInfo | Select-String 'senseGuid' -ErrorAction Stop
} Catch {$WdatpOrgID = $null}
$MpRegOrgID = Get-Content $MPRegistry | Select-String 'SenseOrgId' | Select-Object -First 1



    } '6' {
      Write-Host "Why'd you press 6?" -BackgroundColor Red

    }
    } 
    pause
 }
 until ($selection -eq 'q')