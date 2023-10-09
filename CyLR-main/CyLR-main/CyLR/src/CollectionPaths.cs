using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using Microsoft.Win32;
using DotNet.Globbing;
using System.Text.RegularExpressions;
using System.Reflection.Emit;
using System.DirectoryServices.ActiveDirectory;

//to access vss file information 
/*using System.Management;
using Microsoft.VisualBasic.FileIO;
using Microsoft.Windows;
using Microsoft.Windows.VolumeShadowCopy;*/




[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("CyLRTests")]
namespace CyLR
{
    /// <summary>
    /// Class to handle functionality around file system scanning, pattern
    /// compilation, and providing targets to attempt collection.
    /// </summary>
    /// 

    ///new testing 7 code inserted
    
    
    //closed







    internal static class CollectionPaths
    {

        /// <summary>
        /// Method used to apply default and user specified patterns to files
        /// identified on the system.
        ///
        /// All paths and patterns are case insensitive. 
        /// </summary>
        /// <param name="arguments">User arguments provided at execution.</param>
        /// <param name="additionalPaths">Additional collection targets from the command line.</param>
        /// <param name="Usnjrnl">Whether or not to collect the $J.</param>
        /// <param name="logger">A logging object.</param>
        /// <returns>
        /// List of distinct files to attempt collection of from a system. 
        /// This list is filtered by the default and custom patterns.
        /// </returns>
        public static List<string> GetPaths(Arguments arguments, List<string> additionalPaths, bool Usnjrnl, Logger logger)
        {
            // Init with additional paths provided as a parameter
            // Only supports static paths.
            var staticPaths = new List<string>(additionalPaths);

            // Init vars for glob, regex, and paths to collect
            var globPaths = new List<Glob>();
            var regexPaths = new List<Regex>();
            var collectionPaths = new List<string>();

            // Enable case insensitivity
            GlobOptions.Default.Evaluation.CaseInsensitive = true; 
            bool staticCaseInsensitive = true;

            // Init base paths to scan for files and folders
            var basePaths = new List<string>();

            // Get listing of drives to scan based on platform
            if (Platform.IsUnixLike())
            {
                basePaths.Add("/");  // Scan the entire root.
            } 
            else 
            {
                logger.debug("Enumerating volumes on system");
                DriveInfo[] allDrives = DriveInfo.GetDrives();
                foreach (DriveInfo d in allDrives)
                {
                    basePaths.Add(d.Name.ToString());
                }
                logger.debug(String.Format("Identified volumes: {0}", String.Join(", ", basePaths)));
            }


            // Load information from the CollectionFilePath if present and availble
            if (arguments.CollectionFilePath != ".")
            {
                if (File.Exists(arguments.CollectionFilePath))
                {
                    logger.debug("Extracting patterns from custom path file");
                    using (StreamReader sr = new StreamReader(arguments.CollectionFilePath)){
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            // Skip lines starting with comment
                            if (line.StartsWith("#"))
                            {
                                continue;
                            }

                            // Skip blank lines
                            if (line.Length == 0)
                            {
                                continue;
                            }

                            // Skip paths without tab separator and report to user
                            if (! line.Contains("\t")){
                                logger.warn(String.Format("Excluding invalid path format \"{0}\"", line));
                                continue;
                            }

                            // Split into config components. Requires a definition and path, delimited by a tab
                            string[] pathParts = line.Split('\t');

                            var pathDef = pathParts[0].ToLower();
                            var pathData = Environment.ExpandEnvironmentVariables(pathParts[1]);

                            // Append the path to the proper list based on the definition
                            switch (pathDef)
                            {
                                case "static":
                                    staticPaths.Add(pathData);
                                    break;
                                case "glob":
                                    globPaths.Add(Glob.Parse(pathData));
                                    break;
                                case "regex":
                                    regexPaths.Add(new Regex(pathData));
                                    break;
                                case "force":
                                    collectionPaths.Add(pathData);
                                    break;
                                default:
                                    logger.warn(String.Format("Excluding invalid path format \"{0}\"", line));
                                    break;
                            }
                        }
                    }
                }
                // Handle conditions where the file is not present.
                else
                {
                    logger.error(String.Format("Error: Could not find file: {0}",  arguments.CollectionFilePath));
                    logger.error("Exiting");
                    logger.TearDown();
                    throw new ArgumentException();
                }
            }

            // Load information provided at the command line as additional paths
            if (arguments.CollectionFiles != null)
            {
                logger.debug("Adding command line specified files");
                staticPaths.AddRange(arguments.CollectionFiles);
            }

            bool hasMacOSFolders = (Directory.Exists("/private") 
                && Directory.Exists("/Applications")
                && Directory.Exists("/Users"));

            if (arguments.CollectionFilePath == "." || arguments.CollectDefaults)
            {
                logger.debug("Enumerating patterns for default artifact collection");
                //This section will attempt to collect files or folder locations under each users profile by pulling their ProfilePath from the registry and adding it in front.
                //Add "defaultPaths.Add($@"{user.ProfilePath}" without the quotes in front of the file / path to be collected in each users profile.
                if (!Platform.IsUnixLike())
                {
                    logger.info("Windows platform detected");
                    // Define default paths
                    string systemRoot = Environment.ExpandEnvironmentVariables("%SYSTEMROOT%");
                    string programData = Environment.ExpandEnvironmentVariables("%PROGRAMDATA%");
                    string systemDrive = Environment.ExpandEnvironmentVariables("%SystemDrive%");
                    globPaths.Add(Glob.Parse(systemRoot + @"\Tasks\**"));
                    globPaths.Add(Glob.Parse(systemRoot + @"\Prefetch\**"));
                    globPaths.Add(Glob.Parse(systemRoot + @"\System32\sru\**"));
                    globPaths.Add(Glob.Parse(systemRoot + @"\System32\winevt\Logs\**"));
                    globPaths.Add(Glob.Parse(systemRoot + @"\System32\Tasks\**"));
                    globPaths.Add(Glob.Parse(systemRoot + @"\System32\LogFiles\W3SVC1\**"));
                    globPaths.Add(Glob.Parse(systemRoot + @"\Appcompat\Programs\**"));
                    globPaths.Add(Glob.Parse(programData + @"\Microsoft\Windows\Start Menu\Programs\Startup\**"));
                    globPaths.Add(Glob.Parse(systemDrive + @"\$Recycle.Bin\**\$I*"));
                    globPaths.Add(Glob.Parse(systemDrive + @"\$Recycle.Bin\$I*"));
                    // Edited on 7-24
                    globPaths.Add(Glob.Parse(systemDrive + @"\$Extend\"));
                    globPaths.Add(Glob.Parse(systemDrive + @"\$Secure_$SDS\"));

                    staticPaths.Add(@"%SYSTEMROOT%\SchedLgU.Txt");
                    staticPaths.Add(@"%SYSTEMROOT%\inf\setupapi.dev.log");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\drivers\etc\hosts");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SAM");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SYSTEM");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SOFTWARE");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SECURITY");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SAM.LOG1");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SYSTEM.LOG1");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SOFTWARE.LOG1");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SECURITY.LOG1");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SAM.LOG2");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SYSTEM.LOG2");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SOFTWARE.LOG2");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\config\SECURITY.LOG2");
                    staticPaths.Add(@"%SYSTEMROOT%\$Extend\");
                    staticPaths.Add(@"%SYSTEMROOT%\$Secure_$SDS\");
                    // new paths/////////////////////////////////////////////////
                    staticPaths.Add(@"%ProgramData%\Avast Software\Avast\log\");
                    staticPaths.Add(@"%ProgramData%\Avast Software\Avast\Chest\");
                    staticPaths.Add(@"%ProgramData%\Avast Software\Persistent Data\Avast\Logs\");
                    staticPaths.Add(@"%ProgramData%\Avast Software\Icarus\Logs\");

                    staticPaths.Add(@"%ProgramData%\AVG\Antivirus\log\");
                    staticPaths.Add(@"%ProgramData%\AVG\Antivirus\report\");
                    staticPaths.Add(@"%ProgramData%\AVG\Persistent Data\Antivirus\Logs\");
                    staticPaths.Add(@"%ProgramData%\AVG\Antivirus\");

                    staticPaths.Add(@"%ProgramData%\Avira\Antivirus\LOGFILES\");
                    staticPaths.Add(@"%ProgramData%\Avira\Security\Logs\");
                    staticPaths.Add(@"%ProgramData%\Avira\VPN");

                    staticPaths.Add(@"%ProgramData%\Bitdefender\Endpoint Security\Logs\");
                    staticPaths.Add(@"%ProgramData%\Bitdefender\Desktop\Profiles\Logs\");

                    staticPaths.Add(@"%ProgramData%\crs1\Logs\");
                    staticPaths.Add(@"%ProgramData%\apv2\Logs\");
                    staticPaths.Add(@"%ProgramData%\crb1\Logs\");
                    staticPaths.Add(@"%ProgramData%\Emsisoft\Reports\");

                    staticPaths.Add(@"%ProgramData%\ESET\ESET NOD32 Antivirus\Logs\");
                    staticPaths.Add(@"%ProgramData%\ESET\ESET Security\Logs\");
                    staticPaths.Add(@"%ProgramData%\ESET\RemoteAdministrator\Agent\EraAgentApplicationData\Logs\");
                    staticPaths.Add(@"%ProgramData%\F-Secure\Log\");
                    staticPaths.Add(@"%ProgramData%\F-Secure\Antivirus\ScheduledScanReports\");

                    staticPaths.Add(@"%ProgramData%\HitmanPro\Logs\");
                    staticPaths.Add(@"%ProgramData%\HitmanPro.Alert\Logs\");
                    staticPaths.Add(@"%ProgramData%\HitmanPro.Alert\");



                    staticPaths.Add(@"%ProgramData%\Malwarebytes\Malwarebytes Anti-Malware\Logs\");
                    staticPaths.Add(@"%ProgramData%\Malwarebytes\MBAMService\logs\");
                    staticPaths.Add(@"%ProgramData%\Malwarebytes\MBAMService\ScanResults\");

                    staticPaths.Add(@"%ProgramData%\McAfee\DesktopProtection\");
                    staticPaths.Add(@"%ProgramData%\McAfee\Endpoint Security\Logs\");
                    staticPaths.Add(@"%ProgramData%\McAfee\Endpoint Security\Logs_Old\");
                    staticPaths.Add(@"%ProgramData%\McAfee\VirusScan\");

                    staticPaths.Add(@"%ProgramData%\RogueKiller\logs\");
                    staticPaths.Add(@"%ProgramData%\SecureAge Technology\SecureAge\log\");
                    staticPaths.Add(@"%ProgramData%\sentinel\logs\");

         
       
                    staticPaths.Add(@"%ProgramData%\Symantec\Symantec Endpoint Protection\**\Data\Logs\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\winevt\logs\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\winevt\logs\");

                    staticPaths.Add(@"%ProgramData%\Symantec\Symantec Endpoint Protection\**\Data\Quarantine\");
                    staticPaths.Add(@"%ProgramData%\Symantec\Symantec Endpoint Protection\**\Data\CmnClnt\ccSubSDK\");
                    staticPaths.Add(@"%ProgramData%\Symantec\Symantec Endpoint Protection\**\Data\");

                    staticPaths.Add(@"%ProgramFiles%\TotalAV\logs\");
                    staticPaths.Add(@"%ProgramData%\TotalAV\logs\");
                    staticPaths.Add(@"%ProgramData%\Trend Micro\");

                    staticPaths.Add(@"%ProgramFiles%\Trend Micro\Security Agent\Report\");
                    staticPaths.Add(@"%ProgramFiles%\Trend Micro\Security Agent\ConnLog\");

                    staticPaths.Add(@"%ProgramData%\VIPRE Business Agent\Logs\");

                    staticPaths.Add(@"%ProgramData%\WRData\");

                    staticPaths.Add(@"%ProgramData%\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\**\");
                    staticPaths.Add(@"%ProgramData%\Microsoft\Microsoft AntiMalware\Support\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\winevt\Logs\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\winevt\Logs\");

                    //Edited on 7-24
                    staticPaths.Add(@"%ProgramData%\Microsoft\Windows Defender\**");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\Temp\**");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\Temp\**");

                    staticPaths.Add(@"%ProgramData%\Acronis\TrueImageHome\Logs\ti_demon\");
                    staticPaths.Add(@"%ProgramData%\Acronis\TrueImageHome\Database\");
                    staticPaths.Add(@"%ProgramData%\Acronis\TrueImageHome\Scripts\");

                    staticPaths.Add(@"%ProgramData%\Ammyy\");

                    //Edited on 7-24
                    staticPaths.Add(@"%ProgramData%\AnyDesk\**");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\SysWOW64\config\systemprofile\AppData\Roaming\AnyDesk\");

                    staticPaths.Add(@"%ProgramFiles%\ATERA Networks\AteraAgent\");

                    staticPaths.Add(@"%SYSTEMROOT%\Atlassian\Application Data\Confluence\logs\");

                    staticPaths.Add(@"%ProgramFiles%\Atlassian\Confluence\logs\");

                    staticPaths.Add(@"%ProgramFiles%\Microsoft\Exchange Server\**\Logging\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\Microsoft.NET\Framework*\v*\Temporary ASP.NET Files\");

                    
                    staticPaths.Add(@"%SYSTEMROOT%\inetpub\wwwroot\aspnet_client\system_web\");

                    staticPaths.Add(@"%ProgramFiles%\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\");
                    staticPaths.Add(@"%ProgramFiles%\Microsoft\Exchange Server\*\TransportRoles\Logs\");

                    staticPaths.Add(@"%ProgramFiles(x86)%\FileZilla Server\Logs\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\config\systemprofile\AppData\Local\Sun\Java\Deployment\cache\**\**\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\config\systemprofile\AppData\Local\Sun\Java\Deployment\cache\**\**\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\config\systemprofile\AppData\LocalLow\Sun\Java\Deployment\cache\**\**\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\config\systemprofile\AppData\LocalLow\Sun\Java\Deployment\cache\**\**\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\SysWOW64\config\systemprofile\AppData\Local\Sun\Java\Deployment\cache\**\**\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\SysWOW64\config\systemprofile\AppData\Local\Sun\Java\Deployment\cache\**\**\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Sun\Java\Deployment\cache\**\**\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Sun\Java\Deployment\cache\**\**\");

                    staticPaths.Add(@"%ProgramData%\Kaseya\Log\Endpoint\");

                    staticPaths.Add(@"%ProgramFiles%\Kaseya\**\");
                    staticPaths.Add(@"%ProgramData%\Kaseya\Log\KaseyaEdgeServices\");
                    staticPaths.Add(@"%ProgramData%\LogMeIn\Logs\");

                    staticPaths.Add(@"%ProgramData%\Macrium\Macrium Service\");
                    staticPaths.Add(@"%ProgramData%\Macrium\Reflect\");
                    staticPaths.Add(@"%ProgramData%\Macrium\Reflect Launcher\");

                    staticPaths.Add(@"%ProgramData%\Tenable\Nessus\conf\");
                    staticPaths.Add(@"%ProgramData%\Tenable\Nessus\nessus\logs\");

                    staticPaths.Add(@"%ProgramData%\ssh\");
                    staticPaths.Add(@"%ProgramData%\ssh\logs\");

                    staticPaths.Add(@"%ProgramData%\OpenVPN\config\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\SysWOW64\rserver30\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\rserver30\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\SysWOW64\rserver30\CHATLOGS\**\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\rserver30\CHATLOGS\**\");

                    staticPaths.Add(@"%ProgramFiles%\Remote Utilities - Host\Logs\");
                    staticPaths.Add(@"%ProgramData%\Remote Utilities\");
                    staticPaths.Add(@"%ProgramFiles%\ScreenConnect\App_Data\");
                    staticPaths.Add(@"%ProgramData%\ScreenConnect Client*\");

                    staticPaths.Add(@"%ProgramFiles%\Splashtop\Splashtop Remote\Server\log\");
                    staticPaths.Add(@"%ProgramData%\Splashtop\Temp\log\");

                    staticPaths.Add(@"%ProgramData%\SupremoRemoteDesktop\Log\");
                    staticPaths.Add(@"%ProgramData%\SupremoRemoteDesktop\Inbox\");

                    staticPaths.Add(@"%ProgramFiles%\TeamViewer\");

                    staticPaths.Add(@"%ProgramFiles%\UltraViewer\UltraViewerService_log.txt\");
                    staticPaths.Add(@"%ProgramFiles%\UltraViewer\ConnectionLog.Log\");

                    staticPaths.Add(@"%SYSTEMROOT%\System32\LogFiles\**");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\LogFiles\W3SVC*\");

                    //new changed 
                    staticPaths.Add(@"%SYSTEMROOT%\System32\LogFiles\W3SVC*\**");

                    staticPaths.Add(Path.Combine(Environment.ExpandEnvironmentVariables("%SYSTEMROOT%"), @"Windows.old\System32\LogFiles\W3SVC*\**"));

                    staticPaths.Add(Path.Combine(Environment.GetEnvironmentVariable("SYSTEMROOT"), @"inetpub\logs\LogFiles\"));

                    staticPaths.Add(Path.Combine(Environment.GetEnvironmentVariable("SYSTEMROOT"), @"inetpub\logs\LogFiles\W3SVC*"));

                    staticPaths.Add(Path.Combine(Environment.GetEnvironmentVariable("SYSTEMROOT"), @"Resources\Directory", "**", "LogFiles", "Web", "W3SVC*"));

                    staticPaths.Add(Path.Combine(Environment.GetEnvironmentVariable("SYSTEMROOT"), @"ManageEngine\DesktopCentral_Server\logs\"));


                    staticPaths.Add(@"%ProgramFiles%\Microsoft SQL Server\**\MSSQL\LOG\");

                    staticPaths.Add(Path.Combine(Environment.GetEnvironmentVariable("SYSTEMROOT"), @"nginx\logs\"));

                    staticPaths.Add(@"%ProgramData%\NZBGet\");
                    staticPaths.Add(@"%ProgramData%\NZBGet\nzb\");


                    // Edited on 7-24 

                    staticPaths.Add(@"%SYSTEMROOT%\$Extend\*");

                    staticPaths.Add(@"%SYSTEMROOT%\$Boot\**");
                    staticPaths.Add(@"%SYSTEMROOT%\$Extend\$RmMetadata\$TxfLog\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\AppCompat\Programs\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\AppCompat\Programs\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\config");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\config\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\CCM\Logs\AssetAdvisor.log\");
                    staticPaths.Add(@"%SYSTEMROOT%\$Boot\");
                    //staticPaths.Add(@"%SYSTEMROOT%\$Secure_$SDS\");
                    staticPaths.Add(@"%SYSTEMROOT%\$Secure_$SDS\*");

                    staticPaths.Add(@"%ProgramData%\Microsoft\Network\Downloader\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\Appcompat\Programs\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\Appcompat\Programs\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\WDI\**");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\WDI\LogFiles\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\WDI\{*\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\WDI\{*\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\LogFiles\WMI\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\LogFiles\**");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\LogFiles\WMI\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\SleepStudy\**");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\SleepStudy\**");

                    staticPaths.Add(@"%ProgramData%\Microsoft\Windows\PowerEfficiency Diagnostics\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs\");

                    staticPaths.Add(@"%ProgramData%\Microsoft\Diagnosis\EventTranscript\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\ProgramData\Microsoft\Diagnosis\EventTranscript\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\grouppolicy\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\grouppolicy\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\grouppolicy\**\Scripts\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\grouppolicy\**\Scripts\");

                    staticPaths.Add(@"%SYSTEMROOT%\System Volume Information\_restore*\RP*\");

                    staticPaths.Add(@"%ProgramData%\Microsoft\Windows\Start Menu\Programs\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\LogFiles\**");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\LogFiles\**");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\Minidump\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\Minidump\");


                    staticPaths.Add(@"%SYSTEMROOT%\Windows\prefetch\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\prefetch\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\config\RegBack\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\config\RegBack\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\config\systemprofile\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\config\systemprofile\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\ServiceProfiles\LocalService\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\ServiceProfiles\LocalService\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\ServiceProfiles\NetworkService\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\ServiceProfiles\NetworkService\");

                    staticPaths.Add(@"%SYSTEMROOT%\System Volume Information\_restore*\RP*\snapshot\");

                    staticPaths.Add(@"%SYSTEMROOT%\AppData\Roaming\Microsoft\Word\");
                    // commented on 7-17 staticPaths.Add(@"%SYSTEMROOT%\AppData\Local\Microsoft\Office\**\OfficeFileCache\");
                    staticPaths.Add(@"%SYSTEMROOT%\AppData\Local\Google\Chrome\User Data\**\");
                    staticPaths.Add(@"%SYSTEMROOT%\AppData\Local\Google\Chrome\User Data\**\Sessions\");
                    staticPaths.Add(@"%SYSTEMROOT%\AppData\Local\Google\Chrome\User Data\**\Sync Data\");
                    staticPaths.Add(@"%SYSTEMROOT%\AppData\Roaming\Microsoft\Protect\**\");

                    staticPaths.Add(@"%SYSTEMROOT%\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\");
                    staticPaths.Add(@"%SYSTEMROOT%\**\AppData\Roaming\Microsoft\Protect\**\");
                    staticPaths.Add(@"%SYSTEMROOT%\AppData\Roaming\Microsoft\Windows\Recent\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\Tasks\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\Tasks\");


                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\Tasks\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\Tasks\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\apppatch\Custom\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\apppatch\Custom\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\apppatch\Custom\Custom64\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\apppatch\Custom\Custom64\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\CatRoot\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\CatRoot\");

                    // commented on 7-17 staticPaths.Add(@"%SYSTEMROOT%\Users\**\AppData\Local\Packages\Microsoft.ScreenSketch_8wekyb3d8bbwe\TempState\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\SRU\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\SRU\");

                    staticPaths.Add(@"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp\");
                    staticPaths.Add(@"%SYSTEMROOT%\System32\WDI\LogFiles\StartupInfo\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\WDI\LogFiles\StartupInfo\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\LogFiles\SUM\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\inf\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\inf\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\wbem\**");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\wbem\Repository\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\wbem\Repository\");


                    staticPaths.Add(@"%ProgramData%\Microsoft\Windows\WER\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\System32\LogFiles\Firewall\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\Windows\System32\LogFiles\Firewall\");

                    // edb” is the database that stores the indexing content for the Windows Search feature to provide faster results for files, emails, and other contents.
                    staticPaths.Add(@"%ProgramData%\microsoft\search\data\applications\windows\");
                    staticPaths.Add(@"%ProgramData%\microsoft\search\data\applications\windows\windows.edb");

                    staticPaths.Add(@"%ProgramData%\microsoft\search\data\applications\windows\GatherLogs\");

                    staticPaths.Add(@"%SYSTEMROOT%\Windows\Panther\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\Panther\Rollback");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows\Panther\Rollback");

                    staticPaths.Add(@"%ProgramData%\ProgramData\USOPrivate\UpdateStore");
                    staticPaths.Add(@"%ProgramData%\Microsoft\Windows\Power Efficiency Diagnostics");
                    staticPaths.Add(@"%ProgramData%\Microsoft\Diagnosis\");
                    staticPaths.Add(@"%SYSTEMROOT%\Windows.old\ProgramData\Microsoft\Diagnosis\");

                    staticPaths.Add(@"%SYSTEMROOT%\$Secure_$SDS\");
                    staticPaths.Add(@"%SYSTEMROOT%\$Extend\");

                    // winodws Volume Shadow Copy path
                    ///staticPaths.Add(@"C:\Windows\system32\vssvc.exe");






                    /////////////////////////////////////////////////////////////////////////////////////////

                    // Send static filesystem artifacts to collectionPaths directly
                    collectionPaths.Add(@"%SystemDrive%\$LogFile");
                    collectionPaths.Add(@"%SystemDrive%\$MFT");

                    collectionPaths.Add(@"%SystemDrive%\$Extend\$UsnJrnl:$J");

                    // Edited on 7-25
                    collectionPaths.Add(@"%SystemDrive%\$Extend\$RmMetadata");
                    collectionPaths.Add(@"%SystemDrive%\$Extend\$RmMetadata\$TxfLog");
                    collectionPaths.Add(@"%SystemDrive%\$Extend\$RmMetadata\$TxfLog\$T");
                    collectionPaths.Add(@"%SystemDrive%\$Extend\$J");
                    collectionPaths.Add(@"%SystemDrive%\$Extend\$Max");

                    //Edited on 7-24

                    collectionPaths.Add(@"%SystemDrive%\$Secure_$SDS\");
                    collectionPaths.Add(@"%SystemDrive%\$Boot");
                    

                    
                    // Add USN if enabled
                    if (Usnjrnl)    
                    {
                        collectionPaths.Add(@"%SystemDrive%\$Extend\$UsnJrnl:$J");

                        //Edited on 7-25
                        collectionPaths.Add(@"%SystemDrive%\$Secure_$SDS");
                        collectionPaths.Add(@"%SystemDrive%\$Extend\$RmMetadata\$TxfLog\$T");

                        collectionPaths.Add(@"%SystemDrive%\$Extend\$J");
                        collectionPaths.Add(@"%SystemDrive%\$Extend\$Max");

                        collectionPaths.Add(@"%SystemDrive%\$Extend\$UsnJrnl:$Max");
                        collectionPaths.Add(@"%SystemDrive%\$Extend\$UsnJrnl:$Secure_$SDS");
                    }
                    
                    // Expand envars for all staticPaths.
                    staticPaths = staticPaths.Select(Environment.ExpandEnvironmentVariables).ToList();
                    collectionPaths = collectionPaths.Select(Environment.ExpandEnvironmentVariables).ToList();
                    
                    // Add user specific paths to static list.
                    var users = FindUsers();
                    foreach (var user in users)
                    {
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Windows\Recent\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\WebCache\"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Mozilla\Firefox\Profiles\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\ConnectedDevicesPlatform\"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\Explorer\**"));

                        // new paths added ///////////////////////////////////////////

                        // commented on 7-17 globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\**"));
                        // commented on 7-17 globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Desktop\**"));
                        // commented on 7-17 globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Documents\**"));
                        // commented on 7-17 globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Downloads\**"));
                        // commented on 7-17 globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Dropbox\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Avast Software\Avast\Log\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\F-Secure\Log\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Malwarebytes\Malwarebytes Anti-Malware\Logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\SUPERAntiSpyware\Logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Symantec\Symantec Endpoint Protection\Logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\VIPRE Business\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\GFI Software\AntiMalware\Logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Sunbelt Software\AntiMalware\Logs\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\1password\data\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\1password\backups\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\1password\logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\4kdownload.com\4K Video Downloader\4K Video Downloader\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\AnyDesk\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Aspera\Aspera Connect\var\log\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\.aspera\connect\var\log\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Box\Box\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Box Sync\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Box\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Box Sync\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Cisco\Unified Communications\Jabber\CSF\History\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Jumping Bytes\ClipboardMaster\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Jumping Bytes\ClipboardMaster\pics\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\GPSoftware\Directory Opus\State Data\MRU\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\GPSoftware\Directory Opus\State Data\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\GPSoftware\Directory Opus\Thumbnail Cache\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\GPSoftware\Directory Opus\Logs\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\discord\cache\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\discord\local storage\leveldb\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\doublecmd\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Dropbox\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Dropbox\machine_storage\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Protect\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Dropbox\instance\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\EFSoftware\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Evernote\Evernote\Databases\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Everything\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Everything\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Stardock\Fences\Backups\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\FileZilla\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\FileZilla Server\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\FreeCommanderXE\Settings\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\FreeCommanderXE\Settings\Bkp_Settings*\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Temp\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Temp\FreeCommander*\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Free Download Manager\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Free Download Manager\backup\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\FreeFileSync\Logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Google\Drive\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Google\DriveFS\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Google Drive*\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\LocalLow\Google\GoogleEarth\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\HeidiSQL\Backups\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\HeidiSQL\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\HexChat\logs\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\IceChat Networks\IceChat\Logs\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\IrfanView\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Apple\Mobilesync\Backup\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Apple Computer\Mobilesync\Backup\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Apple\Mobilesync\Backup\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Sun\Java\Deployment\cache\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\LocalLow\Sun\Java\Deployment\cache\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\JDownloader 2.0\cfg\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Kaseya\Log\KaseyaLiveConnect\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\temp\LogMeInLogs\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Mattermost\IndexedDB\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\MediaMonkey\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\Microsoft.Office.OneNote_8wekyb3d8bbwe\LocalState\AppData\Local\OneNote\**\FullTextSearchIndex\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\Microsoft.Office.OneNote_8wekyb3d8bbwe\LocalState\AppData\Local\OneNote\Notifications\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\Microsoft.Office.OneNote_8wekyb3d8bbwe\LocalState\AppData\Local\OneNote\16.0\AccessibilityCheckerIndex\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\Microsoft.Office.OneNote_8wekyb3d8bbwe\LocalState\AppData\Local\OneNote\16.0\NoteTags\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\Microsoft.Office.OneNote_8wekyb3d8bbwe\LocalState\AppData\Local\OneNote\16.0\RecentSearches\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\StickyNotes\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Teams\IndexedDB\https_teams.microsoft.com_0.indexeddb.leveldb\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Teams\Local Storage\leveldb\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Teams\Cache\**"));
                        //globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Teams\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\Microsoft.Todos_8wekyb3d8bbwe\LocalState\AccountsRoot\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\Microsoft.Todos_8wekyb3d8bbwe\LocalState\AccountsRoot\4c444a17ebb042fb92df97d00d1c802a\avatars\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Midnight Commander\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\mIRC\logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\mRemoteNG\**"));
                        // commented on 7-17 globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\**\mRemoteNG\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\MultiCommander*\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\MultiCommander*\Config\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\MultiCommander*\Logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\MultiCommander*\UserData\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\MultiCommander*\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Notepad++\backup\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Notepad++\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\OneCommander\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Apps\2.0\**\**\onec*\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\OneDrive\logs\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\OneDrive*\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\.ssh\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\OpenVPN\config\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\OpenVPN\log\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Documents\Outlook Files\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Outlook\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\pCloud\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\PeaZip\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\ProtonVPN\Logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Q-Dir\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\QNAP\QfinderPro\**"));


                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Documents\ChatLogs\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Documents\ShareX\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Siemens\Automation\Portal*\Settings\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Signal\attachments.noindex\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Signal\logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Signal\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Signal\sql\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\Microsoft.SkypeApp_*\LocalState\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Skype\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Skype for Desktop\IndexedDB\*.leveldb\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Skype for Desktop\Cache\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Slack\IndexedDB\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Slack\Local Storage\leveldb\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Slack\logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Slack\Cache\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Slack\storage\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\TechSmith\Snagit\DataStore\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\SpeedProject\SpeedCommander 19\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Sublime Text*\Settings\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\SugarSync\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Documents\SugarSync Shared Folders\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Documents\My SugarSync\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\SumatraPDF\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\SumatraPDF\sumatrapdfcache\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Temp\**\config\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\TeamViewer\MRU\RemoteSupport\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Telegram Desktop\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Downloads\Telegram Desktop\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\TeraCopy\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Thunderbird\Crash Reports\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Thunderbird\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Thunderbird\Profiles\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Thunderbird\Profiles\**\ImapMail\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Thunderbird\Profiles\**\Mail\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Thunderbird\Profiles\**\calendar-data\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Thunderbird\Profiles\**\Attachments\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\GHISLER\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\GHISLER\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\UltraViewer\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\ViberPC\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\ViberPC\**\Avatars\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\ViberPC\**\Backgrounds\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\ViberPC\**\Thumbnails\**"));


                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\vlc\**"));
                       // globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Videos\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\VMware\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\RealVNC\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\WhatsApp\Cache\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\WhatsApp\Local Storage\leveldb\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\LocalCache\Indexed\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\XYplorer\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\XYplorer\Panes\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\XYplorer\AutoBackup\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Zoom\logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Documents\Zoom\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Zoom Plugin\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\BraveSoftware\Brave-Browser\User Data\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Sessions\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Google\Chrome\User Data\**\Cache\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Mozilla\Firefox\Profiles\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\Temporary Internet Files\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\INetCache\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\WebCache\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cache\Cache_Data\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Google\Chrome\User Data\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Google\Chrome\User Data\**\Sessions\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Google\Chrome\User Data\**\Sync Data\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Google\Chrome\User Data\**\Extensions\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Google\Chrome\User Data\**\File System\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Edge\User Data\**\Collections\**"));
                        // Replace above file path: only collecting "Autofill, Default Folders"
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Edge\User Data\Autofill\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Edge\User Data\Default\**"));


                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Edge\User Data\**\Sessions\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Edge\User Data\**\Sync Data\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Edge\User Data\Snapshots\**"));


                        // Replce End Here


                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Mozilla\Firefox\Profiles\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Mozilla\Firefox\Profiles\**\weave\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Mozilla\Firefox\Profiles\**\bookmarkbackups\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Mozilla\Firefox\Profiles\**\sessionstore-backups\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Office\Recent\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Internet Explorer\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Internet Explorer\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\History\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\Cookies\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\IEDownloadHistory\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\INetCookies\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Opera Software\Opera Stable\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\PuffinSecureBrowser\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\PuffinSecureBrowser\image_cache\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\BitTorrent\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\DC++\Logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Freenet\**"));
                        //globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Freenet\downloads\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Documents\FrostWire\Torrent Data\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\.frostwire5\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Shalsoft\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Newsbin\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\NewsLeecher\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\nicotine\logs\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\nicotine\incomplete\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\nicotine\buddyfiles.db\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\nicotine\incomplete\AppData\Roaming\nicotine\buddystreams.db\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\nicotine\buddymtimes.db\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\nicotine\buddyfileindex.db\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\nicotine\buddywordindex.db\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\nicotine\config\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\nicotine\usershares\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\nicotine\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\qBittorrent\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\qBittorrent\logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\sabnzbd\logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\sabnzbd\admin\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Shareaza\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\SoulseekQt\Soulseek Chat Logs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\SoulseekQt\1\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\uTorrent\**"));

                        //new changed open

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\MicrosoftCorporationII.WindowsSubsystemForAndroid_8wekyb3d8bbwe\LocalState\diagnostics\logcat\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\MicrosoftCorporationII.WindowsSubsystemForAndroid_8wekyb3d8bbwe\LocalCache\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\MicrosoftCorporationII.WindowsSubsystemForAndroid_8wekyb3d8bbwe\LocalState\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\TheDebianProject.DebianGNULinux_*\LocalState\rootfs\etc\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\TheDebianProject.DebianGNULinux_*\LocalState\rootfs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\TheDebianProject.DebianGNULinux_*\LocalState\rootfs\var\spool\cron\crontabs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\TheDebianProject.DebianGNULinux_*\LocalState\rootfs\var\log\apt\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\KaliLinux.54290C8133FEE_*\LocalState\rootfs\etc\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\KaliLinux.54290C8133FEE_*\LocalState\rootfs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\KaliLinux.54290C8133FEE_*\LocalState\rootfs\var\spool\cron\crontabs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\KaliLinux.54290C8133FEE_*\LocalState\rootfs\var\log\apt\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\46932SUSE.openSUSE*Leap*\LocalState\rootfs\etc\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\46932SUSE.openSUSE*Leap*\LocalState\rootfs\**"));

                        ///new changed closed



                       

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\46932SUSE.SUSELinuxEnterpriseServer*\LocalState\rootfs\etc\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\46932SUSE.SUSELinuxEnterpriseServer*\LocalState\rootfs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu*\LocalState\rootfs\etc\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu*\LocalState\rootfs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu*\LocalState\rootfs\var\spool\cron\crontabs\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu*\LocalState\rootfs\var\log\apt\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\LocalLow\Microsoft\CryptnetUrlCache\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\INetCache\IE\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Temp\Diagnostics\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Packages\**\LocalState\rootfs\home\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Windows\Recent\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\Desktop\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Word\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Excel\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Powerpoint\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Publisher\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Diagnostics\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\ElevatedDiagnostics\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Office\**\OfficeFileCache\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Terminal Server Client\Cache\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Word\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\Explorer\**"));
                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\CrashDumps\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\Notifications\**"));

                        globPaths.Add(Glob.Parse($@"{user.ProfilePath}\AppData\Local\ConnectedDevicesPlatform\**"));


                        // commenting ended
                        ////////////////////////////////////////////////////////////////////////////////////////////////////////

                        staticPaths.Add($@"{user.ProfilePath}\NTUSER.DAT");
                        staticPaths.Add($@"{user.ProfilePath}\NTUSER.DAT.LOG1");
                        staticPaths.Add($@"{user.ProfilePath}\NTUSER.DAT.LOG2");
                        staticPaths.Add($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\UsrClass.dat");
                        staticPaths.Add($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1");
                        staticPaths.Add($@"{user.ProfilePath}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2");
                        staticPaths.Add($@"{user.ProfilePath}\AppData\Local\Google\Chrome\User Data\Default\History");
                        staticPaths.Add($@"{user.ProfilePath}\AppData\Local\Microsoft\Edge\User Data\Default\History");
                        staticPaths.Add($@"{user.ProfilePath}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt");
                    }
                    
                }
                // Handle macOS platforms
                else if (Platform.IsUnixLike() && hasMacOSFolders)
                {
                    logger.info("macOS platform detected");
                    // Define default paths to collect
                    var defaultPaths = new List<string> 
                    {
                        "/etc/hosts.allow",
                        "/etc/hosts.deny",
                        "/etc/hosts",
                        "/private/etc/hosts.allow",
                        "/private/etc/hosts.deny",
                        "/private/etc/hosts",
                        "/etc/passwd",
                        "/etc/group",
                        "/private/etc/passwd",
                        "/private/etc/group",
                    };
                    staticPaths.AddRange(defaultPaths);

                    // Expand envars for all staticPaths.
                    staticPaths = staticPaths.Select(Environment.ExpandEnvironmentVariables).ToList();


                    var defaultGlobs = new List<Glob> {
                        //Glob.Parse("**/Library/*Support/Google/Chrome/Default/*"),
                        Glob.Parse("**/Library/*Support/Google/Chrome/Default/History*"),
                        Glob.Parse("**/Library/*Support/Google/Chrome/Default/Cookies*"),
                        Glob.Parse("**/Library/*Support/Google/Chrome/Default/Bookmarks*"),
                        Glob.Parse("**/Library/*Support/Google/Chrome/Default/Extensions/**"),
                        Glob.Parse("**/Library/*Support/Google/Chrome/Default/Last*"),
                        Glob.Parse("**/Library/*Support/Google/Chrome/Default/Shortcuts*"),
                        Glob.Parse("**/Library/*Support/Google/Chrome/Default/Top*"),
                        Glob.Parse("**/Library/*Support/Google/Chrome/Default/Visited*"),
                        Glob.Parse("**/places.sqlite*"),
                        Glob.Parse("**/downloads.sqlite*"),
                        Glob.Parse("**/*.plist"),
                        Glob.Parse("/Users/*/.*history"),
                        Glob.Parse("/root/.*history"),
                        Glob.Parse("/System/Library/StartupItems/**"),
                        Glob.Parse("/System/Library/LaunchAgents/**"),
                        Glob.Parse("/System/Library/LaunchDaemons/**"),
                        Glob.Parse("/Library/LaunchAgents/**"),
                        Glob.Parse("/Library/LaunchDaemons/**"),
                        Glob.Parse("/Library/StartupItems/**"),
                        Glob.Parse("/var/log/**"),
                        Glob.Parse("/private/var/log/**"),
                        Glob.Parse("/private/etc/rc.d/**"),
                        Glob.Parse("/etc/rc.d/**"),
                        Glob.Parse("/.fseventsd/**")
                    };
                    globPaths.AddRange(defaultGlobs);
                    
                } 
                // Handle Linux platforms
                else if (Platform.IsUnixLike())
                {
                    logger.info("Linux platform detected");

                    // Define default paths to collect
                    var defaultPaths = new List<string> 
                    {
                        // Super user
                        "/root/.ssh/config",
                        "/root/.ssh/known_hosts",
                        "/root/.ssh/authorized_keys",
                        "/root/.selected_editor",
                        "/root/.viminfo",
                        "/root/.lesshist",
                        "/root/.profile",
                        "/root/.selected_editor",

                        // Boot
                        "/boot/grub/grub.cfg",
                        "/boot/grub2/grub.cfg",

                        // Sys
                        "/sys/firmware/acpi/tables/DSDT",

                        //etc
                        "/etc/hosts.allow",
                        "/etc/hosts.deny",
                        "/etc/hosts",
                        "/etc/passwd",
                        "/etc/group",
                        "/etc/crontab",
                        "/etc/cron.allow",
                        "/etc/cron.deny",
                        "/etc/anacrontab",
                        "/var/spool/anacron/cron.daily",
                        "/var/spool/anacron/cron.hourly",
                        "/var/spool/anacron/cron.weekly",
                        "/var/spool/anacron/cron.monthly",
                        "/etc/apt/sources.list",
                        "/etc/apt/trusted.gpg",
                        "/etc/apt/trustdb.gpg",
                        "/etc/resolv.conf",
                        "/etc/fstab",
                        "/etc/issues",
                        "/etc/issues.net",
                        "/etc/insserv.conf",
                        "/etc/localtime",
                        "/etc/timezone",
                        "/etc/pam.conf",
                        "/etc/rsyslog.conf",
                        "/etc/xinetd.conf",
                        "/etc/netgroup",
                        "/etc/nsswitch.conf",
                        "/etc/ntp.conf",
                        "/etc/yum.conf",
                        "/etc/chrony.conf",
                        "/etc/chrony",
                        "/etc/sudoers",
                        "/etc/logrotate.conf",
                        "/etc/environment",
                        "/etc/hostname",
                        "/etc/host.conf",
                        "/etc/fstab",
                        "/etc/machine-id",
                        "/etc/screen-rc",
                    };
                    staticPaths.AddRange(defaultPaths);

                    // Expand envars for all staticPaths.
                    staticPaths = staticPaths.Select(Environment.ExpandEnvironmentVariables).ToList();

                    var defaultGlobs = new List<Glob> {
                        // User profiles
                        Glob.Parse("/home/*/.*history"),
                        Glob.Parse("/home/*/.ssh/known_hosts"),
                        Glob.Parse("/home/*/.ssh/config"),
                        Glob.Parse("/home/*/.ssh/autorized_keys"),
                        Glob.Parse("/home/*/.viminfo"),
                        Glob.Parse("/home/*/.profile"),
                        Glob.Parse("/home/*/.*rc"),
                        Glob.Parse("/home/*/.*_logout"),
                        Glob.Parse("/home/*/.selected_editor"),
                        Glob.Parse("/home/*/.wget-hsts"),
                        Glob.Parse("/home/*/.gitconfig"),

                        // Firefox artifacts
                        Glob.Parse("/home/*/.mozilla/firefox/*.default*/**/*.sqlite*"),
                        Glob.Parse("/home/*/.mozilla/firefox/*.default*/**/*.json"),
                        Glob.Parse("/home/*/.mozilla/firefox/*.default*/**/*.txt"),
                        Glob.Parse("/home/*/.mozilla/firefox/*.default*/**/*.db*"),

                        // Chrome artifacts
                        Glob.Parse("/home/*/.config/google-chrome/Default/History*"),
                        Glob.Parse("/home/*/.config/google-chrome/Default/Cookies*"),
                        Glob.Parse("/home/*/.config/google-chrome/Default/Bookmarks*"),
                        Glob.Parse("/home/*/.config/google-chrome/Default/Extensions/**"),
                        Glob.Parse("/home/*/.config/google-chrome/Default/Last*"),
                        Glob.Parse("/home/*/.config/google-chrome/Default/Shortcuts*"),
                        Glob.Parse("/home/*/.config/google-chrome/Default/Top*"),
                        Glob.Parse("/home/*/.config/google-chrome/Default/Visited*"),
                        Glob.Parse("/home/*/.config/google-chrome/Default/Preferences*"),
                        Glob.Parse("/home/*/.config/google-chrome/Default/Login Data*"),
                        Glob.Parse("/home/*/.config/google-chrome/Default/Web Data*"),

                        // Superuser profiles
                        Glob.Parse("/root/.*history"),
                        Glob.Parse("/root/.*rc"),
                        Glob.Parse("/root/.*_logout"),
                        
                        // var
                        Glob.Parse("/var/log/**"),
                        Glob.Parse("/var/spool/at/**"),
                        Glob.Parse("/var/spool/cron/**"),
                        
                        // etc
                        Glob.Parse("/etc/rc.d/**"),
                        Glob.Parse("/etc/cron.daily/**"),
                        Glob.Parse("/etc/cron.hourly/**"),
                        Glob.Parse("/etc/cron.weekly/**"),
                        Glob.Parse("/etc/cron.monthly/**"),
                        Glob.Parse("/etc/modprobe.d/**"),
                        Glob.Parse("/etc/modprobe-load.d/**"),
                        Glob.Parse("/etc/*-release"),
                        Glob.Parse("/etc/pam.d/**"),
                        Glob.Parse("/etc/rsyslog.d/**"),
                        Glob.Parse("/etc/yum.repos.d/**"),
                        Glob.Parse("/etc/init.d/**"),
                        Glob.Parse("/etc/systemd.d/**"),
                        Glob.Parse("/etc/default/**"),

                    };
                    globPaths.AddRange(defaultGlobs);
                    
                } 
                else 
                {
                    logger.error("Unsupported platform");
                    logger.TearDown();
                    throw new Exception();
                }
            }

            // Perform case operations
            if (staticCaseInsensitive)
            {
                staticPaths = staticPaths.Select(x => x.ToLower()).ToList();
            }


            // Get file system listing to populate collection paths
            logger.debug("Enumerating file systems and matching patterns");
            var num_paths_scanned = 0;
            foreach (var basePath in basePaths)
            {
                logger.debug(String.Format("Enumerating volume: {0}", basePath));
                foreach (var entry in WalkTree(basePath, logger))
                {
                    num_paths_scanned++;
                    // Convert to string for ease of comparison
                    var entryStr = entry.ToString();
                    string staticEntry = entryStr;

                    if (staticCaseInsensitive)
                    {
                        staticEntry = entryStr.ToLower();
                    } 

                    // If found in the staticPaths list, add to the collection
                    if (staticPaths.Contains(staticEntry)){
                        collectionPaths.Add(entryStr);
                        continue;
                    }

                    // If not found in the static list, evaluate glob first
                    // as it is more efficient than regex
                    bool globFound = false;
                    foreach (var globPattern in globPaths)
                    {
                        try
                        {
                            globFound = globPattern.IsMatch(entryStr);
                        }
                        catch (System.Exception)
                        {
                            logger.error("Unknown globbing error encountered. Please report.");
                            throw;
                        }
                        if (globFound)
                        {
                            collectionPaths.Add(entryStr);
                            break; 
                        }
                    }

                    if (globFound)
                        continue;

                    // Lastly evaluate regex
                    bool regexFound = false;
                    foreach (var regexPattern in regexPaths)
                    {
                        try
                        {
                            regexFound = regexPattern.IsMatch(entryStr);
                        }
                        catch (System.Exception)
                        {
                            logger.error("Unknown regex error encountered. Please report.");
                            throw;
                        }
                        if (regexFound)
                        {
                            collectionPaths.Add(entryStr);
                            break;
                        }
                    }
                    
                    if (regexFound)
                    {
                        continue;
                    }
                }
            }


            // Remove empty strings from custom paths
            if (collectionPaths.Any()){
                collectionPaths.RemoveAll(x => string.IsNullOrEmpty(x));
            }
            logger.info(String.Format("Scanned {0} paths", num_paths_scanned));
            logger.info(String.Format("Found {0} paths to collect", collectionPaths.Count));

            // Return paths to collect
            return collectionPaths;
        }

        /// <summary>
        /// Method used to enumerate files recursively from a location on a drive.
        /// </summary>
        /// <param name="basePath">A string value containing the root to walk recursively.</param>
        /// <param name="logger">A logging object.</param>
        /// <returns>
        /// Yields an <c>IEnumerable</c> containing <c>FileInfo</c> records for each
        /// file found within the path.
        /// </returns>
        private static IEnumerable<FileInfo> WalkTree(string basePath, Logger logger)
        {
            var dirStack = new Stack<DirectoryInfo>();
            dirStack.Push(new DirectoryInfo(basePath));

            while (dirStack.Count > 0)
            {
                var dir = dirStack.Pop();

                // Get sub directories to add to stack
                // handle access issues
                try
                {
                    foreach (var subDir in dir.GetDirectories().Where(d => !d.Attributes.HasFlag(FileAttributes.ReparsePoint)))
                    {
                        dirStack.Push(subDir);
                    }
                }
                catch (System.Exception)
                {
                    logger.warn(String.Format("Unable to enumerate all files and sub directories in {0}", dir.ToString()));
                }

                // Get files within current directory
                // Handle file access exceptions.
                List<FileInfo> allFiles = new List<FileInfo>();
                try
                {
                    foreach (var fileEntry in dir.GetFiles())
                    {   
                        allFiles.Add(fileEntry);
                    }   
                }
                catch (System.IO.IOException){
                    logger.warn(String.Format("Cannot read one or more files in {0}", dir.ToString()));
                }
                catch (System.UnauthorizedAccessException){
                    logger.warn(String.Format("Access is denied to one or more files in {0}", dir.ToString()));
                }
                catch (System.Exception)
                {
                    logger.warn(String.Format("Unable to enumerate one or more files in {0}", dir.ToString()));
                }

                foreach (var f in allFiles)
                {
                    yield return f;
                }
            }   
        }

        /// <summary>
        /// Method to enumerate user profiles on a Windows system.
        /// </summary>
        /// <returns>
        /// Yields an <c>IEnumerable</c> containing <c>UserProfile</c> records for each
        /// account identified on the system.
        /// </returns>
        public static IEnumerable<UserProfile> FindUsers()
        {
            var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            foreach (string name in key.GetSubKeyNames())
            {
                var path = $@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{name}";
                var profile = Registry.GetValue(path, "FullProfile", string.Empty);
                if (profile != null)
                {
                    var result = new UserProfile
                    {
                        UserKey = name,
                        Path = $@"{path}\ProfileImagePath",
                        ProfilePath = (string)Registry.GetValue(path, "ProfileImagePath", 0),
                        FullProfile = (int)Registry.GetValue(path, "FullProfile", 0)
                    };
                    if (result.FullProfile != -1) yield return result;
                }
            }
        }
        
        internal class UserProfile
        {
            public string UserKey { get; set; }
            public string Path { get; set; }
            public string ProfilePath { get; set; }
            public int FullProfile { get; set; }
        }
    }

    /// new code insert
    


    /// new code closed
    

    


}


///  Program1 p1;
///  p1.main();
///  p1.GetShadowCopyPaths();
///  p1.CopyShadowCopyContents(shadowCopyPath, shadowCopyContents);
