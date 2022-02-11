
Kansa Frame Work
A PowerShell-based incident response framework

If you follow information security, you know that information systems are constantly under attack and often fall victim to adversaries looking to make a quick buck, gain competitive advantage through theft of intellectual property or embarrass a target that they find politically or ideologically offensive.
In many enterprises, computer security incident response (IR) teams exist to respond to these threats and these teams nearly always spring into action with very limited knowledge about the incidents they are investigating.
Maybe the incident started because someone noticed an account added to the domain administrators group. How did the account get there? How long has it been there? What has it been used for and by whom?
In the early going, the investigative focus may be narrow — the known victim machine, but the scope often quickly expands. Investigators may need to gather data from many or even all machines within a given domain or other security boundary to look for indicators of compromise or anomalous activity. Readers of PowerShell Magazine understand that PowerShell can provide much of this capability for Windows systems.
Disclaimer
At this point, I should provide the following disclaimer: This article is solely representative of the views and opinions of the author, Dave Hull, and is not intended to state or reflect those of Microsoft Corporation, the author’s employer. This article is not endorsed by Microsoft.
Kansa: A PowerShell-based incident response framework
You could do what I did a couple years ago and write a monolithic PowerShell script to collect the data you need for your investigation and copy that script to every host in your environment, maybe requiring CredSSP to pull third-party binaries like Sysinternal’s Autorunsc from a file server or to write output to a file server, but that would be a bad idea.
For starters, a monolithic script written to collect many different data points will be cumbersome if you later want to collect a single data point from multiple hosts. Secondly, copying a script to every host in your environment means you’re not taking advantage of Windows Remote Management and PowerShell’s ability to run jobs across multiple hosts in parallel. Lastly and very importantly, using CredSSP should be avoided. Period. Using it during a security investigation in a compromised environment may actually be increasing risk by exposing more privileged credentials to an adversary. For more on that, read this.
At this point, you know what took me awhile to figure out and you could start writing your own code with these lessons in mind. Or you could check out Kansa, a free, open source, PowerShell-based incident response framework hosted at https://github.com/davehull/Kansa.
Kansa is modular. It features a core script, dozens of collector modules and analysis scripts to help make sense of the data collected. Kansa takes advantage of Windows Remote Management and PowerShell remoting. It uses PowerShell’s default non-delegated Kerberos network logons, not CredSSP and therefore does not expose credentials to harvesting.
Let’s take a deeper look at Kansa. After downloading the latest release from https://github.com/davehull/Kansa/releases, unzip it. You’ll need to unblock the scripts before you can run them on your local machine. The easiest way to do this is to open a PowerShell prompt and cd into Kansa’s top level directory and run the following command:
ls -r *.ps1 | unblock-file
Before we dive in and run the script, let’s take a look at the contents of the main directory:
Analysis
Modules
.gitignore
contributing.md
kansa.ps1
LICENSE
MSLimitedPublicLicense.txt
README.md
ToDo
Kansa’s primary purpose is to make it easier to collect data from many hosts, but you’ll notice the first directory above is called Analysis. Kansa comes with dozens of scripts to help analyze the data it collects, we’ll come back to that in a bit.
The Modules directory contains all of the collector scripts that the main script, Kansa.ps1, will invoke on hosts also known as targets in Kansa’s parlance. The other files in the listing above are obviously licenses, some explanation of what Kansa is and a ToDo list, though most items are tracked via issues on GitHub.
Just about all of the code that makes up Kansa is licensed under the Apache Version 2.0 license. There’s a small bit of code licensed under the Microsoft Limited Public License. See the respective license files for details, if you have concerns.
We’ll dive into the Modules directory and look at the collectors and discuss some things about Kansa.ps1 as the need arises. A directory listing of the Modules folder shows the following items:
ASEP
bin
Config
Disk
Log
Net
Process
default-template.ps1
Modules.conf
The last two items above are files, everything else is a directory. The default-template.ps1 is a simple example script with some code in it that I’ve found myself using in multiple modules.
Modules.conf is a configuration file that controls which modules Kansa.ps1 will invoke and the order in which they will be invoked. Why does the order matter? Incident responders collecting data from running systems want to collect data in the “order of volatility,” or starting with the most volatile data – the contents of memory, network connections and running processes and then move to less dynamic items like files on disk; this is because the actions of the investigator will affect the contents of RAM, possibly network connections and running processes.
In Modules.conf there is one module per line. Commenting out a line, prevents that module from being run.
Let’s return to the directories found under Modules starting with ASEP. If you’re not familiar with ASEP, it’s an acronym for Auto-Start Extension Point. These are locations in Windows that can be used to configure code to run either at system start or in response to some Windows event. As such, these locations are commonly used by attackers as a means of maintaining persistence in Windows environments.
A directory listing of the ASEP folder shows the following:
Get-Autorunsc.ps1
Get-PSProfiles.ps1
Get-SvcAll.ps1
Get-SvcFail.ps1
Get-SvcTrigs.ps1
Get-WMIEvtConsumer.ps1
Get-WMIEvtFilter.ps1
Get-WMIFltConBind.ps1
Each of these scripts are collectors that Kansa.ps1 may invoke on targets, depending on the Modules.conf file or if specified via the -ModulePath argument. There are over 40 collector scripts and I won’t go into detail on all of them, but I will discuss some.
The first script, Get-Autorunsc.ps1 takes a dependency on Sysinternals Autorunsc.exe, a great utility for gathering data from many known ASEP locations, including the path to the executable or script, command line arguments and cryptographic hashes, such as MD5.
Kansa is not limited to Windows built-in commands or PowerShell cmdlets. If you want to collect data using some third-party binary, simply copy that binary into the ._\Modules\bin_ directory and include a special comment on the second line of your collector module script to direct Kansa to copy the given binary to your targets, prior to running that collector. This special comment, what I refer to as a directive, for Get-Autorunsc.ps1 looks like this:
# BINDEP .\Modules\bin\Autorunsc.exe
BINDEP is simply shorthand for “binary dependency.” With this directive in place, if Kansa.ps1 is run with the -Pushbin argument, it will recognize that it needs to copy .\Modules\bin\Autorunsc.exe to its targets. These binaries are not generally removed after being copied to remote hosts, though this depends on the module, so future Kansa runs may not require the -Pushbin argument.
Get-PSProfiles.ps1 acquires copies of PowerShell profiles from both system default locations and individual user’s accounts. Attackers have planted code in these profiles as a means of maintaining persistence by having their code execute when user’s open PowerShell prompts. Autoruns does not currently collect information about this ASEP.
Get-SvcAll.ps1 collects information about all the services on targets.
Get-SvcFail.ps1 collects information about service recovery options. Most services are configured to simply restart as a recovery option, but one of the possible recovery options is to run arbitrary code. Autoruns does not currently collect data about this ASEP.
Get-SvcTrigs.ps1 collects information about service triggers. Windows services are no longer limited to starting at system start or starting manually. They can also start and stop based on the presence of Bluetooth or USB mass storage devices or even in response to arbitrary Windows events. Autoruns does not currently collect information about this ASEP.
Get-WMIEvtConsumer.ps1 collects data about WMI Event Consumers, which when combined with WMI Event Filters and WMI Filter-to-Event Consumer Bindings can be used to run arbitrary code in response to Windows events. Malware authors have been using WMI Event Consumers as a persistence mechanism for some time and until very recently, Autoruns did not collect information about this ASEP and even now it doesn’t collect information about the Event Filter, which is what triggers the Event Consumer.
The next directory under _.\Modules_ is bin, which we’ve already touched on so let’s move on to _.\Modules\Config_. In that directory you’ll find the following:
Get-AMHealthStatus.ps1
Get-AMInfectionStatus.ps1
Get-CertStore.ps1
Get-GPResult.ps1
Get-Hotfix.ps1
Get-IIS.ps1
Get-LocalAdmins.ps1
Get-Products.ps1
Get-SmbShare.ps1
The _Get-AM*_ scripts collect data about the status of Microsoft’s Anti-Malware client and the rest of these collectors are self-explanatory based on their names. Next stop on our rapid tour of Kansa, _.\Modules\Disk_, which contains:
Get-File.ps1
Get-FlsBodyfile.ps1
Get-TempDirListing.ps1
Get-File.ps1 needs to be configured by whoever is running Kansa and it is used to acquire a specific file, but remember, it will try and acquire that file from every host, so use it to collect common files if you’re running with multiple targets.
Get-FlsBodyFile.ps1 requires Fls.exe and some dlls from the Sleuth Kit, an open source digital forensics framework available from http://www.sleuthkit.org. This collector’s BINDEP directive looks like this:
# BINDEP .\Modules\bin\fls.zip
fls.zip has to be created by the user, it’s not packaged with Kansa. Directions for putting together fls.zip are in the Get-FlsBodyFile.ps1 script and that collector is written to decompress the zip archive and then execute fls and send its output back to the host where Kansa was run.
So what is fls? It’s like dir or ls on steroids and will pull directory listings for both allocated and unallocated (deleted) files, including time stamps and MFT File Reference numbers, all of which can be very useful during investigations. Next up _.\Modules\Log_:
Get-LogAppExperienceProgInventory.ps1
Get-LogAppExperienceProgTelemetry.ps1
Get-LogAppLockerExeDll.ps1
Get-LogAppLockerMSIScript.ps1
Get-LogAppLockerPackagedAppDeployment.ps1
Get-LogCBS.ps1
Get-LogSecurity.ps1
Get-LogShellCoreOperational.ps1
Get-LogTermSrvcsLocalSessionMgrOperational.ps1
Get-LogTermSrvcsRemoteConnMgrOperational.ps1
Get-LogUserAssist.ps1
Most of these are probably easy to understand based on file names, but let’s cover the last one.
Get-LogUserAssist.ps1 doesn’t actually acquire data from a log file, instead it reads from each user’s ntuser.dat file and pulls out the contents of the UserAssist key. UserAssist is a Registry key that stores information about execution of programs and control panel applets that happen via the Windows GUI. On some versions of Windows, UserAssist also tracks run count and since Registry keys have LastWriteTimes (also acquired by the script) the data may give some insight into when a given program was run.
The next set of collectors are found in _.\Modules\Net_ and the listing contains:
Get-Arp.ps1
Get-DNSCache.ps1
Get-NetIPInterfaces.ps1
Get-NetRoutes.ps1
Get-Netstat.ps1
Get-SmbSession.ps1
These should be largely self-explanatory, but let’s take a moment to look at Get-Netstat.ps1 in a little detail. As you may have guessed, this collector runs Netstat on each target, but it runs it with the -naob arguments. If you run this on your systems, your output may look something like the following attached photos.

Imagine collecting this data from thousands of hosts. How would you analyze it? It doesn’t easily lend itself to automated analysis. Get-Netstat.ps1 takes this output and converts it to PowerShell objects. You can run Get-Netstat.ps1 on your own local machine, all of the collectors can be run locally, and the output will look like this attached photos.

Because PowerShell objects can easily be converted to a variety of output formats, this data is converted by Kansa.ps1 to TSV and the final result looks like this attached photo.

This is data that can be easily imported into Excel or a database or analyzed using Microsoft’s free LogParser tool.
But why does Kansa.ps1 convert it to TSV? This is actually controlled by Get-Netstat.ps1 via another special comment directive that tells Kansa how to handle the data returned by the modules. In the case of Get-Netstat.ps1, this directive looks like this:
# OUTPUT tsv
The supported output types are bin for binary files (i.e. memory dumps), CSV/TSV, txt, XML and zip. If a module doesn’t return PowerShell objects, the output type should be one of bin, txt or zip.
The next set of collectors are in _.\Modules\Process_ and are all process related:
Get-Handle.ps1
Get-PrefetchFiles.ps1
Get-PrefetchListing.ps1
Get-ProcDump.ps1
Get-ProcsWMI.ps1
Get-Prox.ps1
Get-RekalPslist.ps1
Get-Tasklistv.ps1
Again, many of these are likely self-explanatory, but let’s touch on a few. Get-Handle.ps1 is another that depends on a Sysinternals utility, this time Handle.exe. Get-PrefetchFiles.ps1 and Get-PrefetchFileListing.ps1 both pull data from _$env:windir\Prefetch_ with the first adding all .pf files in that directory to a zip archive and sending them back to the host where Kansa was run. Get-PrefetchFileListing.ps1 simply returns the directory listing along with time stamp information.
If you’re not familiar with the Windows Prefetch, it’s a feature that’s enabled on Windows desktop OSes, but turned off by default on servers and its purpose is to improve performance, but it has side-effects that benefit forensic investigators and incident responders. Prefetch files include a run count that is incremented each time a program is run. That incrementing requires a modification to the respective .pf file and that means that .pf file’s LastWriteTime will be updated, providing a solid indicator of when the program was run.
Get-ProcDump.ps1 uses Sysinternals ProcDump.exe command to collect a specified process’s memory. Naturally this must be configured to grab the process of interest.
Get-ProcsWMI.ps1 uses Get-WmiObject to pull information about running processes including parent process ID, process creation time, and command line arguments for running processes. This script also pulls MD5 hashes of the process’s image on disk. Other hashes are available by tweaking the script to return a different hash.
Get-Prox.ps1 runs the PowerShell Get-Process cmdlet, which returns some great information including loaded modules and data about threads, but it doesn’t return command line arguments, parent process ID or information about the process owner, hence the need for Get-ProcsWMI.ps1. We’ll come back to Get-RekalPslist.ps1 in a moment.
The Get-Tasklistv.ps1 script returns process session name, session number and process owner all of which can be useful during investigations.
It would be awesome if PowerShell’s Get-Process cmdlet would return all of its great data, plus the items gathered by Get-ProcsWMI.ps1 and the two Get-Tasklist scripts, but for now, we have to run multiple scripts to get the data we need. I have opened issues with the PowerShell team requesting these improvements to Get-Process. You can vote up my open issue here.
Back to Get-RekalPslist.ps1. This collector is a useful proof-of-concept, but not something I use very often. One of the issues savvy IR folks have raised about Kansa is that it relies on the Windows API for most of the data it collects. If an attacker is using rootkits, they may be subverting those API calls and causing them to return bogus data.
For this reason, most IR folks prefer tools that don’t rely on the Windows API. One common technique is to use a tool to acquire a copy of a system’s memory, there are a variety of tools for this, but WinPMem may be the current best of breed and it’s also free as part of the Rekall Memory Forensic Framework (http://www.rekall-forensic.com/about.html). Rekall is a fork of the Volatility Memory Analysis Framework (http://www.volatilityfoundation.org/).
One benefit of Rekall over Volatility is that it can be used to perform memory analysis on running systems without first having to acquire a copy of memory and without the need for commercial tools to expose live memory for analysis (this is the current requirement for Volatility to do live memory analysis). When working with systems around the world that may commonly have 192 GB of RAM, having to acquire a copy of memory for analysis can be problematic.
With that lengthy explanation of Rekall out of the way, what does Get-RekalPslist.ps1 do then? When Kansa.ps1 is run with the -Pushbin argument, it directs Kansa to copy a zip archive of Rekall to targets, this is a whopping 17 MB file, then it decompresses the archive to a 35 MB folder on the target, loads the winpmem.sys driver, which has ring 0 access and then calls the PSlist module to acquire information about processes from memory, including recently exited processes and unlinked processes that may be hidden by rootkits. Rekall has many other useful plugins for finding data that may be inaccessible via APIs, if rootkits are in play.
So even though Kansa relies on PowerShell and PowerShell relies on the Windows API and the Windows API can be subverted by adversaries and therefore provide unreliable information, there are workarounds. And that’s it for the current set of collectors.
So, how do we run Kansa?
Below is an example command line for running Kansa:
PS C:\tools\Kansa> .\kansa.ps1 -TargetList .\hostlist -Pushbin -Verbose
Let’s discuss the command line arguments. -TargetList .\hostlist tells kansa.ps1 to run collectors against the systems listed in the hostlist file, which contains one host per line. If you omit this argument, Kansa will query ActiveDirectory for the list of computers and target all of them. Querying AD in this way requires this ActiveDirectory module that’s bundled with Remote Server Administration Tools so you’ll need that installed if you’re not providing a list of targets via -TargetList (http://www.microsoft.com/en-us/download/details.aspx?id=39296). -Pushbin instructs kansa.ps1 to copy any required third-party binaries to targets.
You can see by the output that my .\hostlist file in this example only contains two hosts. I have run Kansa against thousands of hosts at a time located around the world and in my experience, it generally completes its collection in under an hour, but there are many variables to consider including which modules you run, where your hosts are located, how much bandwidth you have, etc. In my example run above, each host returned about 100 MB of data, but again, this will vary based on which modules you run.
After Kansa finishes running, it will let you know if encountered any errors by telling you to look in the Errors.log file which will be in the Output directory. All Output directories are time stamped. Let’s take a look at the one that was just created as part of the sample run above:
I ran the ls command above before the script completed, but you can see that Kansa creates an output directory for each module. If we dive in one more layer, you’ll see that each host’s output is broken out in each module output directory:
That covers it from the collection side of the house, but there’s more to cover.
Data requires analysis
Recall from earlier in this post when we first extracted the Kansa release archive. We noted the presence of an Analysis subfolder. Kansa’s original purpose may have been about acquiring data, but acquired data must be analyzed in order to be useful during an investigation. So Kansa includes a few dozen scripts that can be used to analyze the collected data. Many of these require Microsoft’s free LogParser utility and they expect it to be in the path.
Let’s take this from the top with a look in the Analysis folder:
ASEP
Config
Log
Meta
Network
Process
You’ll notice the directory structure here follows closely with the directory structure under the _.\Modules_ path. Under the ASEP folder, you’ll see:
Get-ASEPImagePathLaunchStringMD5Stack.ps1
Get-ASEPImagePathLaunchStringMD5UnsignedStack.ps1
Get-ASEPImagePathLaunchStringPublisherStack.ps1
Get-ASEPImagePathLaunchStringStack.ps1
Get-ASEPImagePathLaunchStringUnsignedStack.ps1
Get-SvcAllRunningAuto.ps1
Get-SvcAllStack.ps1
Get-SvcFailAllStack.ps1
Get-SvcFailCmdLineStack.ps1
Get-SvcFailStack.ps1
Get-SvcStartNameStack.ps1
Get-SvcTrigStack.ps1
Again, I won’t detail all of the analysis scripts, but I will cover a few. For the most part, the analysis scripts perform frequency analysis. Kansa’s strength is that it makes it easy for investigators to collect data from many machines. Frequency analysis makes it easy to spot anomalies in environments, especially if you’re comparing machines that are well-managed and that should be similar in configuration – say maybe all systems in a given department, Human Resources or Finance, or servers in a data center belonging to a specific role – database servers, web servers, etc.
The _Get-ASEP*_ scripts above perform frequency analysis of data collected by _Get-Autorunsc.ps1_. The first one, _Get-ASEPImagePathLaunchStringMD5Stack.ps1_ performs frequency analysis of Autorunsc data aggregated on the path to the executable or script (ImagePath), the command line arguments (LaunchString) and the MD5 hash of the binary or script on disk. The next analysis script performs the same frequency analysis, but it filters out executables that have valid code signing certificates, which may not be given that attackers have been known to steal code signing certs and use them to sign malware.
Here’s an example of stacked output for unsigned Get-Autorunsc.ps1 data collected from 10 domain controllers:
cnt Image Path                                            MD5
--- ----------------------------------------------------- --------------------------------
10  c:\windows\system32\cpqnimgt\cpqnimgt.exe             78af816051e512844aa98f23fa9e9ab5
10  c:\hp\hpsmh\data\cgi-bin\vcagent\vcagent.exe          54879ccbd9bd262f20b58f79cf539b3f
10  c:\windows\system32\cpqmgmt\cqmgstor\cqmgstor.exe     60668a25cfa2f1882bee8cf2ecc1b897
10  c:\program files\hpwbem\storage\service\hpwmistor.exe 202274cb14edaee27862c6ebce3128d8
10  c:\hp\hpsmh\bin\smhstart.exe                          5c74c7c4dc9f78255cae78cd9bf7da63
10  c:\msnipak\win2012sp0\asr\configureasr.vbs            197a28adb0b404fed01e9b67568a8b5e
10  c:\program files\hp\cissesrv\cissesrv.exe             bf68a382c43a5721eef03ff45faece4a
The first column here is the count or the frequency of occurrence for the give Image Path and its associated MD5 hash. We can see that all 10 domain controllers have the same set of seven unsigned ASEPs, so there are no outliers here, but if we wanted to analyze this further, we could copy the MD5 hashes and search for them in NIST’s National Software Reference Library (http://www.nsrl.nist.gov/) or in VirusTotal (https://www.virustotal.com/#search) and see if they come back as clean, malicious or unknown.
Under _.\Analysis\Config_ there is a single script, Get-LocalAdminStack.ps1, which can be used to find unusual local administrator accounts.
_.\Analysis\Log_ also contains a single analysis script, Get-LogUserAssistValueStack.ps1, which is useful for finding unusual entries from the UserAssist data that was collected by Kansa.
There are two scripts under _.\analysis\Meta_:
Get-AllFileLengths.ps1
Get-FileLengths.ps1
Unlike most of the analysis scripts, these two don’t perform frequency analysis. But they are still useful for spotting outliers. You can run the first one to return a grid view window of all the collected Kansa output files and their lengths and the second one will return a grid view window of some specific collected files and their lengths. What’s useful about this? Recall the discussion about WMI Event Consumers? Below is the output of Get-FileLengths.ps1 –FileNamePattern *wmievtconsmr.xml:
Each BaseName in the grid view window above contains the name of a fictitious system, followed by an underscore and an indicator of the data contained in the file, so these are WMI Event Consumers from many hosts, several thousand in this case. Simply sorting by file size is enough to find outliers. Analysis does not have to be complicated to be effective.
In the _.\Analysis\Net_ directory, you’ll find the following analysis scripts:
Get-ARPStack.ps1
Get-DNSCacheStack.ps1
Get-NetstatForeign16sStack.ps1
Get-NetstatForeign24sStack.ps1
Get-NetstatListenerStack.ps1
Get-NetstatStack.ps1
Get-NetstatStackByProtoForeignIpStateComponentProcess.ps1
Get-NetstatStackForeignIpPortProcess.ps1
Get-NetstatStackForeignIpProcess.ps1
The purpose of each of these should be fairly apparent. Get-NetstatForeign16sStack.ps1 and Get-NetstatForeign24sStack.ps1 are useful for getting an idea of what networks your hosts may be communicating with. These scripts will likely need some editing for your environment as they currently make assumptions about internal networks using RFC1918 addresses. The 16 and 24 scripts, as you may guess, apply CIDR block notation and aggregate connections based on the first two and three ForeignAddress octets, this may not be the most accurate analysis, but it’s good for quick analysis.
And lastly the analysis scripts in _.\Analysis\Process_:
Get-HandleProcessOwnerStack.ps1
Get-PrefetchListingLastWriteTime.ps1
Get-PrefetchListingStack.ps1
Get-ProcsWMICLIStack.ps1
Get-ProcsWMICmdlineStack.ps1
Get-ProcsWMISortByCreationDate.ps1
Get-ProcsWMITempExePath.ps1
Get-ProxSystemStartTime.ps1
I won’t go into details on these as I think you can get an idea of what they do based on their names and if you want to know more about them, check out the project on GitHub.
Data collected and analyzed, next step: Remediation
You’ve seen how Kansa can be used to collect and analyze data. If you were working a real security incident, at this point you may have a good understanding of your adversary, what backdoors they’ve planted, what processes they’ve injected into, what domains they are using for command and control (C2) and you may have figured out how they originally entered the environment.
The next thing to do is make sure the original vector is fixed so they can’t use it to come back, then you’ve got to carefully execute a very well-coordinated remediation plan. Remediation planning should take place in parallel with your investigation. As you find new adversary artifacts, someone on the team should be documenting how they will need to be remediated. Say you find evidence that the adversary has run a credential stealing tool on many hosts, you know that you should roll all passwords in the environment. If you’ve found C2, you may want to block access to it during remediation. For all the backdoors you’ve found, figure out how to remove them. You may have to wipe hard drives and completely re-install many systems or in a worst case scenario, completely forklift hardware.
I have worked cases against red teams, however, where they used a fairly light touch, installing backdoors that could be easily removed, injecting into processes that could be stopped and restarted without impacting services. If you find yourself working a similar case, you can use Kansa for remediation.
You can write a PowerShell script to carry out remediation tasks – stopping rogue processes, removing persistence mechanisms, implementing host-level firewall rules to block C2, etc. Maybe you save this script as Get-Remediation.ps1, then you run the following command:
.\kansa.ps1 –ModulePath .\Get-Remediation.ps1 –TargetList Owned –ThrottleLimit 100
Because you’re carrying out actions that likely won’t be returning any data, you may safely bump up the -ThrottleLimit allowing you to act quickly, ideally before your adversary has a chance to respond.
With round one of remediation completed, you’ll want to closely monitor your environment for any signs that the adversary is still active. There may be things you missed, like that web shell they planted, but never used and so the battle continues.
I hope you’ve enjoyed this tour of Kansa and its capabilities. It’s been one of the most fun and rewarding personal projects I’ve undertaken. It scratches a personal itch, but I sincerely hope that others find it useful, as well. I hope you’ll check it out and please contribute, whether its code, bugs or feature requests.

Jamalhoseinshah@gmail.com 
