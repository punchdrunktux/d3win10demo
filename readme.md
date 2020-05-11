

## Objective: ##
Demonstrate a means of testing Win10 security features against MITRE ATT&CK, in a repeatable fashion by D3-3.  Ensure that the security function is enabled and somewhat effective against basic, well-known tactics.

## Components: ##

### MITRE ATT&CK ###

    MITRE ATT&CK® is a knowledge base of adversary tactics and techniques based on real-world observations. 
    
    https://attack.mitre.org/

### Windows 10 ### 
    Windows 10 1809, running Sy's win10 configuration to be tested.

### Sysmon ###
    System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log.
    
     https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

### Sysmon Config (Olaf) ### 
    Sysmon configuration repository, aligned with MITRE ATT&CK
    
    https://github.com/olafhartong/sysmon-modular

### AtomicRedTeam ###
    Atomic Red Team allows every security team to test their controls by executing simple "atomic tests" that exercise the same techniques used by adversaries (all mapped to Mitre's ATT&CK).
    
    https://github.com/redcanaryco/atomic-red-team

### Invoke-AtomicRedTeam ###
    Invoke-AtomicRedTeam is a PowerShell module to execute tests as defined in the atomics folder of Red Canary's Atomic Red Team project.
    
    https://github.com/redcanaryco/invoke-atomicredteam

------
## Overview: ##

- Use Win10 configured per Sy's instructions / Defender AV disabled
- Install Sysmon to capture granular system events
- Install AtomicRed MITRE ATT&CK tests & Invoke-AtomicRedTeam PowerShell Module
- Update SyBuild to address any failed tests
- Re-run AtomicRed test

---------

## Procedure ##

1. ### Sybuild with GPOs ###
   
2. ### Disable Windows Defender ###

3. ### Install Sysmon ###
   References:
   - Olaf Hartong sysmon config - https://github.com/olafhartong/sysmon-modular
   - TrustedSec Sysmon Guide - https://github.com/trustedsec/SysmonCommunityGuide
   - Process Access - https://github.com/trustedsec/SysmonCommunityGuide/blob/master/process-access.md
   - PS GumShoe (AccessMask) - https://github.com/PSGumshoe/PSGumshoe/tree/sysmon_events
    
   
 In a command window, as Admin:
	
```Invoke-WebRequest -Uri http://live.sysinternals.com/Sysmon64.exe -OutFile c:\temp\sysmon64.exe```
   
 Download sysmon config by Olaf Hartong ( https://github.com/olafhartong/sysmon-modular )
	
In Powershell, as Admin:
   
 ```Invoke-WebRequest -Uri https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -OutFile c:\temp\sysmonconfig.xml```
	
Load configuration into sysmon and install service
   
 ```sysmon64 /accepteula -I c:\temp\sysmonconfig.xml```
   
 Check the Access Masks from Sysmon
   
 ``` Import-Module ./PSGumshoe.psd1 ```
   
 ``` Get-SysmonAccessMask -AccessMask 0x143A```
   
4. ### Install RedCanary Atomic Red and Invoke-AtomicTest PowerShell Scripts ###
   ( https://github.com/redcanaryco )

    ```IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')```

    ```Install-AtomicRedTeam -getAtomics -Force```

    Note: each time you start a new powershell session, you'll need to load the module, per below.   The alternative is to add the module to your powershell profile.

    ``` Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force```
	
5. ### Choose MITRE ATT&CK Technique ###

    https://attack.mitre.org/

6. ### RedCanary AtomicTest ###

    Format: Invoke-AtomicTest <Tactic #> [options] 

    #### Get a list of all Procedures in a Tactic ####
    ```Invoke-AtomicTest T1003 -ShowDetailsBrief```

   #### View details of a Mimikatz PowerShell test ####

    ```Invoke-AtomicTest T1003 -TestNumber 2 -ShowDetails```

    #### Check to see if required prerequisites are met for the test ####

    ```Invoke-AtomicTest T1003 -TestNumber 2 -CheckPrereq```

    #### Get a list of all Procedures in a Tactic ####

    ```Invoke-AtomicTest T1003 -TestNumber 2 -GetPrereq```

    ####  Dump credentials from memory using Gsecdump ####

    ```Invoke-AtomicTest T1003 -TestNumber 2```

    ### Powershell Mimikatz ####

    ```Invoke-AtomicTest T1003 -TestNumber 1```

7.  ### Add Protection for LSASS ###

    https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

    To enable LSA protection on a single computer:

    	1. Open the Registry Editor (RegEdit.exe), and navigate to the registry key that is located at: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa.
    	2. Set the value of the registry key to: "RunAsPPL"=dword:00000001.
    	3. Restart the computer.
8. ### Re-run Credential Attacks ###


    #### Reload the Invoke-AtomicTest Module ####
    
    ``` Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force```
    
    #### Reload the Invoke-AtomicTest Module ####
    
    ```Invoke-AtomicTest T1003 -TestNumber 1,2 -GetPrereq```


    ####  Dump credentials from memory using Gsecdump ####
    
    ```Invoke-AtomicTest T1003 -TestNumber 2```
    
    ### Powershell Mimikatz ####
    
    ```Invoke-AtomicTest T1003 -TestNumber 1```

