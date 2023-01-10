**Title : Hunting the Execution of Sudoers File in Linux**

Threat actors and attackers gather victim permission levels and configuration when they have compromised the victim system. In the linux system, attackers abuse the /etc/sudoers file to know all user rights on compromised victim systems. 

**Detection**

Able to detect the execution of /etc/sudoers file to identify all users with sudo permissions.

ImageFileName :

/usr/bin * => /usr/bin/cat, /usr/bin/head etc 

/usr/bin => standard directory on the linux systems contains most of the executable files.

- '/cat'
- 'grep'
- '/head'
- '/tail'
- '/more'
- ‘/nano’
- ‘/vim’

Command Line: 

/etc/sudoers

**Possible Splunk Query** 

    index=main event_simpleName=ProcessRollup2* event_platform=Lin ImageFileName= "/usr/bin*"CommandLine="* /etc/sudoers"
    | eval timestamp=(timestamp/1000)+(7*3600), timestamp=strftime(timestamp,"%d/%m/%Y %H:%M:%S") 
    | stats values(CommandLine) as CommandLine, count(aid) as executionCount, values(timestamp) as time by aid, ComputerName, ImageFileName, ParentBaseFileName, FileName

**Explantation** 

In the first line query, get all process execution events by vim, nano, cat etc. from /usr/bin location and related with any command line arguments  /etc/sudoers in the linux system from our environment. 
To change the timestamp UTC format as a human readable format. 
In the final line query, do the statistical analysis by aid, ComputerName, ImageFileName, ParentBaseFileName, FileName, timestamp with command line execution statistical analysis.  

References

https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py 



