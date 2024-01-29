## What is shiv?

Shiv is a simple, easy-to-use tool designed for performing Windows local, network, & domain enumeration. It also has modules for remotely executing commands on neighboring systems.

## Why Use shiv?

- **Evasive**: Allows you to perform basic system, network, and domain enumeration without using built-in tools that could have detection signatures (net, qwinsta, psexec, wmic, systeminfo)
- **Interactive or Batch Interface**: It can be executed without any commands to behave like an interactive shell or with parameters to execute specific tasks.
- **Lightweight**: Easy to deploy without any additional libraries or dependencies. Can be also compiled as a DLL or shellcode without any issue.

## Getting Started

To get started with shiv:

```
Usage: shiv.exe [Options...]
        -s hosts        Hosts - can be in comma separated list, ip address, hostname, or ip address range
        -p ports        Ports - can be in comma separated list, single port, or hyphen seperated range

        -c command      Command - command to execute on remote host or arguments for shellcode binary
        -b type         Execution Type - WinRM (port 5985) SMB (445)
        -f path         Executable Path - The local executable binary (x64) to inject into memory and execute remotely (SMB)

        -d domain       Domain - domain for remote authentication or domain controller for AD functions
        -u user         User - username for remote command (i.e. joe, joe@DOMAIN)
        -P pass         Password - password for user
        -o pass         Old Password - old password for user

        -g group        Group - list users in group
        -t time         Timeout - in seconds to wait for connections
        -l log          Log Path - change the output to a file path or "stdout"
        -v val          Verbosity - up to three levels of verbosity

        -x              Sessions - list sessions on host (port 445)
        -z              Server Info - list OS, hostname, domain of server via SMB (port 445)
        -n              Change Password - change the user's pw on the host
        -r              Shares - list shares on hosts (port 445)
        -e              Web Endpoints - list any web endpoints listed in C:\Windows\System32\inetsrv\applicationHost.xml
        -i              WMI netstat - list network connection info on host (port 135)
        -y              Processes - list process information on current host
        -a              Password Spray - attempt to login to every domain user with the given password
        -E              Local enumeration - Enumerate current system. e.g. IP Address, Hostname, PATH, user
        -h              Help - print this help message

Example: shiv.exe -s 172.16.4.0/27,172.16.0.1 -p 135,443,500-800 -t 2
```

### 1. Port scan

```
shiv -s 192.168.162.145 -p22,80,135,3389,445
```
```
[+] Scanning hosts:

[+] Host: 192.168.162.145 has the following ports open:
        [+] Port 135 is open
        [+] Port 445 is open
        [+] Port 3389 is open

[+] Scanning finished
```

### 2. Get detailed process list (PID, PPID, Privilege, Path, Listening Ports, Service Name )

```
shiv -y
```
```
PID,PPID,Session Id,Username,Arch,Binary Name,Binary Path,Service Name,Open Ports,Connections
1116,704,0,LocalSystem,Unknown,svchost.exe,"C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p",NcbService,"","",
0,0,0,,Unknown,[System Process],"",,"","",
1232,704,0,LocalSystem,Unknown,svchost.exe,"C:\WINDOWS\system32\svchost.exe -k netsvcs -p",Schedule,"TCP4:49667,TCP6:49667,","",
108,4,0,,Unknown,Registry,"",,"","",
1128,704,0,NT AUTHORITY\LocalService,Unknown,svchost.exe,"C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p",TimeBrokerSvc,"","",
4,0,0,,Unknown,System,"",,"TCP4:445,TCP4:139,TCP6:445,UDP4:137,UDP4:138,","",
3372,704,0,localSystem,Unknown,svchost.exe,"C:\WINDOWS\system32\svchost.exe -k netsvcs -p",Winmgmt,"","",
2512,704,0,LocalSystem,Unknown,svchost.exe,"C:\WINDOWS\System32\svchost.exe -k netsvcs -p",ShellHWDetection,"","", 
...
```

### 3. Execute command using WMI

```
shiv -s 192.168.162.145 -p135 -b wmi -c whoami
```
```
[+] Scanning hosts:

[+] Host: 127.0.0.1 has the following ports open:
        [+] Port 135 is open

[+] Scanning finished
```

## References

Shiv integrates code/ideas from the following repos for some of its functionality. Checkout out these projects and much thanks for their contributions to the community!

https://github.com/TheWover/donut
https://github.com/fortra/impacket
https://github.com/gentilkiwi/mimikatz
