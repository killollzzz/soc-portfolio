**1. Алерт на Lateral Movement (EventCode=4648)

```spl
index=windows EventCode=4648
| bucket _time span=10m
| stats count by _time, client_ip, TargetUserName, host
| where count > 3
| table _time, client_ip, TargetUserName, host, count
```

**2. Алерт на подозрительный Powershell

```spl
index=windows EventCode=4688 (CommandLine="*-EncodedCommand*" OR CommandLine="*-w hidden*" OR CommandLine="*-nop*" OR CommandLine="*-exec bypass*")
| table _time, host, user, CommandLine
```

**3 Алерт на Брутфорс RDP

RDP-это удаленный доступ к винде, на протоколе 3389

```spl
index=windows EventCode=4625 LogonType=10
| bucket _time span=5m
| stats count by _time, IpAddress, TargetUserName, host
| where count > 5
| table _time, IpAddress, TargetUserName, host, count
```

**4. Алерт на фишинг — Outlook запускает EXE

```spl
index=sysmon EventCode=1 ParentImage="*outlook.exe*"  Image ="*.exe*"
| table _time, CommandLine, Computer, User
```

 **5. Алерт на Pass-the-Hash

**Pass-the-Hash (PtH)** — атака, при которой злоумышленник использует **хеш пароля** вместо самого пароля для входа в систему.

```spl
index=windows EventCode=4624 LogonType=9
| table _time, TargetUserName, IpAddress, host
```

**6. Алерт MITRE ATT&CK: Lateral Movement через WMI

```spl
index=sysmon EventCode=1 ParentImage="*wmiprvse.exe*" (Image="*cmd.exe*" OR Image="*powershell.exe*")
| table _time, CommandLine, Computer, User, SourceIp, DestinationIp
```

**7. Алерт на детект блокировок Windows Firewall

```spl
index=windows EventCode=5157
| bucket _time span=5m
| stats count by _time, SourceIp, DestinationIp, DestinationPort
| where count > 10
| table _time, SourceIp, DestinationIp, DestinationPort, count
```

