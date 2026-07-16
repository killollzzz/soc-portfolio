**1. Подозрительные User-Agent (инструменты хакеров)**

```spl
index=* ("sqlmap" OR "nmap" OR "nikto" OR "gobuster" OR "hydra" OR "metasploit" OR "masscan")
```

**2. Эксплуатация известных уязвимостей**

```spl
index=* ("eval-stdin.php" OR "phpunit" OR "struts" OR "log4j" OR "thinkphp" OR "drupal")
```

**3. Ошибки сервера (500, 502, 503) — возможная атака**

```spl
index=* (" 500 " OR " 502 " OR " 503 ")
| timechart count
```

**4. Поиск powershell -enc

```spl
index=* ("-EncodedCommand" OR "-enc" OR "FromBase64String")
```

**5. Поиск скачивания через powershell

```spl
index=* ("DownloadString" OR "Net.WebClient" OR "IEX" OR "Invoke-Expression")
```

**6. Алерт на Lumma Stealer

```spl
index=web_logs (uri="*sinitjq.cyou*" OR uri="*set_agent*" OR uri="*act=log*")
| table _time, client_ip, uri, method, status
```

**7. Алерт на Kongtuke ClickFix.m

```spl
index=web_logs (uri="*1.php*" OR uri="*st2*" OR uri="*getarchive*" OR uri="*installreport*" OR uri="*archivehash*")
| table _time, client_ip, uri, method, status
```

**8. Алерт на GeoIP Check (ipinfo.io)

```spl
index=web_logs (uri="*/city*" OR uri="*/region*" OR uri="*/country*") AND uri="*ipinfo.io*"
| table _time, client_ip, uri, method, status
```

**9. Алерт на `njRAT MassLogger`
[[8) Расследование njRAT + MassLogger Infection]]
```spl
index=web_logs (uri="*cphost14.qhoster.net*" OR uri="*api.telegram.org*" OR uri="*reallyfreegeoip.org*" OR uri="*ip-api.com*" OR uri="*checkip.dyndns.org*")
| table _time, client_ip, uri, method, status
```

**10. Алерт на Сканирование `.env` и конфигов.

```spl
index=web_logs (uri="*.env*" OR uri="*.git/config*" OR uri="*wp-config.php*" OR uri="*config.json*" OR uri="*config.yml*")
| bucket _time span=5m
| stats count by _time, client_ip, uri
| where count > 3
| table _time, client_ip, uri, count, method, status
```

**11. Алерт на экспорт данных через Telegram API

```spl
index=web_logs uri="*api.telegram.org*"
| table _time, client_ip, uri, method, status
```

**12. Алерт на Mozi-ботнета

```spl
index=web_logs (uri="*Mozi.a*" OR uri="*chmod 777*" OR uri="*wget*") | table _time, client_ip, uri, status
```

**13. Алерт на Guloader Detection

```spl
index=web_logs (uri="*drive.google.com/uc?export=download*" OR uri="*ip-api.com/line/?fields=hosting*")
| table _time, client_ip, uri, method, status
```

**14. Алерт на DGA Domains Detection**

```spl
index=web_logs (uri="*obsidiangate.space*" OR uri="*focusgroovy.com*" OR uri="*thunderplanethub.top*" OR uri="*northernbridgeworks.com*")
| table _time, client_ip, uri, method, status
```
