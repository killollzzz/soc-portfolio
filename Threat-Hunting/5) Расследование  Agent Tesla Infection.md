**Дата расследования:** 05.07.2026  
**Источник:** Malware Traffic Analysis  
**Файл:** `2020-11-06-possible-Agent-Tesla-traffic.pcap`  
**Длительность:** ~1 час 22 секунды  
**Пакетов:** 820  
**Жертва:** `10.11.6.101`

---

## Ход расследования

### Шаг 1: Общая статистика

|Метрика|Значение|
|---|---|
|Пакетов|820|
|Длительность|1 час 22 сек|
|SYN|8|
|ACK|810|

### Шаг 2: DNS-запросы

|#|Домен|IP|Назначение|
|---|---|---|---|
|1|`cp87128.tmweb.ru`|`185.114.245.201`|Сервер загрузки вредоноса|
|2|`api.ipify.org`|`54.235.142.93`|Получение внешнего IP жертвы|
|3|`mail.nartaccess.com`|`178.18.200.18`|C2-сервер (экфильтрация)|

### Шаг 3: HTTP-трафик

|#|Направление|URL|Код|
|---|---|---|---|
|6|Жертва → 185.114.245.201|`GET /tender.exe`|-|
|741|185.114.245.201 → Жертва|`tender.exe`|200 OK (712 КБ)|
|749|Жертва → 54.235.142.93|`GET /` ([api.ipify.org](https://api.ipify.org))|-|
|751|54.235.142.93 → Жертва|Ответ с IP|200 OK|

### Шаг 4: Извлечение файла

- **Файл:** `tender.exe`
    
- **Размер:** 712 КБ
    
- **Content-Type:** `application/octet-stream`
    
- **SHA256:** `ae1030f0ff069ac50dea9f299186507db2223f47fc51d1952c92d4709ba56190`
    
- **VirusTotal:** 37/50 (Agent Tesla)
    

---

## Индикаторы компрометации (IOC)

|Тип|Значение|
|---|---|
|SHA256|`ae1030f0ff069ac50dea9f299186507db2223f47fc51d1952c92d4709ba56190`|
|Домен загрузки|`cp87128.tmweb.ru`|
|IP загрузки|`185.114.245.201`|
|Файл|`tender.exe`|
|C2-домен|`mail.nartaccess.com`|
|C2-IP|`178.18.200.18`|

---

## MITRE ATT&CK

|Тактика|Техника|ID|
|---|---|---|
|Initial Access|Spearphishing Attachment|T1566.001|
|Execution|User Execution: Malicious File|T1204.002|
|Defense Evasion|Masquerading (tender.exe)|T1036|
|Discovery|System Information Discovery ([api.ipify.org](https://api.ipify.org))|T1082|
|Command & Control|Web Protocols|T1071.001|
|Exfiltration|Exfiltration Over C2 Channel|T1041|

---

## Splunk-правило

```spl
index=web_logs (uri="*tender.exe*" OR uri="*api.ipify.org*" OR uri="*mail.nartaccess.com*")
| table _time, client_ip, uri, method, status
```

---

## Рекомендации

1. Заблокировать `185.114.245.201`, `178.18.200.18`, `cp87128.tmweb.ru`, `mail.nartaccess.com`
    
2. Проверить другие хосты на наличие `tender.exe` (SHA256: `ae1030f0...`)
    
3. Добавить IOC в SIEM
    
4. Провести тренинг по фишингу (если заражение через почту)
    

---