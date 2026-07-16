
**Дата расследования:** 08.07.2026  
**Источник:** Malware Traffic Analysis  
**Файл:** `2025-05-27-VIP-recovery-infection-traffic.pcap`  
**Длительность:** ~2 минуты 2 секунды  
**Пакетов:** 149  
**Жертва:** `10.5.27.101`

---

## Ход расследования

### Шаг 1: Общая статистика

|Метрика|Значение|
|---|---|
|Пакетов|149|
|Длительность|2 мин 2 сек|
|Внешних подключений|5 IP|

### Шаг 2: Вектор заражения

Согласно описанию к дампу:

- **Email** от `uyumelektrik.com` (`198.55.98.69`) → вложение `UYUM ELK...r01` (RAR-архив)
    
- Внутри архива — `UYUM ELK...exe` (VIP Recovery)
    
- После запуска EXE устанавливается в `C:\Users\[username]\AppData\Roaming\gCmiVoeYUJc.exe`
    

**MITRE ATT&CK:** T1566.001 (Spearphishing Attachment)

### Шаг 3: Цепочка заражения

|#|Время|Запрос|Описание|
|---|---|---|---|
|1|0.18с|GET `/` → `132.226.247.73`|Проверка IP ([checkip.dyndns.org](https://checkip.dyndns.org))|
|2-10|0.37-3.00с|GET `/` → `132.226.247.73`|Многократная проверка IP (10 запросов)|
|11|0.75с|TLS Client Hello → `104.21.64.1`|Геолокация ([reallyfreegeoip.org](https://reallyfreegeoip.org))|
|12|3.46с|TLS Client Hello → `149.154.167.220`|Экфильтрация через Telegram API|

### Шаг 4: C2-инфраструктура

|Домен|IP|Роль|
|---|---|---|
|`checkip.dyndns.org`|`132.226.247.73`|Проверка внешнего IP|
|`reallyfreegeoip.org`|`104.21.64.1`|Геолокация|
|`api.telegram.org`|`149.154.167.220`|Экфильтрация данных|

### Шаг 5: Экфильтрация через SMTP

Согласно описанию — дополнительно отправлял email через `mail.testeremarketim.com:587`.

### Шаг 6: Брутфорс / Lateral Movement

Отсутствует.

---

## Индикаторы компрометации (IOC)

|Тип|Значение|
|---|---|
|IP отправителя|`198.55.98.69`|
|Геолокация|`132.226.247.73`, `104.21.64.1`|
|Telegram API|`149.154.167.220`|
|SMTP|`5.2.84.41` ([mail.testeremarketim.com](https://mail.testeremarketim.com))|
|Email получателя|`phinametics247@gmail.com`|
|SHA256 (EXE)|`aaf37584883937059e00508a1dfe72df4148efef238b4e86038902f968f220c1`|
|Persistence|`C:\Users\[username]\AppData\Roaming\gCmiVoeYUJc.exe`|

---

## MITRE ATT&CK

|Тактика|Техника|ID|
|---|---|---|
|Initial Access|Spearphishing Attachment|T1566.001|
|Execution|User Execution: Malicious File|T1204.002|
|Discovery|System Information Discovery|T1082|
|Discovery|System Location Discovery|T1614|
|Exfiltration|Exfiltration Over Web Service (Telegram)|T1567.002|
|Exfiltration|Exfiltration Over Alternative Protocol (SMTP)|T1048|

---

## Splunk-правило

spl

index=web_logs (uri="*checkip.dyndns.org*" OR uri="*reallyfreegeoip.org*" OR uri="*api.telegram.org*")
| table _time, client_ip, uri, method, status

---

## Рекомендации

1. Заблокировать `132.226.247.73`, `104.21.64.1`, `149.154.167.220`, `5.2.84.41`
    
2. Удалить `gCmiVoeYUJc.exe` с хоста `10.5.27.101`
    
3. Проверить другие хосты на обращения к `checkip.dyndns.org` и `api.telegram.org`
    
4. Добавить IOC в SIEM