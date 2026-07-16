
**Дата расследования:** 11.07.2026  
**Источник:** Malware Traffic Analysis  
**Файл:** `2025-12-23-MACSYNC-stealer-infection.pcap`  
**Длительность:** ~20 секунд  
**Пакетов:** 193  
**Жертва:** `10.12.23.101`

---

## Ход расследования

### Шаг 1: Общая статистика

|Метрика|Значение|
|---|---|
|Пакетов|193|
|Длительность|20 сек|
|Внешних подключений|4 IP|

### Шаг 2: C2-инфраструктура

|Домен|IP|Роль|
|---|---|---|
|`obsidiangate.space`|`104.21.4.37`, `172.67.131.158`|C2 (TLSv1.3)|
|`focusgroovy.com`|`104.21.87.188`, `172.67.145.157`|C2 (GET /dynamic, POST /gate)|

### Шаг 3: Цепочка заражения

|#|Время|Запрос|Описание|
|---|---|---|---|
|1|0.08с|DNS: `obsidiangate.space`|Разрешение C2-домена|
|2|0.16с|TLS Client Hello → `obsidiangate.space`|Установка защищённого канала|
|3|1.49с|DNS: `focusgroovy.com`|Разрешение второго C2|
|4|1.53с|GET `/dynamic?txd=985683bd...`|Запрос к C2 (регистрация)|
|5|18.95с|POST `/gate`|Отправка украденных данных|

### Шаг 4: Хеш файла

- **Файл:** `dynamic?txd=985683bd660c0c47c6be513a2d1f0a554d52d241714bb17fb18ab0d0f8cc2dc6`
    
- **SHA256:** `b34b8f20aff3cd7f58a7d57bfc55e08255fdcb3597cb7f1c4eb49d6fc41c9f86`
    
- **VirusTotal:** 28/60
    

### Шаг 5: FTP / SMTP

Отсутствует.

---

## Индикаторы компрометации (IOC)

|Тип|Значение|
|---|---|
|C2-домен|`obsidiangate.space`|
|C2-домен|`focusgroovy.com`|
|C2 IP|`104.21.87.188`, `172.67.145.157`|
|GET-запрос|`/dynamic?txd=985683bd660c0c47c6be513a2d1f0a554d52d241714bb17fb18ab0d0f8cc2dc6`|
|POST-запрос|`/gate`|
|Хеш dynamic|`b34b8f20aff3cd7f58a7d57bfc55e08255fdcb3597cb7f1c4eb49d6fc41c9f86`|

---

## MITRE ATT&CK

|Тактика|Техника|ID|
|---|---|---|
|Command & Control|Web Protocols|T1071.001|
|Defense Evasion|Encrypted Channel (TLS)|T1573|
|Exfiltration|Exfiltration Over C2 Channel|T1041|

---

## Splunk-правило

spl

index=web_logs (uri="*obsidiangate.space*" OR uri="*focusgroovy.com*" OR uri="*dynamic?txd=*" OR uri="*/gate")
| table _time, client_ip, uri, method, status

---

## Рекомендации

1. Заблокировать `obsidiangate.space`, `focusgroovy.com`, `104.21.87.188`, `172.67.145.157`
    
2. Проверить другие хосты на обращения к `/dynamic?txd=` и `/gate`
    
3. Добавить IOC в SIEM