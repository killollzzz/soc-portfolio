
**Дата расследования:** 08.07.2026  
**Источник:** Malware Traffic Analysis  
**Файл:** `2025-02-07-three-days-of-scans-and-probes-and-web-traffic-hitting-my-web-server.pcap`  
**Длительность:** 3 дня  
**Пакетов:** 135 105  
**Жертва:** `203.161.44.208`  
**Вердикт:** Массовое многопотоковое сканирование. Сервер не взломан (все ответы 404).

---

## Ход расследования

### Шаг 1: Общая статистика

|Метрика|Значение|
|---|---|
|Пакетов|135 105|
|Длительность|3 дня|
|SYN|57 361|
|ACK|62 925|

### Шаг 2: Основной сканирующий IP

`203.161.44.39` — ~36 500 пакетов, ~18 000 SYN. Сканировал порты 22 (SSH), 445 (SMB), 5985 (WinRM).

### Шаг 3: Категории атак

|Категория|Паттерны|
|---|---|
|PHPUnit RCE|`eval-stdin.php` (50+ путей)|
|ThinkPHP RCE|`invokefunction`|
|PHP-CGI RCE|`/hello.world?%ADd+allow_url_include`|
|PEAR CMD RCE|`pearcmd`, `config-create`|
|Docker API|`/containers/json`|
|Path Traversal|`../../../../etc/passwd`|
|Mozi ботнет|`Mozi.a`, `chmod 777`, `wget`|
|`.git/config`|Кража конфигов Git|
|`.env` сканирование|`/.env`, `/admin/.env`, `/config/.env`|
|Конфиги|`/config.json`, `/wp-config.php`, `/config/aws.yml`|
|Админки|`/admin/config.php`, `/login.asp`, `/admin.php`|
|Роутеры|`/boaform/admin/formLogin`|
|GeoServer|`/geoserver/web/`, `/geoserver/wfs`|
|Solr|`/solr/admin/info/system`|
|SSH/Telnet|SYN на порты 22, 23|

### Шаг 4: Ответы сервера

Все атаки получили **404 Not Found** — сервер не взломан.

---

## Индикаторы компрометации (IOC)

### Сканирующий IP

`203.161.44.39`

### URL-артефакты

`eval-stdin.php`, `invokefunction`, `pearcmd`, `/containers/json`, `/etc/passwd`, `.git/config`, `.env`, `/wp-config.php`, `/config.json`, `/boaform/admin/formLogin`, `/admin/config.php`, `/geoserver/web/`, `/solr/admin/info/system`

---

## MITRE ATT&CK

|Тактика|Техника|ID|
|---|---|---|
|Initial Access|Exploit Public-Facing Application|T1190|
|Discovery|Network Service Scanning|T1046|
|Execution|Unix Shell (Mozi)|T1059.004|
|Credential Access|Unsecured Credentials|T1552|
|Credential Access|Default Accounts|T1078.001|
|Discovery|Container Discovery|T1613|

---

## Splunk-правила

**Общее (веб-атаки):**

```spl
index=web_logs (uri="*eval-stdin.php*" OR uri="*invokefunction*" OR uri="*pearcmd*" OR uri="*/containers/json*" OR uri="*/etc/passwd*" OR uri="*/.env*" OR uri="*/.git/config*" OR uri="*/admin*" OR uri="*login.asp*" OR uri="*Mozi.a*" OR uri="*hello.world*" OR uri="*/geoserver/*" OR uri="*/solr/*" OR uri="*wp-config*")
| stats count by client_ip, uri
| where count > 3
| table client_ip, uri, count
```

**Сканирование портов:**

```spl
index=network tcp_flags="SYN" tcp_flags!="ACK"
| bucket _time span=5m
| stats count by _time, src_ip, dst_port
| where count > 100
| table _time, src_ip, dst_port, count
```

**Сканирование SMB (порт 445):**

```spl
index=network dst_port=445
| bucket _time span=5m
| stats count by _time, client_ip, dst_port
| where count > 5
| table _time, client_ip, dst_port, count
```

**Сканирование WinRM (порт 5985):**

```spl
index=network dst_port=5985
| bucket _time span=5m
| stats count by _time, client_ip, dst_port
| where count > 5
| table _time, client_ip, dst_port, count
```
---

## Рекомендации

1. Заблокировать `203.161.44.39` и все IP атакующих из предыдущих PCAP
    
2. Настроить WAF
    
3. Включить rate-limiting
    
4. Добавить IOC в SIEM