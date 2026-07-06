
**Дата расследования:** 06.07.2026  
**Источник:** Malware Traffic Analysis  
**Файл:** `2026-01-19-six-days-of-scans-and-probes-and-web-traffic-hitting-my-web-server.pcap`  
**Длительность:** 5 дней 23:59:57  
**Пакетов:** 344 483  
**Жертва:** `203.161.44.208`  
**Вердикт:** Массовое многопотоковое сканирование. Сервер не взломан (все ответы 404). Атакующие — ботнеты и автоматические сканеры.

---

## Ход расследования

### Шаг 1: Общая статистика

|Метрика|Значение|
|---|---|
|Пакетов|344 483|
|Длительность|6 дней|
|SYN|124 940|
|ACK|161 735|

### Шаг 2: Категории атак

| Категория               | Паттерны                                                                     | CVE/Техника   |
| ----------------------- | ---------------------------------------------------------------------------- | ------------- |
| **PHPUnit RCE**         | `eval-stdin.php` (50+ путей)                                                 | CVE-2017-9841 |
| **ThinkPHP RCE**        | `invokefunction`, `call_user_func_array`                                     | -             |
| **PHP-CGI RCE**         | `/hello.world?%ADd+allow_url_include`                                        | CVE-2024-4577 |
| **PEAR CMD RCE**        | `pearcmd`, `config-create`                                                   | -             |
| **Docker API**          | `/containers/json`                                                           | T1613         |
| **Path Traversal**      | `../../../../etc/passwd`                                                     | T1003         |
| **Mozi ботнет**         | `Mozi.a`, `chmod 777`, `wget`                                                | T1059.004     |
| **`.git/config`**       | Кража конфигов Git                                                           | T1552         |
| **`.env` сканирование** | `/.env`, `/admin/.env`, `/config/.env`, `/app/config/.env`                   | T1552         |
| **Конфиги**             | `/config.json`, `/wp-config.php`, `/config/aws.yml`, `/config/stripe.yml`    | T1552         |
| **Админки**             | `/admin/config.php`, `/login.asp`, `/admin.jsp`, `/admin.php`, `/admin.html` | T1078.001     |
| **Роутеры (BOA)**       | `/boaform/admin/formLogin`                                                   | T1078.001     |
| **GeoServer**           | `/geoserver/web/`, `/geoserver/wfs`                                          | T1190         |
| **Solr**                | `/solr/admin/info/system`                                                    | T1190         |
| **SSH/Telnet**          | SYN на порты 22, 23                                                          | T1046         |

### Шаг 3: Топ атакующих IP

| IP                | Количество запросов               | Основные векторы                                   |
| ----------------- | --------------------------------- | -------------------------------------------------- |
| `180.76.172.156`  | Первый и самый настойчивый        | PHPUnit, ThinkPHP, CVE-2024-4577, Pearcmd, Docker  |
| `45.135.194.98`   | Массовый брутфорс `/login`        | Перебор логинов                                    |
| `45.56.103.154`   | Сотни запросов к админкам         | `/admin.*`, `/login.*`, `/config`                  |
| `139.144.52.241`  | Фаззинг админок                   | `/admin.php`, `/login.aspx`, `/config`             |
| `204.76.203.125`  | Сканирование конфигов             | `/config.json`, `/wp-config.php`, `/.env`          |
| `195.178.110.199` | Сканирование конфигов и `.git`    | `/config.yml`, `/wp-config.php`, `.git/config`     |
| `192.159.99.233`  | Сканирование конфигов             | `/config.json`, `/config.js`, `/sftp-config.json`  |
| `45.148.10.247`   | Сканирование `.env` и конфигов    | `/admin/.env`, `/config/aws.yml`, `/wp-config.php` |
| `23.224.68.178`   | PHPUnit + ThinkPHP + админки      | `eval-stdin.php`, `invokefunction`, `/admin/`      |
| `20.56.82.62`     | PHPUnit + CVE-2024-4577 + админки | `eval-stdin.php`, `/hello.world`, `/admin/`        |

**Всего выявлено 18+ уникальных IP атакующих.**

### Шаг 4: Дефолтные учётные данные

|IP|URL|
|---|---|
|`103.248.93.90`|`/boaform/admin/formLogin?username=adminisp&psd=adminisp`|
|`117.242.201.136`|`/boaform/admin/formLogin?username=adminisp&psd=adminisp`|
|`124.132.143.87`|`/boaform/admin/formLogin?username=ec8&psd=ec8`|
|`27.206.248.8`|`/boaform/admin/formLogin?username=ec8&psd=ec8`|
|`103.93.93.211`|`/boaform/admin/formLogin?username=user&psd=user`|
|`139.5.11.184`|`/boaform/admin/formLogin?username=adminisp&psd=adminisp`|

### Шаг 5: Ответы сервера

Все атаки получили **404 Not Found** или **400 Bad Request**. Сервер не был взломан.

---

## Индикаторы компрометации (IOC)

### IP атакующих (подтверждённые)

`180.76.172.156`, `20.56.82.62`, `23.224.68.178`, `170.64.177.108`, `185.110.190.90`, `192.159.99.95`, `5.104.86.151`, `103.40.61.98`, `156.146.57.122`, `190.129.122.221`, `178.18.240.233`, `108.165.179.97`, `68.183.234.194`, `147.45.124.214`, `61.245.11.87`, `161.132.19.72`, `161.97.153.92`, `81.163.30.15`, `45.135.194.98`, `45.56.103.154`, `139.144.52.241`, `204.76.203.125`, `195.178.110.199`, `192.159.99.233`, `45.148.10.247`, `213.209.159.151`

### URL-артефакты

`/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/index.php?s=/index/\think\app\invokefunction`, `/hello.world?%ADd+allow_url_include`, `/containers/json`, `/.git/config`, `/.env`, `/wp-config.php`, `/config.json`, `/boaform/admin/formLogin`, `/admin/config.php`, `/geoserver/web/`, `/solr/admin/info/system`

### User-Agent

Не указан в большинстве запросов — типично для автоматических сканеров.

---

## MITRE ATT&CK

|Тактика|Техника|ID|
|---|---|---|
|Initial Access|Exploit Public-Facing Application|T1190|
|Discovery|Network Service Scanning|T1046|
|Execution|Unix Shell (Mozi)|T1059.004|
|Credential Access|Unsecured Credentials (`.env`, `.git`)|T1552|
|Credential Access|Default Accounts (BOA router)|T1078.001|
|Discovery|Container Discovery (Docker API)|T1613|

---

## Splunk-правило (общее)

```spl
index=web_logs (uri="*eval-stdin.php*" OR uri="*invokefunction*" OR uri="*pearcmd*" OR uri="*/containers/json*" OR uri="*/etc/passwd*" OR uri="*/.env*" OR uri="*/.git/config*" OR uri="*/admin*" OR uri="*login.asp*" OR uri="*Mozi.a*" OR uri="*hello.world*" OR uri="*/geoserver/*" OR uri="*/solr/*" OR uri="*wp-config*")
| stats count by client_ip, uri
| where count > 3
| table client_ip, uri, count
```

---

## Рекомендации

1. Заблокировать 26+ IP на файрволе (список выше)
    
2. Настроить WAF для блокировки типовых веб-атак
    
3. Скрыть версию сервера (Apache/2.4.62)
    
4. Отключить отображение лишних эндпоинтов
    
5. Включить HTTPS
    
6. Настроить rate-limiting для `/login`, `/admin`
    
7. Добавить IOC в SIEM