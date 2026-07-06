**Дата расследования:** 05.07.2026  
**Источник:** Malware Traffic Analysis  
**Файл:** `2025-12-11-Kongtuke-ClickFix-activity-part-2-running-ClickFix-script-on-a-physical-host.pcap`  
**Длительность:** ~5 минут 30 секунд  
**Пакетов:** 195 754  
**Жертва:** `10.12.11.77` (DESKTOP-XO2TNI8)

---

## Ход расследования

### Шаг 1: Общая статистика

|Метрика|Значение|
|---|---|
|Пакетов|195 754|
|Длительность|5 мин 30 сек|
|SYN|96|
|ACK от C2|~177 000|
|Основной C2 IP|`45.61.136.222`|

### Шаг 2: DNS-запросы

DNS-трафик минимальный — злоумышленник использовал прямые IP-адреса.

### Шаг 3: Цепочка заражения

|#|Время|Запрос|Описание|
|---|---|---|---|
|1|2.62с|`GET /1.php?s=63e95be1-...`|Регистрация жертвы на C2|
|2|6.56с|`GET /1.php?s=04e1ab2b-...`|Вторая сессия к `45.61.136.222`|
|3|9.30с|`GET /lihza3q7x6htr.php?id=DESKTOP-XO2TNI8&key=43063511387`|Передача имени хоста и ключа|
|4|39.30с|`GET /st2?s=...&id=DESKTOP-XO2TNI8&key=68120057674`|Второй этап, новый ключ|
|5|41.31с|`GET /getarchive`|Скачивание вредоносного архива (205 МБ)|
|6|114.13с|`GET /installreport?r=0&hash=1DD91BA2F5...`|Отчёт об установке|
|7|114.35с|`GET /archivehash`|Проверка хеша архива|
|8|126.15с|`GET /installreport?r=1`|Подтверждение успешной установки|

### Шаг 4: C2-инфраструктура

|IP|Домен|Роль|
|---|---|---|
|`45.61.136.222`|`3eds4jqf9fzud80.top`|Основной C2|
|`64.190.113.145`|`abfanlmhfjighcd.top`|Промежуточный сервер|
|`185.220.101.202`|-|Tor exit node (подтверждён)|

### Шаг 5: Признаки ClickFix

- `s=` — GUID сессии
    
- `id=DESKTOP-XO2TNI8` — имя хоста жертвы
    
- `key=` — уникальные ключи заражения (меняются между этапами)
    
- `getarchive` / `archivehash` — работа с архивами
    
- `installreport` — отчёт об успешной установке вредоносного ПО
    

### Шаг 6: Определение геолокации

|Сервис|Запрос|Ответ|
|---|---|---|
|`ipinfo.io`|`/173.66.46.112/city`|Город|
|`ipinfo.io`|`/173.66.46.112/region`|Регион|
|`ipinfo.io`|`/173.66.46.112/country`|Страна|
|`checkip.dyndns.org`|`/`|Внешний IP|

Злоумышленник определял местоположение жертвы — возможно, для фильтрации (не заражать определённые страны).

### Шаг 7: OCSP-проверка

Жертва обращалась к `23.204.150.28` (DigiCert OCSP) для проверки SSL-сертификатов C2-доменов. Подтверждает использование HTTPS вредоносным ПО.

---

## Индикаторы компрометации (IOC)

|Тип|Значение|
|---|---|
|C2 IP (основной)|`45.61.136.222`|
|C2 IP (промежуточный)|`64.190.113.145`|
|C2-домен|`3eds4jqf9fzud80.top`|
|C2-домен|`abfanlmhfjighcd.top`|
|Tor exit node|`185.220.101.202`|
|ID хоста|`DESKTOP-XO2TNI8`|
|Ключ 1|`43063511387`|
|Ключ 2|`68120057674`|
|Сессия 1|`63e95be1-92e0-45c1-a928-65d63b17cd1c`|
|Сессия 2|`04e1ab2b-3f93-46fa-9aed-c3a2a3f126c9`|
|Хеш|`1DD91BA2F56CED5AF731E67121619D6A9EF2CBB8F1524989FC542EF904605908`|
|Геолокация|`ipinfo.io`, `34.117.59.81`|

---

## MITRE ATT&CK

|Тактика|Техника|ID|
|---|---|---|
|Command & Control|Web Protocols|T1071.001|
|Command & Control|Proxy: Tor|T1090.003|
|Discovery|System Information Discovery|T1082|
|Discovery|System Location Discovery|T1614|
|Execution|User Execution: Malicious Script|T1204.001|

---

## Splunk-правила

**Правило 1: Kongtuke ClickFix**

spl

index=web_logs (uri="*1.php*" OR uri="*st2*" OR uri="*getarchive*" OR uri="*installreport*" OR uri="*archivehash*")
| table _time, client_ip, uri, method, status

**Правило 2: GeoIP Check ([ipinfo.io](https://ipinfo.io))**

spl

index=web_logs (uri="*/city*" OR uri="*/region*" OR uri="*/country*") AND uri="*ipinfo.io*"
| table _time, client_ip, uri, method, status

---

## Рекомендации

1. Заблокировать `45.61.136.222`, `64.190.113.145`, `3eds4jqf9fzud80.top`, `abfanlmhfjighcd.top`
    
2. Проверить другие хосты на обращения к `/1.php`, `/st2`, `/getarchive`, `/installreport`
    
3. Заблокировать исходящий трафик к Tor (порты 8443, 9001, 9030)
    
4. Сбросить пароли на хосте `DESKTOP-XO2TNI8`
    
5. Добавить IOC в SIEM