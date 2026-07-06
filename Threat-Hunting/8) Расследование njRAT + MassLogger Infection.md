**Дата расследования:** 06.07.2026  
**Источник:** Malware Traffic Analysis  
**Файл:** `2026-01-29-njRAT-infection-with-MassLogger.pcap`  
**Длительность:** ~7 минут 28 секунд  
**Пакетов:** 2 621  
**Жертва:** `10.1.29.101`

---

## Ход расследования

### Шаг 1: Общая статистика

|Метрика|Значение|
|---|---|
|Пакетов|2 621|
|Длительность|7 мин 28 сек|
|SYN|502|
|ACK|2 177|

### Шаг 2: Цепочка заражения

|#|Время|Запрос|Описание|
|---|---|---|---|
|1|0.00с|DNS: `ip-api.com`|Определение IP жертвы|
|2|0.14с|DNS: `api.telegram.org`|Подготовка канала экфильтрации|
|3|95.42с|DNS: `checkip.dyndns.org`|Проверка внешнего IP|
|4|96.17с|DNS: `reallyfreegeoip.org`|Определение геолокации|
|5|102.90с|DNS: `cphost14.qhoster.net`|Разрешение C2-домена|
|6|105.96с|TLS Client Hello → `cphost14.qhoster.net`|Установка защищённого C2-канала|
|7|106.15с|TLS Server Hello, обмен ключами|Канал установлен|

### Шаг 3: C2-инфраструктура

|Домен|IP|Роль|
|---|---|---|
|`cphost14.qhoster.net`|`78.110.166.82`|Основной C2 (TLSv1.2)|
|`api.telegram.org`|`149.154.166.110`|Экфильтрация через Telegram API|

### Шаг 4: Геолокация

|Домен|IP|Назначение|
|---|---|---|
|`ip-api.com`|`208.95.112.1`|Определение IP|
|`reallyfreegeoip.org`|`104.21.67.152`|Геолокация|
|`checkip.dyndns.org`|`193.122.130.0`|Проверка внешнего IP|

### Шаг 5: Признаки njRAT + MassLogger

- Экфильтрация через **Telegram API** (MassLogger использует Telegram-ботов)
    
- C2 на дешёвом хостинге `qhoster.net` (типично для njRAT)
    
- Проверка геолокации перед соединением с C2
    
- TLS-шифрование C2-трафика
    

---

## Индикаторы компрометации (IOC)

|Тип|Значение|
|---|---|
|C2-домен|`cphost14.qhoster.net`|
|C2 IP|`78.110.166.82`|
|Telegram API|`api.telegram.org` / `149.154.166.110`|
|Геолокация|`reallyfreegeoip.org`, `ip-api.com`, `checkip.dyndns.org`|

---

## MITRE ATT&CK

|Тактика|Техника|ID|
|---|---|---|
|Command & Control|Web Protocols (HTTPS)|T1071.001|
|Exfiltration|Exfiltration Over Web Service (Telegram)|T1567.002|
|Discovery|System Information Discovery|T1082|
|Discovery|System Location Discovery|T1614|
|Defense Evasion|Encrypted Channel (TLS)|T1573|

---

## Splunk-правило

```spl
index=web_logs (uri="*reallyfreegeoip.org*" OR uri="*cphost14.qhoster.net*" OR uri="*ip-api.com*" OR uri="*checkip.dyndns.org*")
| table _time, client_ip, uri, method, status
```

---

## Рекомендации

1. Заблокировать `78.110.166.82`, `cphost14.qhoster.net`
    
2. Заблокировать `api.telegram.org` для неавторизованных приложений
    
3. Проверить другие хосты на обращения к `reallyfreegeoip.org`, `ip-api.com`
    
4. Добавить IOC в SIEM