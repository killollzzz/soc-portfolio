**Дата расследования:** 05.07.2026  
**Источник:** Malware Traffic Analysis  
**Файл:** `2025-12-30-Lumma-Stealer-infection-with-other-malware.pcap`  
**Длительность:** ~5 минут  
**Пакетов:** 17 013  
**Жертва:** `10.12.30.101`

---

## Ход расследования

### Шаг 1: Общая статистика

|Метрика|Значение|
|---|---|
|Пакетов|17 013|
|Длительность|4 мин 46 сек|
|SYN|208|
|ACK|16 732|
|DNS|166|

### Шаг 2: DNS-запросы

|Домен|IP|
|---|---|
|`sinitjq.cyou`|`13.201.207.191`|

Домен `sinitjq.cyou` — случайное имя, типичное для DGA или одноразовых C2-доменов.

### Шаг 3: HTTP/HTTPS-трафик

**C2-коммуникация:**

|Метод|URI|Описание|
|---|---|---|
|GET|`/api/set_agent?id=DF59CCBE0E...&agent=Chrome`|Регистрация агента (Chrome)|
|POST|`/api/set_agent?act=log`|Отправка украденных логов|
|GET|`/api/set_agent?id=DF59CCBE0E...&agent=Edge`|Регистрация агента (Edge)|
|POST|`/api/set_agent?act=log`|Отправка украденных логов|

**User-Agent:** Chrome, Edge (указывается в параметре `agent=`)

### Шаг 4: TLS

- Client Hello с SNI `sinitjq.cyou` → `13.201.207.191` (TLSv1.3)
    
- Application Data между жертвой и `172.67.203.237` (TLSv1.2)
    

### Шаг 5: Определение типа вредоноса

**Признаки Lumma Stealer:**

- `/api/set_agent` — API для регистрации заражённой машины
    
- `agent=Chrome`, `agent=Edge` — сбор данных из браузеров
    
- `act=log` — эксфильтрация украденных данных
    
- Уникальный ID: `DF59CCBE0E57F241298E11CD1E79C8A1`
    
- Токен: `005c3799f51121306a8d1550707e79cfe964`
    

---

## Индикаторы компрометации (IOC)

|Тип|Значение|
|---|---|
|C2-домен|`sinitjq.cyou`|
|C2 IP|`13.201.207.191`|
|Второй IP|`172.67.203.237`|
|ID агента|`DF59CCBE0E57F241298E11CD1E79C8A1`|
|Токен|`005c3799f51121306a8d1550707e79cfe964`|
|User-Agent|Chrome, Edge (в параметре agent=)|

---

## MITRE ATT&CK

|Тактика|Техника|ID|
|---|---|---|
|Command & Control|Web Protocols|T1071.001|
|Credential Access|Credentials from Web Browsers|T1555.003|
|Exfiltration|Exfiltration Over C2 Channel|T1041|
|Defense Evasion|Encrypted Channel (TLS)|T1573|

---

## Splunk-правило

spl

index=web_logs (uri="*sinitjq.cyou*" OR uri="*set_agent*" OR uri="*act=log*")
| table _time, client_ip, uri, method, status

---

## Рекомендации

1. Заблокировать `sinitjq.cyou`, `13.201.207.191`, `172.67.203.237`
    
2. Проверить другие хосты на обращения к `/api/set_agent`
    
3. Сбросить пароли всех браузеров на хосте `10.12.30.101`
    
4. Добавить IOC в SIEM