
**Дата расследования:** 10.07.2026  
**Источник:** Malware Traffic Analysis  
**Файл:** `2026-02-03-Guloader-for-AgentTesla-style-malware-with-FTP-data-exfiltration.pcap`  
**Длительность:** ~2 минуты 12 секунд  
**Пакетов:** 353  
**Жертва:** `10.2.3.101` (`DESKTOP-W7F98GR`, пользователь `tyler`)

---

## Ход расследования

### Шаг 1: Общая статистика

|Метрика|Значение|
|---|---|
|Пакетов|353|
|Длительность|2 мин 12 сек|

### Шаг 2: Цепочка заражения

|#|Время|Запрос|Описание|
|---|---|---|---|
|1|0.11с|TLS Client Hello → `drive.google.com`|Скачивание Guloader|
|2|9.40с|DNS: `ip-api.com`|Определение IP жертвы|
|3|9.45с|GET `/line/?fields=hosting`|Проверка хостинга|
|4|11.27с|FTP: USER `edunis@corwineagles.com`|Подключение к FTP-серверу|
|5|11.35с|FTP: PASS `cCycU=91vup7`|Аутентификация|
|6|11.96с|FTP: STOR `PW_tyler-...`|Отправка украденных паролей|
|7|12.31с|FTP: STOR `Contacts_Thunderbird.txt...`|Отправка контактов|

### Шаг 3: C2-инфраструктура

|Домен|IP|Роль|
|---|---|---|
|`ip-api.com`|`208.95.112.1`|Геолокация|
|`drive.google.com`|`142.250.115.138`|Скачивание Guloader|
|`ftp.corwineagles.com`|`162.241.123.75`|FTP-экфильтрация|

### Шаг 4: Украденные данные

|Файл|Содержимое|
|---|---|
|`PW_tyler-DESKTOP-W7F98GR_2026_02_03_16_13_59.html`|Пароли из браузеров|
|`Contacts_Thunderbird.txt_tyler-DESKTOP-W7F98GR_2026_02_03_16_14_02.txt`|Контакты Thunderbird|

### Шаг 5: FTP-учётные данные злоумышленника

- **FTP-сервер:** `162.241.123.75` ([ftp.corwineagles.com](https://ftp.corwineagles.com))
    
- **Логин:** `edunis@corwineagles.com`
    
- **Пароль:** `cCycU=91vup7`
    

---

## Индикаторы компрометации (IOC)

|Тип|Значение|
|---|---|
|Геолокация|`208.95.112.1` ([ip-api.com](https://ip-api.com))|
|Скачивание|`142.250.115.138` ([drive.google.com](https://drive.google.com))|
|FTP-сервер|`162.241.123.75` ([ftp.corwineagles.com](https://ftp.corwineagles.com))|
|FTP-логин|`edunis@corwineagles.com`|
|FTP-пароль|`cCycU=91vup7`|
|Email-отправитель|`shipping@paramee.com`|
|IP-отправитель|`160.250.132.142`|
|SHA256 (вложение)|`9fc244b6ba5c24fe50134870932f6dea852b8fa419ec7cdcf3d84eed70e0e331`|
|SHA256 (Guloader)|`b7d239db797326e43a96fb228e93bbbfa1e12d610c8a79ba3148b74b0021ecb4`|

---

## MITRE ATT&CK

|Тактика|Техника|ID|
|---|---|---|
|Initial Access|Spearphishing Attachment|T1566.001|
|Execution|User Execution: Malicious File|T1204.002|
|Discovery|System Location Discovery|T1614|
|Credential Access|Credentials from Web Browsers|T1555.003|
|Collection|Email Collection (Thunderbird)|T1114|
|Exfiltration|Exfiltration Over Alternative Protocol (FTP)|T1048|

---

## Splunk-правила

**Геолокация:**

spl

index=web_logs (uri="*ip-api.com*" OR uri="*fields=hosting*")
| table _time, client_ip, uri, method, status

**FTP-экфильтрация:**

spl

index=network dst_port=21 OR proto="ftp"
| stats count by _time, src_ip, dst_ip
| where count > 3
| table _time, src_ip, dst_ip, count

---

## Рекомендации

1. Заблокировать `208.95.112.1`, `162.241.123.75`, `160.250.132.142`
    
2. Сбросить пароли на хосте `DESKTOP-W7F98GR`
    
3. Проверить другие хосты на FTP-трафик и запросы к `ip-api.com`
    
4. Добавить IOC в SIEM