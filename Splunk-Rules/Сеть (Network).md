**1. Большой объём исходящего трафика (эксфильтрация)**

```spl
index=*
| eval bytes_num = tonumber(replace(_raw, ".*?(\\d+)$", "\\1"))
| where bytes_num > 100000`
```

**2. Алерт на SSH-брутфорс

```spl
index=linux_auth (body="*Failed password*" OR "*Invalid user*" OR "*authentication failure*")
| bucket _time span=5m
| stats count by _time, client_ip
| where count > 5
| table _time, client_ip, count
```

**3.Алерт на DNS-туннель

```spl
index=dns
| eval query_length = len(query)
| where query_length > 50
| bucket _time span=10m
| stats count by _time, src_ip, query
| where count > 10
| table _time, src_ip, query, count
```

**4. Алерт на Beaconing

```spl
index=web_logs OR index=zeek
| stats count by _time, client_ip, dst_ip, uri
| sort client_ip, dst_ip, _time
| streamstats current=f last(_time) as prev_time by client_ip, dst_ip, uri
| eval gap = _time - prev_time
| where gap > 60 AND gap < 120
| stats count by client_ip, dst_ip, uri, gap
| where count > 5
| table client_ip, dst_ip, uri, gap, count
```

**5. Алерт на Beaconing через DNS

```spl
index=dns
| stats count by _time, src_ip, query
| sort src_ip, query, _time
| streamstats current=f last(_time) as prev_time by src_ip, query
| eval gap = _time - prev_time
| where gap > 60 AND gap < 300
| stats count by src_ip, query, gap
| where count > 5
| table src_ip, query, gap, count
```

**6. Алерт на Tor браузер

```spl
index=web_logs (uri="*/city*" OR uri="*/region*" OR uri="*/country*") AND uri="*ipinfo.io*"
| table _time, client_ip, uri, method, status
```

**7 Алерт на Multi-Vector Server Scan (6-Day PCAP)
[[Multi-Vector Server Scan (6-Day PCAP)]]
```spl
index=web_logs (uri="*eval-stdin.php*" OR uri="*invokefunction*" OR uri="*pearcmd*" OR uri="*/containers/json*" OR uri="*/etc/passwd*" OR uri="*/.env*" OR uri="*/.git/config*" OR uri="*/admin*" OR uri="*login.asp*" OR uri="*Mozi.a*" OR uri="*hello.world*" OR uri="*/geoserver/*" OR uri="*/solr/*" OR uri="*wp-config*")
| stats count by client_ip, uri
| where count > 3
| table client_ip, uri, count
```

