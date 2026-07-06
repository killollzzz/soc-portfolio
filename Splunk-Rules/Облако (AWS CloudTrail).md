**1. Алерт на CloudTrail-правила

```spl
index=aws_cloudtrail 
(eventName="CreateUser" OR eventName="DeleteTrail" OR eventName="StopLogging" OR eventName="AttachUserPolicy" OR eventName="AttachRolePolicy")
NOT (sourceIPAddress="10.*" OR sourceIPAddress="192.168.*")
| table eventTime, eventName, sourceIPAddress, userIdentity.arn
```

**2. Алерт на массовое скачивание из S3 (экспорт данных)

```spl
index=aws_cloudtrail eventName="GetObject"
| bucket _time span=5m
| stats count by _time, sourceIPAddress, userIdentity.arn, requestParameters.bucketName
| where count > 100
| table eventTime, sourceIPAddress, userIdentity.arn, requestParameters.bucketName, count
```