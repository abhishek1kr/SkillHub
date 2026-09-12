---
name: evidence-guidelines
description: HTTP/2 200 OK {"id":123,"email":"usera@test.com","role":"admin"}
category: reporting
---

## Evidence
### Request/Response
```
GET /api/v1/users/123 HTTP/2
Host: target.com
Authorization: Bearer eyJ...

HTTP/2 200 OK
{"id":123,"email":"user_a@test.com","role":"admin"}
```

### Screenshot
[صورة تبين الاستجابة]

