---
applyTo: "src/main/**/*.kt"
---

# Error Handling (RFC 9457 Problem Details)

The project adheres to Problem Details RFC 9457 for error responses.

Example request:

```
POST /purchase HTTP/1.1
Host: store.example.com
Content-Type: application/json
Accept: application/json, application/problem+json

{
"item": 123456,
"quantity": 2
}
```

Problem details response:

```
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json
Content-Language: en

{
 "type": "https://example.com/probs/out-of-credit",
 "title": "You do not have enough credit.",
 "detail": "Your current balance is 30, but that costs 50.",
 "instance": "/account/12345/msgs/abc",
 "balance": 30,
 "accounts": ["/account/12345",
              "/account/67890"]
}
```

```kotlin
// Exception handling with proper logging
try {
    // Business logic
} catch (e: SerializationException) {
    call.respond(HttpStatusCode.BadRequest, ErrorResponse(...))
} catch (e: IOException) {
    call.respond(HttpStatusCode.InternalServerError, ErrorResponse(...))
}
```
