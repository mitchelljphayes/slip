# Test Health App

A minimal nginx container that serves:
- `GET /health` → 200 "ok"
- `GET /` → 200 "hello from slip test app"

## Build

```bash
docker build -t slip-test-app:latest tests/fixtures/health-app/
```

## Use in tests

Configure your test app with:
- `image = "slip-test-app"`
- `port = 3000`
- `health.path = "/health"`
