# Test Health App

A minimal nginx container for manual and integration testing of slip deploys.

Serves:
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

## Note

This fixture is for manual testing and future integration tests. It is not
currently wired into the automated test suite.
