# Как смотреть DAST CyberScan

1. GitHub → Actions → workflow **CI** → Artifacts → `zap-baseline-report`.
   Nightly API: workflow **Nightly DAST API** → `zap-api-report` (также можно **Run workflow** вручную).
2. Открыть `zap-report.html` в браузере.
3. Смотреть High / Medium / Low / Info. High = срочно, Info часто просто заметка.
4. Сейчас soft-fail: пайплайн может быть зелёным даже с WARN — отчёт всё равно смотрим.
5. CSP (Medium) — на потом; COEP/COOP/CORP и Modern Web App — пока accept.
6. Если ZAP в логе пишет Permission denied / no such service — сначала чиним CI, не «дыры в приложении».

## Baseline (UI) — локально

```powershell
docker compose up -d caddy backend frontend worker

docker compose --profile dast run --rm zap
```

Отчёты: `zap-reports/zap-report.html`, `zap-report.json`.

Через Caddy на backend уходит только `/api/*`.  
`http://localhost/docs` и `/openapi.json` в браузере **не** Swagger — они попадают на frontend.

## API scan (OpenAPI)

### 1. Скачать спеку из backend-контейнера

```powershell
mkdir zap-reports -Force
docker exec cyberscan-backend curl -fsS http://127.0.0.1:8000/openapi.json -o /tmp/openapi.json
docker cp cyberscan-backend:/tmp/openapi.json .\zap-reports\openapi.json
```

### 2. Запуск

`-O` должен быть **полным URL** (`http://caddy`), иначе ZAP импортирует 0 URL.

```powershell
docker compose --profile dast run --rm --user root --entrypoint zap-api-scan.py zap `
  -t /zap/wrk/openapi.json `
  -f openapi `
  -O http://caddy `
  -r zap-api-report.html `
  -J zap-api-report.json `
  -I
```

Отчёты: `zap-reports/zap-api-report.html`, `zap-api-report.json`.

В логе должно быть `Number of Imported URLs:` > 0.

### Triage API (типичное)

| Alert | Вердикт |
|--------|---------|
| Unexpected Content-Type (404 / HTML `/`) | noise |
| CORP / COEP / COOP | accept (как baseline) |
| Source Code Disclosure на `/api/auth/debug` | fix — эндпоинт за `DEBUG` (default off) |

`/api/auth/debug` скрыт из OpenAPI и отдаёт 404, пока нет `DEBUG=true`.

## Auth JWT API scan

Без токена ZAP почти не проверяет защищённые пути (`/api/scans`, `/api/auth/me`, `/api/scan`).

### 1. Логин → JWT

```powershell
# при необходимости: регистрация
curl.exe -s -X POST http://localhost/api/auth/register `
  -d "username=zapuser&email=zap@test.local&password=zaptest123"

$r = curl.exe -s -X POST http://localhost/api/auth/login `
  -d "email=zap@test.local&password=zaptest123"
$tok = ($r | ConvertFrom-Json).token

# проверка
curl.exe -s http://localhost/api/auth/me -H "Authorization: Bearer $tok"
```

### 2. Scan с заголовком

```powershell
docker compose --profile dast run --rm --user root `
  -e "ZAP_AUTH_HEADER_VALUE=Bearer $tok" `
  --entrypoint zap-api-scan.py zap `
  -t /zap/wrk/openapi.json `
  -f openapi `
  -O http://caddy `
  -r zap-api-auth-report.html `
  -J zap-api-auth-report.json `
  -I
```

Отчёты: `zap-reports/zap-api-auth-report.html`, `zap-api-auth-report.json`.

Признак, что auth дошёл: в отчёте/логе **200** на `/api/auth/me` и `/api/scans` (не 401).

Токен не коммитить и не светить в скриншотах/артефактах CI.

## Nightly + JWT (CI)

1. GitHub → Settings → Secrets and variables → Actions → New repository secret. Создай три:
   - `ZAP_TEST_EMAIL` — например `zap-ci@test.local`
   - `ZAP_TEST_PASSWORD` — длинный учебный пароль (≥6 символов)
   - `ZAP_TEST_USERNAME` — например `zapci`
2. Workflow `nightly-dast-api.yml`: register/login → `Authorization: Bearer` → ZAP API scan.
3. В отчёте ищи **200** на `/api/auth/me` и `/api/scans` (не 401).

