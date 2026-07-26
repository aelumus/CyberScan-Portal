# Secrets & SCA (Gitleaks / Trivy)

## Зачем

| Инструмент | Вопрос |
|------------|--------|
| **Gitleaks** | Нет ли паролей/ключей в git (и в истории)? |
| **Trivy FS** | Есть ли CRITICAL/HIGH CVE в зависимостях репо (`package-lock`, `requirements`)? |
| **Trivy image** | То же + CVE в OS-пакетах **внутри** Docker-образа |

Bandit / npm audit / pip-audit уже в lint. Gitleaks и Trivy закрывают секреты и контейнеры.

## Политика в CI

- Gitleaks — **hard fail** (секрет = стоп).
- Trivy FS / image — **soft-fail** (отчёт в логе Actions, пайплайн не обязан быть красным).
- `build` ждёт `gitleaks`; собираем только `caddy backend frontend worker`.

## Локально

```powershell
# Gitleaks
docker run --rm -v "${PWD}:/path" zricethezav/gitleaks:latest detect --source=/path -v

# Trivy FS (без тяжёлых датасетов и без secret-скана — секреты уже Gitleaks)
docker run --rm -v "${PWD}:/src" aquasec/trivy:latest fs `
  --scanners vuln `
  --severity CRITICAL,HIGH `
  --ignore-unfixed `
  --timeout 15m `
  --skip-dirs "Malware-Detection-and-Analysis-using-Machine-Learning-main" `
  --skip-dirs "zap-reports" `
  /src
```

Trivy image удобнее смотреть в CI (после `docker compose build`).

## Triage

1. Gitleaks hit → ротация секрета + убрать из истории, не только из текущего файла.
2. Trivy HIGH в Next.js на 14.x при фиксе в 15.x → план апгрейда, не паника в тот же день.
3. Unfixed upstream CVE — часто accept (`--ignore-unfixed` как раз про это).
