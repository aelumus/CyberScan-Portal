# Когда что сканировать (PR / nightly / release)

Идея: **не гонять всё на каждый push**. Быстрое — на PR (блокирует merge). Тяжёлое — ночью или перед релизом.

## Три корзины

| Корзина | Когда | Цель | У нас сейчас |
|---------|--------|------|----------------|
| **PR / каждый push** | каждый PR и push в `main` | быстрый гейт: секреты, линт, явные дыры в коде/deps | Gitleaks (hard), lint + Bandit + npm/pip audit, Trivy FS (soft), Docker build + Trivy image (soft), ZAP baseline (soft) |
| **Nightly** | по cron раз в сутки | глубже, можно дольше: API DAST по OpenAPI | `.github/workflows/nightly-dast-api.yml` (ZAP API, soft-fail; JWT — бэклог) |
| **Pre-release** | перед тегом/выкладкой | ручной triage + «можно в прод?» | чеклист: отчёты ZAP/Trivy, нет незакрытых High по секретам/debug, JWT_SECRET не default |

## Почему так

- **PR** должен быть **быстрым** (минуты). Если каждый PR = полный auth API scan + все образы с жёстким fail — команда начнёт обходить CI.
- **Nightly** ловит то, что дорого на каждый коммит, но важно не копить неделями.
- **Release** — момент, когда soft-fail findings **обязаны** быть разобраны (accept / fix / ticket).

## Hard vs soft (напоминание)

| | Hard на PR | Soft на PR |
|--|------------|------------|
| Пример | Gitleaks | ZAP WARN, Trivy HIGH в Next 14 |
| Смысл | merge нельзя | merge можно, но отчёт смотрим |

Позже часть soft можно перевести в hard (например CRITICAL в Trivy image).

## Как отвечать на собесе (одна минута)

> «На PR — секреты и быстрый SAST/SCA, DAST baseline soft-fail. Ночью — API/auth DAST. Перед релизом — triage отчётов и проверка, что debug/секреты закрыты. Политика fail зависит от риска: секрет всегда hard.»

## Что добавить позже (бэклог)

1. Auth scan в nightly (тестовый user + `ZAP_AUTH_HEADER_VALUE` из GitHub Secret, не из репо).
2. Release checklist issue template.
