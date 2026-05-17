# CyberScan Portal — Frontend

Фронтенд-часть системы автоматизированного анализа вредоносного ПО.  
Написан на **Next.js 14** (App Router) + **TypeScript** + **Tailwind CSS**.

## Запуск (разработка)

```bash
npm install
npm run dev
```

Открыть: [http://localhost:3000](http://localhost:3000)

## Переменные окружения

Создать файл `.env.local`:

```
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## Структура

```
app/
  (app)/          — защищённые страницы (dashboard, scan, scans, models, compare, datasets, about, settings)
  login/          — страница входа
  register/       — страница регистрации
  page.tsx        — публичная посадочная страница
components/
  AuthProvider    — JWT-сессия
  ThemeProvider   — светлая/тёмная тема
  Sidebar / Topbar
  Badges          — VerdictBadge, RiskBadge, ScoreBar
  auth/           — AuthShell, AuthFormControls
hooks/
  useScans        — история сканирований
lib/
  api.ts          — HTTP-клиент (buildApiUrl, getJson, postForm)
  types.ts        — TypeScript-интерфейсы
```

## Технологии

| Пакет | Назначение |
|---|---|
| Next.js 14 | React-фреймворк (SSR / CSR) |
| TypeScript | Строгая типизация |
| Tailwind CSS | Утилитарный CSS |
| Recharts | Графики (ROC, BarChart, AreaChart) |
| Lucide React | Иконки |
