# Session Hijacking Research Testbed

Учебная среда для исследования атак на сессионные токены.

## Локальный запуск

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Деплой на Render

1. Загрузи на GitHub
2. Подключи репозиторий на render.com
3. Render автоматически использует render.yaml

## Страницы

- `/` — главная
- `/register` — регистрация
- `/login` — вход
- `/dashboard` — личный кабинет + JWT токен
- `/logs` — журнал сессий

## Демонстрация атаки

```bash
curl https://твой-адрес.onrender.com/dashboard \
  -H "Cookie: token=ТОКЕН" \
  -H "User-Agent: AttackerBot/1.0"
```
