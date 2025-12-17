# waflite — мини WAF/сканер логов

Небольшой консольный инструмент на Python, который:
- читает HTTP запросы из nginx access log (combined) **или** из файла с сырыми строками запросов;
- прогоняет их через набор правил (SQLi/XSS/traversal/cmd inj/bad UA);
- выставляет скор и выдает решение `allow / block`;
- пишет отчет в JSONL или CSV.

Проект сделан под учебные требования:
- >= 100 строк кода (без тестов/доков/комментариев);
- pytest тесты;
- Google-style docstrings;
- запуск из консоли.

## Установка

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Быстрый старт

1) Пример nginx лога (combined) лежит в `examples/nginx_access.log`

```bash
python -m waflite --in examples/nginx_access.log --fmt nginx --out out/report.jsonl --ofmt jsonl
```

2) Пример файла с сырыми строками запросов лежит в `examples/reqs.txt`

```bash
python -m waflite --in examples/reqs.txt --fmt raw --out out/report.csv --ofmt csv
```

## Конфигурация

Можно передать JSON конфиг через `--cfg` (пример: `examples/cfg.json`).

В конфиге:
- `thr` — порог скора для блока
- `rls` — список правил (id, тип, вес, паттерны)
- `ign_ua` — список UA, которым снижаем скор (например, мониторинг)

## Выходные форматы

- `jsonl`: одна запись на строку (удобно для дальнейшего парсинга)
- `csv`: плоский отчет

## Запуск тестов

```bash
pytest -q
```

## Сборка документации (Sphinx)

```bash
cd docs
make html
# результат: docs/_build/html/index.html
```

## Структура

- `waflite/` — код приложения
- `tests/` — тесты pytest
- `docs/` — Sphinx документация (autodoc)
- `examples/` — примеры входных данных/конфигов

## Замечания по ИБ

Это **учебный** мини-WAF: правила статические, без полноценного парсинга HTTP и без эвристик уровня продакшна.
Зато код удобен как база для расширения (добавить новые правила, источники логов, интеграцию с nginx/iptables и т.д.).

## Web панель + demo shop

Запуск:

```bash
python -m waflite.webmain --db data/rules_db.json --host 127.0.0.1 --port 8000
```

Открыть:
- панель: `http://127.0.0.1:8000/ui`
- demo shop: `http://127.0.0.1:8000/shop`

API:
- `GET /api/rls` (вся база)
- `POST /api/tst` (проверка строки)

### Demo shop сценарии

- Добавить товар в корзину, открыть `/shop/cart`
- Оформить заказ на `/shop/checkout` (после этого будет страница `/shop/order/{id}`)


## WAF API

Запуск:

```bash
python -m waflite.apimain --db data/rules_db.json --host 127.0.0.1 --port 8010
```

Swagger/OpenAPI:
- `http://127.0.0.1:8010/docs`

Пример:

```bash
curl -s -X POST http://127.0.0.1:8010/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"req":"GET /?id=1 UNION SELECT 1 HTTP/1.1","ua":"Mozilla/5.0"}'
```
