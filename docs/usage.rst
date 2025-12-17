Usage
=====

Console scanner
---------------

Пример (nginx log -> jsonl):

.. code-block:: bash

   python -m waflite --in examples/nginx_access.log --fmt nginx --out out/report.jsonl --ofmt jsonl

Web panel + demo shop
---------------------

.. code-block:: bash

   python -m waflite.webmain --db data/rules_db.json --host 127.0.0.1 --port 8000

Открыть:
- /ui (панель правил)
- /shop (магазин)

WAF API
-------

.. code-block:: bash

   python -m waflite.apimain --db data/rules_db.json --host 127.0.0.1 --port 8010

Документация OpenAPI:
- http://127.0.0.1:8010/docs
- http://127.0.0.1:8010/openapi.json

Пример scan:

.. code-block:: bash

   curl -s -X POST http://127.0.0.1:8010/api/v1/scan \
     -H 'Content-Type: application/json' \
     -d '{"req":"GET /?id=1 UNION SELECT 1 HTTP/1.1","ua":"Mozilla/5.0"}' | jq

