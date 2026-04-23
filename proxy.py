"""
Мини-прокси для обхода CORS при обращении к zakupki.gov.ru из браузера.

Запуск:
    python proxy.py

Далее в HTML-читалке выбираем режим "Локальный прокси" — fetch будет
идти на http://127.0.0.1:8765/?url=<xmlUrl>, прокси скачает XML
и вернёт его браузеру с заголовком Access-Control-Allow-Origin: *.

Без внешних зависимостей — только стандартная библиотека.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request
import ssl
import sys

HOST = "127.0.0.1"
PORT = 8765

# zakupki.gov.ru иногда возвращает сертификаты, которые не любит urllib.
# Для локальной работы отключаем строгую проверку — это локальный прокси.
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

ALLOWED_HOSTS = {"zakupki.gov.ru", "www.zakupki.gov.ru"}


class ProxyHandler(BaseHTTPRequestHandler):
    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        target = params.get("url", [None])[0]

        if not target:
            self.send_response(400)
            self._cors_headers()
            self.end_headers()
            self.wfile.write(b"Missing ?url= parameter")
            return

        # Защита: пускаем только на zakupki.gov.ru
        host = urlparse(target).hostname or ""
        if host not in ALLOWED_HOSTS:
            self.send_response(403)
            self._cors_headers()
            self.end_headers()
            self.wfile.write(f"Host not allowed: {host}".encode("utf-8"))
            return

        try:
            req = urllib.request.Request(
                target,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; LocalProxy/1.0)",
                    "Accept": "application/xml, text/xml, */*",
                },
            )
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as r:
                data = r.read()
                content_type = r.headers.get("Content-Type", "application/xml; charset=utf-8")
        except Exception as exc:
            self.send_response(502)
            self._cors_headers()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"Upstream error: {exc}".encode("utf-8"))
            return

        self.send_response(200)
        self._cors_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # Глушим шумный лог
    def log_message(self, fmt, *args):
        sys.stderr.write(f"[proxy] {self.address_string()} - {fmt % args}\n")


if __name__ == "__main__":
    print(f"Прокси запущен: http://{HOST}:{PORT}/?url=<xmlUrl>")
    print("Останов: Ctrl+C")
    try:
        HTTPServer((HOST, PORT), ProxyHandler).serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлен.")
