#!/usr/bin/env python3
"""
Универсальный защитный экран (Reverse-Proxy WAF) для веб-сайта / веб-сервиса.
Работает на чистом Python (без установки сторонних библиотек).

Что делает скрипт:
  1. Принимает все входящие запросы на внешнем порту (например, 8000).
  2. Отсекает спам и перебор (Rate Limit — лимит запросов с одного IP).
  3. Проверяет адрес, параметры, заголовки и тело запроса на типовые веб-атаки
     (SQL-инъекции, обход папок ../, XSS, инъекции команд).
  4. Безопасные запросы прозрачно передаёт настоящему сайту (например, на порт 5000).
  5. Все заблокированные попытки записывает в файл waf_alerts.log.
"""
from collections import defaultdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import time
import urllib.error
import urllib.parse
import urllib.request

# ================= НАСТРОЙКИ ЗАЩИТЫ =================
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8000                     # Порт, на который заходят пользователи извне
BACKEND_URL = "http://127.0.0.1:5000"  # Внутренний адрес вашего защищаемого сайта

MAX_REQ_PER_10_SEC = 40                # Максимум запросов с одного IP за 10 секунд
WHITELIST_IPS = {"127.0.0.1"}          # Белый список IP (например, свой адрес или проверка мониторинга)
LOG_FILE = "waf_alerts.log"            # Куда сохранять журнал заблокированных атак
# ====================================================

# Сигнатуры типовых веб-атак
WAF_SIGNATURES = [
    ("SQL-инъекция", re.compile(r"(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|'\s*or\s+['\d]+=\s*['\d]+|--\s)", re.IGNORECASE)),
    ("Чтение чужих файлов (Path Traversal)", re.compile(r"(\.\./|\.\.\\|/etc/passwd|boot\.ini|\.env)", re.IGNORECASE)),
    ("XSS-скрипт", re.compile(r"(<\s*script|javascript\s*:|onerror\s*=|onload\s*=)", re.IGNORECASE)),
    ("Инъекция системных команд", re.compile(r"(;\s*(cat|ls|id|whoami|bash|sh|nc|curl|wget)\b|\|\s*(bash|sh)\b|\$\()", re.IGNORECASE)),
]

ip_requests: dict[str, list[float]] = defaultdict(list)


def log_alert(client_ip: str, reason: str, method: str, path: str):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] БЛОК | IP: {client_ip} | Причина: {reason} | {method} {path}\n"
    print(line.strip(), flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def is_rate_limited(client_ip: str) -> bool:
    if client_ip in WHITELIST_IPS:
        return False
    now = time.time()
    # Оставляем только запросы за последние 10 секунд
    recent = [t for t in ip_requests[client_ip] if now - t < 10.0]
    recent.append(now)
    ip_requests[client_ip] = recent
    return len(recent) > MAX_REQ_PER_10_SEC


def inspect_request(raw_text: str) -> str | None:
    """Возвращает название угрозы, если сработало правило, иначе None."""
    decoded = urllib.parse.unquote_plus(raw_text)
    for rule_name, pattern in WAF_SIGNATURES:
        if pattern.search(decoded):
            return rule_name
    return None


class ShieldProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def block(self, code: int, message: str):
        body = f'{{"status": "blocked", "reason": "{message}"}}'.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_proxy(self):
        client_ip = self.client_address[0]

        # 1. Проверка частоты запросов (защита от флуда и брутфорса)
        if is_rate_limited(client_ip):
            log_alert(client_ip, "Превышен лимит запросов (Rate Limit)", self.command, self.path)
            return self.block(429, "Too Many Requests")

        # 2. Читаем тело запроса (если есть)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""

        # 3. Проверяем путь, заголовки и тело через правила WAF
        headers_dump = " ".join(f"{k}: {v}" for k, v in self.headers.items())
        full_sample = f"{self.path}\n{headers_dump}\n{body.decode('utf-8', errors='ignore')}"

        threat = inspect_request(full_sample)
        if threat:
            log_alert(client_ip, threat, self.command, self.path)
            return self.block(403, "Forbidden by Security Shield")

        # 4. Пересылаем чистый запрос настоящему сайту
        target_url = f"{BACKEND_URL}{self.path}"
        forward_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in ("host", "content-length")
        }
        req = urllib.request.Request(
            target_url,
            data=body if body else None,
            headers=forward_headers,
            method=self.command,
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp_body = resp.read()
                status = resp.status
                resp_headers = resp.getheaders()
        except urllib.error.HTTPError as e:
            resp_body = e.read()
            status = e.code
            resp_headers = list(e.headers.items())
        except Exception:
            return self.block(502, "Backend service unavailable")

        # 5. Скрываем случайные системные ошибки БД в ответе сервера
        if status >= 500 or b"Traceback (most recent call last)" in resp_body:
            return self.block(500, "Internal Server Error")

        self.send_response(status)
        for k, v in resp_headers:
            if k.lower() not in ("transfer-encoding", "content-encoding", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def do_GET(self):
        self.handle_proxy()

    def do_POST(self):
        self.handle_proxy()

    def do_PUT(self):
        self.handle_proxy()

    def do_DELETE(self):
        self.handle_proxy()


if __name__ == "__main__":
    print(f"[*] Защитный экран запущен на http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[*] Защищаемый сайт: {BACKEND_URL}")
    print(f"[*] Журнал тревог: {LOG_FILE}")
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), ShieldProxyHandler)
    server.serve_forever()
