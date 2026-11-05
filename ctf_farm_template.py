#!/usr/bin/env python3
"""
Универсальный модульный шаблон CTF-раннера (фермы сбора и сдачи флагов).
Работает на стандартном Python 3.10+ и библиотеке requests.

Поддерживает два способа добавления модулей:
  1. Прямо внутри этого файла — добавить функцию в список ACTIVE_MODULES.
  2. Без перезапуска — положить отдельный .py-скрипт в папку ./farm_modules/
     (раннер сам найдёт его на следующем раунде и передаст IP цели в sys.argv[1]).
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
import json
import re
import subprocess
import sys
import time
import requests

# ================= 1. НАСТРОЙКИ ТУРНИРА =================
JURY_URL = "http://127.0.0.1:8080"             # Базовый адрес табло жюри (ForcAD)
SUBMIT_ENDPOINT = f"{JURY_URL}/flags/"         # Адрес приёмника флагов
ATTACK_DATA_URL = f"{JURY_URL}/api/client/attack_data/"

TEAM_TOKEN = "1337133713371337"                # Ваш командный токен (X-Team-Token)
FLAG_REGEX = re.compile(r"[A-Z0-9]{31}=")      # Формат флага на турнире

MY_TEAM_IP = "10.60.1.2"                       # ВАШ IP (исключается автоматически!)
RAW_TARGETS = [
    "127.0.0.1",
    # Пример генерации списка команд на турнире (раскомментировать при необходимости):
    # *[f"10.60.{i}.2" for i in range(1, 21)],
]

ROUND_INTERVAL = 15                            # Пауза между циклами опроса (сек)
MAX_WORKERS = 15                               # Сколько потоков запускать параллельно
BATCH_LIMIT = 100                              # Максимум флагов в одной пачке отправки
MODULES_DIR = Path(__file__).parent / "farm_modules"
HISTORY_FILE = Path(__file__).parent / "submitted_flags.txt"
# ========================================================


def load_submitted_history() -> set[str]:
    """Загружает ранее отправленные флаги с диска, чтобы не слать дубли после перезапуска."""
    if not HISTORY_FILE.exists():
        return set()
    return {line.strip() for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines() if line.strip()}


def save_submitted_batch(flags: list[str]):
    """Дописывает отправленные флаги в локальный файл истории."""
    with HISTORY_FILE.open("a", encoding="utf-8") as f:
        for fl in flags:
            f.write(fl + "\n")


def fetch_attack_data() -> dict:
    """Получает публичные подсказки раунда (flag_id) от сервера жюри, если они доступны."""
    try:
        r = requests.get(ATTACK_DATA_URL, timeout=3)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return {}


# ================= 2. ВСТРОЕННЫЕ МОДУЛИ ОПРОСА =================
def module_example_public_api(ip: str, attack_data: dict) -> str:
    """
    Пример встроенного модуля.
    Принимает IP команды и словарь attack_data.
    Возвращает любую строку (например, r.text) — раннер сам вырежет из неё флаги по FLAG_REGEX.
    """
    url = f"http://{ip}:10002/api/public"
    r = requests.get(
        url,
        params={"limit": "10"},
        headers={"X-Client": "checker-compatible"},
        timeout=3,
    )
    return r.text


# Список активных встроенных функций (добавляй сюда свои новые функции через запятую):
ACTIVE_MODULES = [
    module_example_public_api,
]
# ===============================================================


def run_external_scripts(ip: str) -> set[str]:
    """Запускает все внешние .py-скрипты из папки ./farm_modules/ для указанного IP."""
    found = set()
    if not MODULES_DIR.exists():
        return found

    for script in sorted(MODULES_DIR.glob("*.py")):
        if script.name.startswith("_"):
            continue
        try:
            proc = subprocess.run(
                [sys.executable, str(script), ip],
                capture_output=True,
                text=True,
                timeout=6,
            )
            found.update(FLAG_REGEX.findall(proc.stdout))
        except subprocess.TimeoutExpired:
            print(f"  [!] Таймаут скрипта {script.name} на {ip}", flush=True)
        except Exception as e:
            print(f"  [!] Ошибка скрипта {script.name} на {ip}: {e}", flush=True)
    return found


def process_one_target(ip: str, attack_data: dict) -> set[str]:
    """Выполняет все встроенные функции и внешние скрипты против одного целевого IP."""
    collected = set()

    # 1. Встроенные функции из списка ACTIVE_MODULES
    for mod_func in ACTIVE_MODULES:
        try:
            raw_output = mod_func(ip, attack_data)
            if raw_output:
                collected.update(FLAG_REGEX.findall(str(raw_output)))
        except requests.RequestException:
            pass
        except Exception as e:
            print(f"  [!] Сбой модуля {mod_func.__name__} на {ip}: {e}", flush=True)

    # 2. Внешние скрипты из папки farm_modules/
    collected.update(run_external_scripts(ip))
    return collected


def submit_flags_to_jury(flags: list[str]) -> bool:
    """Отправляет новые флаги пачками в систему жюри."""
    ok_all = True
    for i in range(0, len(flags), BATCH_LIMIT):
        chunk = flags[i : i + BATCH_LIMIT]
        try:
            r = requests.put(
                SUBMIT_ENDPOINT,
                json=chunk,
                headers={"X-Team-Token": TEAM_TOKEN},
                timeout=5,
            )
            if r.ok:
                try:
                    for item in r.json():
                        print(f"  [ЖЮРИ] {item.get('msg', item)}", flush=True)
                except ValueError:
                    print(f"  [ЖЮРИ] {r.text[:200]}", flush=True)
            else:
                print(f"  [!] Жюри вернуло код {r.status_code}: {r.text[:150]}", flush=True)
                ok_all = False
        except Exception as e:
            print(f"  [!] Ошибка связи с жюри: {e}", flush=True)
            ok_all = False
    return ok_all


def main():
    MODULES_DIR.mkdir(exist_ok=True)
    targets = [ip for ip in RAW_TARGETS if ip != MY_TEAM_IP]
    submitted = load_submitted_history()

    print("=" * 68)
    print(f"  CTF РАННЕР ЗАПУЩЕН | Жюри: {JURY_URL}")
    print(f"  Целей в списке: {len(targets)} | Уже в истории флагов: {len(submitted)}")
    print(f"  Папка внешних модулей: {MODULES_DIR}")
    print("=" * 68)

    cycle = 1
    while True:
        stamp = datetime.now().strftime("%H:%M:%S")
        ext_count = len([p for p in MODULES_DIR.glob("*.py") if not p.name.startswith("_")])
        print(
            f"\n[{stamp}] Раунд #{cycle} | Встроенных модулей: {len(ACTIVE_MODULES)} | Внешних скриптов: {ext_count}",
            flush=True,
        )

        attack_data = fetch_attack_data()
        round_flags = set()

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = [pool.submit(process_one_target, ip, attack_data) for ip in targets]
            for fut in futures:
                round_flags.update(fut.result())

        fresh_flags = list(round_flags - submitted)
        if fresh_flags:
            print(f"  [+] Новых флагов: {len(fresh_flags)} шт. Отправляем в жюри...", flush=True)
            if submit_flags_to_jury(fresh_flags):
                submitted.update(fresh_flags)
                save_submitted_batch(fresh_flags)
        else:
            print("  [-] Новых флагов в этом цикле нет.", flush=True)

        cycle += 1
        time.sleep(ROUND_INTERVAL)


if __name__ == "__main__":
    main()
