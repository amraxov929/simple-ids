# -*- coding: utf-8 -*-
"""
main.py
--------
IDS (Intrusion Detection System) - Ana Giris Noktasi
Kullaniciya interaktif CLI menusu sunar.

Kullanım:
    python main.py
"""

import os
import sys
import time
import io

# Windows terminalini UTF-8'e zorla
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

# ---------- Renk Kodları ----------
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    BG_RED  = "\033[41m"
    BG_DARK = "\033[40m"


# ---------- IDS Bileşenlerini İçe Aktar ----------
from models.log_event       import LogEvent
from rules.brute_force_rule import BruteForceRule
from rules.port_scan_rule   import PortScanRule
from alerts.console_alert   import ConsoleAlert
from alerts.file_alert      import FileAlert
from engine.detection_engine import DetectionEngine
from engine.log_reader       import LogReader


# ---------- Yardımcı Fonksiyonlar ----------

def banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(C.CYAN + C.BOLD)
    print("+" + "=" * 63 + "+")
    print("|" + " " * 63 + "|")
    print("|     ___  ____  ____    ____  _____                         |")
    print(r"|    |_ _||  _ \/ ___|  |  _ \/ ____|                        |")
    print(r"|     | | | | | \___ \  | | | \__ \                         |")
    print("|     | | | |_| |___) | | |_| |__) |                        |")
    print("|    |___||____/|____/  |____/|____/                         |")
    print("|" + " " * 63 + "|")
    print("|       Intrusion Detection System  |  v1.0.0               |")
    print("|       OOP Dersi Projesi  -  Signature-Based HIDS          |")
    print("+" + "=" * 63 + "+")
    print(C.RESET)


def separator(char="─", width=65, color=C.DIM):
    print(color + char * width + C.RESET)


def print_info(label: str, value: str):
    print(f"  {C.YELLOW}{label:<18}{C.RESET}{value}")


def wait_enter():
    input(f"\n  {C.DIM}[Enter'a basarak devam edin...]{C.RESET}")


def prompt(text: str) -> str:
    return input(f"  {C.CYAN}► {C.RESET}{text}")


# ---------- Motor Durumu ----------

engine          = DetectionEngine()
console_alert   = ConsoleAlert()
file_alert      = FileAlert("detected_threats.txt")
loaded_log_file = None   # Şu an yüklü log dosyası


def _setup_engine_defaults():
    """Motoru varsayılan kural ve uyarı mekanizmalarıyla hazırlar."""
    global engine
    engine = DetectionEngine()

    bf_rule = BruteForceRule(threshold=5, window_seconds=60)
    ps_rule = PortScanRule(threshold=10, window_seconds=30)

    bf_rule.add_alert(console_alert)
    bf_rule.add_alert(file_alert)
    ps_rule.add_alert(console_alert)
    ps_rule.add_alert(file_alert)

    engine.add_rule(bf_rule)
    engine.add_rule(ps_rule)


# ---------- Menü İşlemleri ----------

def menu_load_log():
    """1 - Log Dosyası Yükle"""
    global loaded_log_file
    banner()
    separator()
    print(f"  {C.BOLD}LOG DOSYASI YÜKLE{C.RESET}")
    separator()
    print(f"\n  {C.DIM}Hazır örnek dosyalar:{C.RESET}")
    print(f"  {C.GREEN}  1){C.RESET} sample_logs/ssh_logs.txt")
    print(f"  {C.GREEN}  2){C.RESET} sample_logs/web_logs.txt")
    print(f"  {C.GREEN}  3){C.RESET} Kendi dosya yolumu gireceğim\n")

    choice = prompt("Seçiminiz (1/2/3): ").strip()
    if choice == "1":
        path = "sample_logs/ssh_logs.txt"
    elif choice == "2":
        path = "sample_logs/web_logs.txt"
    elif choice == "3":
        path = prompt("Dosya yolu: ").strip()
    else:
        print(f"\n  {C.RED}Geçersiz seçim.{C.RESET}")
        wait_enter()
        return

    if not os.path.isfile(path):
        print(f"\n  {C.RED}✗ Dosya bulunamadı: {path}{C.RESET}")
        wait_enter()
        return

    loaded_log_file = path
    print(f"\n  {C.GREEN}✓ Dosya yüklendi: {C.BOLD}{path}{C.RESET}")
    wait_enter()


def menu_list_rules():
    """2 - Kuralları Listele"""
    banner()
    separator()
    print(f"  {C.BOLD}YÜKLÜ TESPİT KURALLARI{C.RESET}")
    separator()

    rules = engine.get_rules()
    if not rules:
        print(f"\n  {C.YELLOW}Henüz kural yüklenmedi.{C.RESET}")
    else:
        print()
        for i, rule in enumerate(rules, 1):
            print(f"  {C.GREEN}{i}. {C.BOLD}{rule.name}{C.RESET}")
            print(f"     {C.DIM}{rule.description}{C.RESET}")
            print()

    wait_enter()


def menu_run_analysis():
    """3 - Analizi Başlat"""
    banner()
    separator()
    print(f"  {C.BOLD}ANALİZ BAŞLATILIYOR{C.RESET}")
    separator()

    if not loaded_log_file:
        print(f"\n  {C.RED}✗ Önce bir log dosyası yükleyin! (Menü → 1){C.RESET}")
        wait_enter()
        return

    print_info("Log Dosyası:", loaded_log_file)
    print_info("Aktif Kurallar:", str(len(engine.get_rules())))
    print()

    engine.reset_all_rules()
    reader = LogReader(loaded_log_file)

    print(f"  {C.CYAN}Analiz çalışıyor...{C.RESET}\n")
    separator("─", 65, C.DIM)

    start_time = time.time()
    threats_found = engine.run_analysis(reader.read_events())
    elapsed = time.time() - start_time

    separator("─", 65, C.DIM)
    print()
    print(f"  {C.BOLD}SONUÇ ÖZETI{C.RESET}")
    separator()
    print_info("Okunan Satır:", str(reader.parsed_count + reader.skipped_count))
    print_info("Ayrıştırılan:", str(reader.parsed_count))
    print_info("Atlanan:", str(reader.skipped_count))
    print_info("Süre:", f"{elapsed:.2f}s")
    separator()

    if threats_found > 0:
        print(f"  {C.BG_RED}{C.BOLD} ⚠  {threats_found} tehdit tespit edildi! {C.RESET}")
        print(f"\n  {C.YELLOW}Ayrıntılar: {C.BOLD}detected_threats.txt{C.RESET}")
    else:
        print(f"  {C.GREEN}{C.BOLD}✓  Tehdit tespit edilmedi.{C.RESET}")

    print()
    wait_enter()


def menu_configure_rules():
    """4 - Kural Ayarları"""
    banner()
    separator()
    print(f"  {C.BOLD}KURAL AYARLARI{C.RESET}")
    separator()
    print()
    print(f"  {C.YELLOW}Brute Force Kuralı Ayarları{C.RESET}")
    try:
        threshold = int(prompt("  Eşik (başarısız deneme sayısı) [varsayılan=5]: ").strip() or "5")
        window    = int(prompt("  Zaman penceresi (saniye)        [varsayılan=60]: ").strip() or "60")
    except ValueError:
        print(f"\n  {C.RED}Geçersiz değer. Varsayılanlar kullanılıyor.{C.RESET}")
        threshold, window = 5, 60

    print()
    print(f"  {C.YELLOW}Port Scan Kuralı Ayarları{C.RESET}")
    try:
        ps_threshold = int(prompt("  Eşik (farklı port sayısı)      [varsayılan=10]: ").strip() or "10")
        ps_window    = int(prompt("  Zaman penceresi (saniye)        [varsayılan=30]: ").strip() or "30")
    except ValueError:
        print(f"\n  {C.RED}Geçersiz değer. Varsayılanlar kullanılıyor.{C.RESET}")
        ps_threshold, ps_window = 10, 30

    # Motoru yeni ayarlarla yeniden kur
    global engine
    engine = DetectionEngine()
    bf = BruteForceRule(threshold=threshold, window_seconds=window)
    ps = PortScanRule(threshold=ps_threshold, window_seconds=ps_window)
    bf.add_alert(console_alert)
    bf.add_alert(file_alert)
    ps.add_alert(console_alert)
    ps.add_alert(file_alert)
    engine.add_rule(bf)
    engine.add_rule(ps)

    print(f"\n  {C.GREEN}✓ Kural ayarları güncellendi.{C.RESET}")
    wait_enter()


def menu_view_threats():
    """5 - Tehdit Kayıtlarını Görüntüle"""
    banner()
    separator()
    print(f"  {C.BOLD}TEHDİT KAYIT DOSYASI{C.RESET}")
    separator()

    threat_file = "detected_threats.txt"
    if not os.path.isfile(threat_file):
        print(f"\n  {C.YELLOW}Henüz tehdit kaydı yok.{C.RESET}")
        wait_enter()
        return

    print()
    with open(threat_file, "r", encoding="utf-8") as f:
        content = f.read()

    if content.strip():
        # Tehdit satırlarını renklendir
        for line in content.splitlines():
            if "TEHDİT" in line.upper():
                print(f"  {C.RED}{C.BOLD}{line}{C.RESET}")
            elif "Kural" in line or "Kaynak" in line or "Mesaj" in line:
                print(f"  {C.YELLOW}{line}{C.RESET}")
            elif line.startswith("─") or line.startswith("="):
                print(f"  {C.DIM}{line}{C.RESET}")
            else:
                print(f"  {line}")
    else:
        print(f"  {C.DIM}(Dosya boş){C.RESET}")

    print()
    wait_enter()


def menu_about():
    """6 - Hakkında"""
    banner()
    separator()
    print(f"  {C.BOLD}PROJE HAKKINDA{C.RESET}")
    separator()
    print()
    print_info("Proje Adı:",  "Basit IDS - Intrusion Detection System")
    print_info("Tür:",        "Signature-Based Host-Based IDS")
    print_info("Dil:",        "Python 3.10+")
    print_info("Konu:",       "OOP Dersi Bitirme Projesi")
    print()
    separator()
    print(f"  {C.BOLD}OOP PRENSİPLERİ{C.RESET}")
    separator()
    print(f"  {C.GREEN}Encapsulation :{C.RESET} LogEvent - private alanlar & property'ler")
    print(f"  {C.GREEN}Inheritance   :{C.RESET} BruteForceRule, PortScanRule ← BaseRule")
    print(f"  {C.GREEN}Polymorphism  :{C.RESET} Her kural analyze() metodunu farklı uygular")
    print(f"  {C.GREEN}Abstraction   :{C.RESET} BaseRule (ABC), IAlertMechanism (ABC)")
    print(f"  {C.GREEN}Aggregation   :{C.RESET} DetectionEngine → BaseRule[] listesi barındırır")
    print()
    separator()
    print(f"  {C.BOLD}SINIFLAR{C.RESET}")
    separator()
    classes = [
        ("models/",  "LogEvent",           "Log satırı veri modeli"),
        ("rules/",   "BaseRule",           "Soyut kural temel sınıfı"),
        ("rules/",   "BruteForceRule",     "Brute force tespit kuralı"),
        ("rules/",   "PortScanRule",       "Port tarama tespit kuralı"),
        ("alerts/",  "IAlertMechanism",    "Uyarı mekanizması arayüzü"),
        ("alerts/",  "ConsoleAlert",       "Konsol uyarı mekanizması"),
        ("alerts/",  "FileAlert",          "Dosya uyarı mekanizması"),
        ("engine/",  "DetectionEngine",    "Ana analiz motoru"),
        ("engine/",  "LogReader",          "Log dosyası okuyucu/ayrıştırıcı"),
    ]
    for pkg, cls, desc in classes:
        print(f"  {C.DIM}{pkg}{C.RESET}{C.CYAN}{C.BOLD}{cls:<22}{C.RESET}{C.DIM}{desc}{C.RESET}")

    print()
    wait_enter()


# ---------- Ana Menü ----------

def main():
    # Windows konsolunda ANSI renklerini etkinleştir
    if os.name == "nt":
        os.system("color")

    _setup_engine_defaults()

    while True:
        banner()

        # Durum bilgisi
        status_log  = (f"{C.GREEN}{loaded_log_file}{C.RESET}"
                       if loaded_log_file else f"{C.RED}Yüklenmedi{C.RESET}")
        status_rule = f"{C.GREEN}{len(engine.get_rules())} kural aktif{C.RESET}"

        print(f"  {C.DIM}Log Dosyası : {C.RESET}{status_log}")
        print(f"  {C.DIM}Kurallar    : {C.RESET}{status_rule}")
        print()
        separator()
        print(f"  {C.BOLD}ANA MENÜ{C.RESET}")
        separator()
        print(f"  {C.CYAN}1{C.RESET}) Log Dosyası Yükle")
        print(f"  {C.CYAN}2{C.RESET}) Kuralları Listele")
        print(f"  {C.CYAN}3{C.RESET}) Analizi Başlat")
        print(f"  {C.CYAN}4{C.RESET}) Kural Ayarları")
        print(f"  {C.CYAN}5{C.RESET}) Tehdit Kayıtlarını Görüntüle")
        print(f"  {C.CYAN}6{C.RESET}) Hakkında")
        print(f"  {C.RED}0{C.RESET}) Çıkış")
        separator()

        choice = prompt("Seçiminiz: ").strip()

        if   choice == "1": menu_load_log()
        elif choice == "2": menu_list_rules()
        elif choice == "3": menu_run_analysis()
        elif choice == "4": menu_configure_rules()
        elif choice == "5": menu_view_threats()
        elif choice == "6": menu_about()
        elif choice == "0":
            banner()
            print(f"  {C.GREEN}Güvenli kalın! IDS kapatılıyor...{C.RESET}\n")
            sys.exit(0)
        else:
            print(f"\n  {C.RED}Geçersiz seçim. Lütfen tekrar deneyin.{C.RESET}")
            time.sleep(1)


if __name__ == "__main__":
    main()
