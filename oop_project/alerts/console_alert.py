"""
alerts/console_alert.py
------------------------
ConsoleAlert - IAlertMechanism Implementasyonu
Uyarıları renkli olarak terminale yazdırır.
"""

from datetime import datetime
from alerts.i_alert_mechanism import IAlertMechanism


# ANSI renk kodları
class Colors:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    BG_RED  = "\033[41m"


class ConsoleAlert(IAlertMechanism):
    """
    Uyarıları renkli ANSI formatında konsola yazdıran uyarı mekanizması.
    IAlertMechanism arayüzünü uygular.
    """

    def send_alert(self, rule_name: str, ip_address: str, message: str) -> None:
        import sys
        # Windows cp1254 uyumlu çıktı için stdout encoding'i ayarla
        if hasattr(sys.stdout, 'reconfigure'):
            try:
                sys.stdout.reconfigure(encoding='utf-8')
            except Exception:
                pass
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        border = Colors.RED + "=" * 65 + Colors.RESET
        print(border)
        print(f"{Colors.BG_RED}{Colors.BOLD} [!] TEHDIT TESPIT EDILDI {Colors.RESET}")
        print(f"{Colors.YELLOW}  Zaman    : {Colors.RESET}{timestamp}")
        print(f"{Colors.YELLOW}  Kural    : {Colors.RESET}{Colors.CYAN}{rule_name}{Colors.RESET}")
        print(f"{Colors.YELLOW}  Kaynak IP: {Colors.RESET}{Colors.RED}{ip_address}{Colors.RESET}")
        print(f"{Colors.YELLOW}  Mesaj    : {Colors.RESET}{Colors.BOLD}{message}{Colors.RESET}")
        print(border)
