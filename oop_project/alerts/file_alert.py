"""
alerts/file_alert.py
---------------------
FileAlert - IAlertMechanism Implementasyonu
Uyarıları 'detected_threats.txt' dosyasına kaydeder.
"""

import os
from datetime import datetime
from alerts.i_alert_mechanism import IAlertMechanism


class FileAlert(IAlertMechanism):
    """
    Uyarıları bir metin dosyasına kaydeden uyarı mekanizması.
    IAlertMechanism arayüzünü uygular.
    """

    def __init__(self, filepath: str = "detected_threats.txt"):
        self.__filepath = filepath
        # Dosya başlığı oluştur (eğer dosya yoksa)
        if not os.path.exists(self.__filepath):
            with open(self.__filepath, "w", encoding="utf-8") as f:
                f.write("=" * 65 + "\n")
                f.write("   IDS - Intrusion Detection System | Tehdit Kayıt Dosyası\n")
                f.write("=" * 65 + "\n\n")

    @property
    def filepath(self) -> str:
        return self.__filepath

    def send_alert(self, rule_name: str, ip_address: str, message: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.__filepath, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] TEHDİT TESPİT EDİLDİ\n")
            f.write(f"  Kural    : {rule_name}\n")
            f.write(f"  Kaynak IP: {ip_address}\n")
            f.write(f"  Mesaj    : {message}\n")
            f.write("-" * 65 + "\n")
