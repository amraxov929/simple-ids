"""
rules/brute_force_rule.py
--------------------------
BruteForceRule - BaseRule Alt Sınıfı
Aynı IP adresinden kısa sürede çok sayıda başarısız giriş denemesi varsa
brute force saldırısı olarak işaretler.
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional
from rules.base_rule import BaseRule
from models.log_event import LogEvent


class BruteForceRule(BaseRule):
    """
    Brute Force saldırısı tespit kuralı.

    Aynı IP'den belirli bir zaman diliminde (window_seconds)
    belirli sayıda (threshold) başarısız giriş denemesi varsa alarm üretir.

    BaseRule'dan miras alır (Inheritance).
    analyze() metodu polimorfik olarak override edilir (Polymorphism).
    """

    # Brute force olarak kabul edilen eylem kelimeleri
    FAILED_ACTIONS = {"failed", "failure", "invalid", "authentication failure",
                      "login failed", "invalid password", "invalid user"}

    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        super().__init__(
            name="BruteForceRule",
            description=(f"Aynı IP'den {window_seconds}sn içinde "
                         f"{threshold} başarısız giriş denemesi")
        )
        self.__threshold = threshold
        self.__window = timedelta(seconds=window_seconds)
        # IP -> [timestamp listesi] eşlemesi
        self.__attempts: dict[str, list[datetime]] = defaultdict(list)

    def analyze(self, event: LogEvent) -> Optional[str]:
        """
        Gelen log olayını brute force kuralına göre analiz eder.
        Başarısız giriş denemesi değilse None döner.
        Eşik aşılırsa uyarı üretir ve uyarı mekanizmalarını tetikler.
        """
        # Yalnızca başarısız giriş eylemlerini izle
        action_lower = event.action.lower()
        is_failed = any(keyword in action_lower for keyword in self.FAILED_ACTIONS)
        if not is_failed:
            return None

        ip = event.ip_address
        now = event.timestamp

        # Zaman penceresi dışındaki kayıtları temizle
        self.__attempts[ip] = [
            t for t in self.__attempts[ip]
            if now - t <= self.__window
        ]
        self.__attempts[ip].append(now)

        count = len(self.__attempts[ip])
        if count >= self.__threshold:
            msg = (f"{ip} IP'sinden Brute Force saldırısı tespit edildi! "
                   f"({count} başarısız deneme, son "
                   f"{self.__window.seconds}sn içinde)")
            self._trigger_alerts(ip, msg)
            # Uyarı sonrası sayacı sıfırla (tekrar alarm üretmemek için)
            self.__attempts[ip].clear()
            return msg

        return None

    def reset(self) -> None:
        """Tüm IP denemelerini sıfırlar."""
        self.__attempts.clear()
