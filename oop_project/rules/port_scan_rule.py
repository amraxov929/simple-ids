"""
rules/port_scan_rule.py
------------------------
PortScanRule - BaseRule Alt Sınıfı
Bir IP adresinin kısa sürede farklı portlara erişmeye çalışması
durumunda port tarama (port scanning) saldırısı olarak işaretler.
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional
from rules.base_rule import BaseRule
from models.log_event import LogEvent


class PortScanRule(BaseRule):
    """
    Port Scan saldırısı tespit kuralı.

    Aynı IP'den belirli bir zaman diliminde (window_seconds)
    belirli sayıda (threshold) farklı porta erişim denemesi varsa alarm üretir.

    BaseRule'dan miras alır (Inheritance).
    analyze() metodu polimorfik olarak override edilir (Polymorphism).
    """

    # Port erişimini gösteren eylem kelimeleri
    PORT_ACTIONS = {"port", "connect", "syn", "access", "scan",
                    "connection attempt", "refused", "open", "closed"}

    def __init__(self, threshold: int = 10, window_seconds: int = 30):
        super().__init__(
            name="PortScanRule",
            description=(f"Aynı IP'den {window_seconds}sn içinde "
                         f"{threshold} farklı porta erişim denemesi")
        )
        self.__threshold = threshold
        self.__window = timedelta(seconds=window_seconds)
        # IP -> {(port, timestamp)} seti
        self.__port_hits: dict[str, list[tuple[int, datetime]]] = defaultdict(list)

    def analyze(self, event: LogEvent) -> Optional[str]:
        """
        Gelen log olayını port tarama kuralına göre analiz eder.
        Port bilgisi içermeyen olaylar göz ardı edilir.
        """
        if event.port is None:
            return None

        action_lower = event.action.lower()
        is_port_action = any(keyword in action_lower for keyword in self.PORT_ACTIONS)
        if not is_port_action:
            return None

        ip = event.ip_address
        now = event.timestamp

        # Zaman penceresi dışındaki kayıtları temizle
        self.__port_hits[ip] = [
            (p, t) for (p, t) in self.__port_hits[ip]
            if now - t <= self.__window
        ]
        self.__port_hits[ip].append((event.port, now))

        # Benzersiz port sayısını kontrol et
        unique_ports = {p for (p, _) in self.__port_hits[ip]}
        count = len(unique_ports)

        if count >= self.__threshold:
            ports_str = ", ".join(str(p) for p in sorted(unique_ports)[:10])
            msg = (f"{ip} IP'sinden Port Scan saldırısı tespit edildi! "
                   f"(Son {self.__window.seconds}sn'de {count} farklı port: "
                   f"{ports_str}{'...' if count > 10 else ''})")
            self._trigger_alerts(ip, msg)
            self.__port_hits[ip].clear()
            return msg

        return None

    def reset(self) -> None:
        """Tüm IP port geçmişini sıfırlar."""
        self.__port_hits.clear()
