"""
engine/detection_engine.py
---------------------------
DetectionEngine - Ana Kontrol Sınıfı (Aggregation)
Kuralları ve uyarı mekanizmalarını yönetir, log olaylarını analiz eder.
"""

from typing import Optional
from rules.base_rule import BaseRule
from models.log_event import LogEvent
from alerts.i_alert_mechanism import IAlertMechanism


class DetectionEngine:
    """
    IDS'nin ana motoru. Aggregation prensibine göre:
    - Birden fazla kural (BaseRule) barındırır.
    - Her gelen LogEvent'i tüm kurallardan geçirir.
    - İhlal varsa kayıtlı uyarı mekanizmalarını tetikler.
    """

    def __init__(self):
        # Aggregation: Engine kendi oluşturmaz, dışarıdan alır
        self.__rules: list[BaseRule] = []
        self.__global_alerts: list[IAlertMechanism] = []
        self.__total_events = 0
        self.__total_threats = 0

    # --- Kural Yönetimi ---

    def add_rule(self, rule: BaseRule) -> None:
        """Motora bir tespit kuralı ekler."""
        self.__rules.append(rule)

    def remove_rule(self, rule_name: str) -> bool:
        """İsme göre bir kuralı motordan kaldırır."""
        before = len(self.__rules)
        self.__rules = [r for r in self.__rules if r.name != rule_name]
        return len(self.__rules) < before

    def get_rules(self) -> list[BaseRule]:
        """Yüklü kuralların kopyasını döner."""
        return list(self.__rules)

    # --- Global Uyarı Yönetimi ---

    def add_global_alert(self, mechanism: IAlertMechanism) -> None:
        """
        Global bir uyarı mekanizması ekler.
        Bu mekanizma otomatik olarak tüm kurallara eklenir.
        """
        self.__global_alerts.append(mechanism)
        for rule in self.__rules:
            rule.add_alert(mechanism)

    # --- Analiz ---

    def process_event(self, event: LogEvent) -> list[str]:
        """
        Tek bir LogEvent nesnesini tüm kurallara gönderir.
        :return: Tespit edilen tehdit mesajlarının listesi
        """
        self.__total_events += 1
        threats = []
        for rule in self.__rules:
            result = rule.analyze(event)
            if result:
                threats.append(result)
                self.__total_threats += 1
        return threats

    def run_analysis(self, events) -> int:
        """
        Bir event generator'ını veya listesini analiz eder.
        :param events: LogEvent nesneleri üreten iterable
        :return: Toplam tespit edilen tehdit sayısı
        """
        threats_found = 0
        for event in events:
            results = self.process_event(event)
            threats_found += len(results)
        return threats_found

    def reset_all_rules(self) -> None:
        """Tüm kuralların iç durumunu sıfırlar."""
        for rule in self.__rules:
            rule.reset()
        self.__total_events = 0
        self.__total_threats = 0

    # --- İstatistikler ---

    @property
    def total_events(self) -> int:
        return self.__total_events

    @property
    def total_threats(self) -> int:
        return self.__total_threats

    def get_summary(self) -> str:
        threat_rate = (
            (self.__total_threats / self.__total_events * 100)
            if self.__total_events > 0 else 0.0
        )
        return (
            f"İşlenen olay : {self.__total_events}\n"
            f"Tespit edilen: {self.__total_threats} tehdit\n"
            f"Tehdit oranı : %{threat_rate:.1f}"
        )
