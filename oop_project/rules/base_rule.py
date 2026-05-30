"""
rules/base_rule.py
------------------
Soyut Kural Sınıfı (Abstract Class) - Inheritance & Polymorphism
Tüm tespit kurallarının miras alacağı temel sınıf.
"""

from abc import ABC, abstractmethod
from typing import Optional
from models.log_event import LogEvent
from alerts.i_alert_mechanism import IAlertMechanism


class BaseRule(ABC):
    """
    Tüm tespit kurallarının türediği soyut temel sınıf.
    Polymorphism: Her alt sınıf analyze() metodunu farklı biçimde uygular.
    Inheritance: Ortak özellikler (name, description, alerts) burada tanımlıdır.
    """

    def __init__(self, name: str, description: str):
        self._name = name
        self._description = description
        # Aggregation: Kural birden fazla uyarı mekanizması barındırabilir
        self._alert_mechanisms: list[IAlertMechanism] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    def add_alert(self, mechanism: IAlertMechanism) -> None:
        """Bu kurala bir uyarı mekanizması ekler."""
        self._alert_mechanisms.append(mechanism)

    def _trigger_alerts(self, ip_address: str, message: str) -> None:
        """Kayıtlı tüm uyarı mekanizmalarını tetikler."""
        for mechanism in self._alert_mechanisms:
            mechanism.send_alert(self._name, ip_address, message)

    @abstractmethod
    def analyze(self, event: LogEvent) -> Optional[str]:
        """
        Bir log olayını analiz eder.
        Tehdit tespit edilirse uyarı mesajı döndürür, aksi hâlde None.

        :param event: Analiz edilecek log olayı
        :return: Tehdit mesajı ya da None
        """
        pass

    def reset(self) -> None:
        """
        Kuralın iç durumunu sıfırlar.
        Durum tutan kurallar (BruteForce, PortScan) bu metodu override eder.
        """
        pass

    def __repr__(self) -> str:
        return f"[{self.__class__.__name__}] {self._name}: {self._description}"
