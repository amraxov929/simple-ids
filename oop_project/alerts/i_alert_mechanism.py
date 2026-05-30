"""
alerts/i_alert_mechanism.py
----------------------------
Arayüz (Interface) - IAlertMechanism
Uyarı mekanizmalarının uymak zorunda olduğu sözleşme.
Python'da ABC (Abstract Base Class) kullanılarak interface simüle edilir.
"""

from abc import ABC, abstractmethod


class IAlertMechanism(ABC):
    """
    Tüm uyarı mekanizmalarının uygulaması gereken arayüz.
    Yeni uyarı kanalları eklemek için bu arayüzden türetmek yeterlidir
    (Örn: EmailAlert, SlackAlert, SMSAlert...).
    """

    @abstractmethod
    def send_alert(self, rule_name: str, ip_address: str, message: str) -> None:
        """
        Bir uyarı gönderir.

        :param rule_name: Tetiklenen kuralın adı (örn: 'BruteForceRule')
        :param ip_address: Saldırıya kaynak olan IP adresi
        :param message: Uyarı mesajı
        """
        pass
