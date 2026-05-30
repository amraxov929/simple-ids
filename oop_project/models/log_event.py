"""
models/log_event.py
-------------------
Veri Modeli - Encapsulation
Her log satırını temsil eden sınıf.
"""

from datetime import datetime


class LogEvent:
    """
    Tek bir log kaydını temsil eden veri sınıfı.
    Encapsulation prensibine göre tüm alanlar private olarak
    tanımlanmış ve property'ler aracılığıyla erişilir.
    """

    def __init__(self, ip_address: str, timestamp: datetime,
                 action: str, port: int = None, extra: str = ""):
        # Private alanlar (Encapsulation)
        self.__ip_address = ip_address
        self.__timestamp = timestamp
        self.__action = action
        self.__port = port          # Port Scan gibi durumlarda port bilgisi
        self.__extra = extra        # Ek bilgi (kullanıcı adı, HTTP metodu vb.)

    # --- Property Tanımlamaları (Getters) ---

    @property
    def ip_address(self) -> str:
        return self.__ip_address

    @property
    def timestamp(self) -> datetime:
        return self.__timestamp

    @property
    def action(self) -> str:
        return self.__action

    @property
    def port(self) -> int:
        return self.__port

    @property
    def extra(self) -> str:
        return self.__extra

    def __repr__(self) -> str:
        ts_str = self.__timestamp.strftime("%Y-%m-%d %H:%M:%S")
        port_str = f":{self.__port}" if self.__port else ""
        return (f"LogEvent(ip={self.__ip_address}{port_str}, "
                f"time={ts_str}, action={self.__action})")
