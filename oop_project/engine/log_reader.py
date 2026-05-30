"""
engine/log_reader.py
---------------------
LogReader Sınıfı
Hedef log dosyasını satır satır okur ve her satırı
ayrıştırarak bir LogEvent nesnesine dönüştürür.

Desteklenen format örnekleri:
  SSH  : May 12 10:23:45 server sshd: Failed password for root from 192.168.1.50 port 22
  WEB  : 192.168.1.100 - - [12/May/2024:10:25:01 +0300] "GET /admin HTTP/1.1" 401
  PORT : [2024-05-12 10:30:00] PORT SCAN 192.168.1.200:4444 -> 10.0.0.1:80
"""

import re
from datetime import datetime
from typing import Optional, Generator
from models.log_event import LogEvent


class LogReader:
    """
    Log dosyasını okuyup LogEvent nesnelerine dönüştüren sınıf.
    Desteklenen format sayısı genişletilebilir (Strategy Pattern uyumlu).
    """

    # --- Regex Desenleri ---

    # SSH log deseni: May 12 10:23:45 server sshd: Failed password for root from 192.168.1.50 port 22
    _SSH_PATTERN = re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
        r".*?(?P<action>Failed password|Accepted password|Invalid user|"
        r"authentication failure|Connection closed|Disconnected)"
        r".*?from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        r"(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE
    )

    # Apache/Nginx access log: 192.168.1.100 - - [12/May/2024:10:25:01 +0300] "GET /admin" 401
    _WEB_PATTERN = re.compile(
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+"
        r"\[(?P<day>\d{2})/(?P<month>\w{3})/(?P<year>\d{4}):(?P<time>\d{2}:\d{2}:\d{2})"
        r".*?\]\s+\"(?P<method>\w+)\s+(?P<path>\S+).*?\"\s+(?P<status>\d{3})",
        re.IGNORECASE
    )

    # Özel port scan formatı: [2024-05-12 10:30:00] PORT CONNECT 192.168.1.200 port 4444
    _PORT_PATTERN = re.compile(
        r"\[(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]"
        r"\s+(?P<action>PORT\s+\w+|SYN|CONNECT|SCAN)"
        r"\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        r"(?::(?P<port>\d+)|\s+port\s+(?P<port2>\d+))?",
        re.IGNORECASE
    )

    # Genel format: [2024-05-12 10:30:00] IP=192.168.1.x ACTION=... PORT=...
    _GENERIC_PATTERN = re.compile(
        r"\[?(?P<ts>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})\]?"
        r".*?(?:IP[=:\s]+)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        r".*?(?:ACTION[=:\s]+)?(?P<action>[A-Z][A-Z\s_]+)"
        r"(?:.*?(?:PORT[=:\s]+)?(?P<port>\d{2,5}))?",
        re.IGNORECASE
    )

    _MONTH_MAP = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
        "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
        "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    def __init__(self, filepath: str):
        self.__filepath = filepath
        self.__parsed_count = 0
        self.__skipped_count = 0

    @property
    def filepath(self) -> str:
        return self.__filepath

    @property
    def parsed_count(self) -> int:
        return self.__parsed_count

    @property
    def skipped_count(self) -> int:
        return self.__skipped_count

    def read_events(self) -> Generator[LogEvent, None, None]:
        """
        Log dosyasını satır satır okur ve LogEvent nesneleri üretir (generator).
        Tanınan format: SSH, Web, Port veya genel format.
        """
        self.__parsed_count = 0
        self.__skipped_count = 0

        with open(self.__filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                event = (self._parse_ssh(line)
                         or self._parse_web(line)
                         or self._parse_port(line)
                         or self._parse_generic(line))

                if event:
                    self.__parsed_count += 1
                    yield event
                else:
                    self.__skipped_count += 1

    # --- Özel Ayrıştırıcılar ---

    def _parse_ssh(self, line: str) -> Optional[LogEvent]:
        m = self._SSH_PATTERN.search(line)
        if not m:
            return None
        try:
            month = self._MONTH_MAP.get(m.group("month"), 1)
            day = int(m.group("day"))
            h, mi, s = map(int, m.group("time").split(":"))
            ts = datetime(datetime.now().year, month, day, h, mi, s)
            port = int(m.group("port")) if m.group("port") else None
            return LogEvent(
                ip_address=m.group("ip"),
                timestamp=ts,
                action=m.group("action"),
                port=port,
                extra=line
            )
        except (ValueError, KeyError):
            return None

    def _parse_web(self, line: str) -> Optional[LogEvent]:
        m = self._WEB_PATTERN.search(line)
        if not m:
            return None
        try:
            month = self._MONTH_MAP.get(m.group("month"), 1)
            day = int(m.group("day"))
            year = int(m.group("year"))
            h, mi, s = map(int, m.group("time").split(":"))
            ts = datetime(year, month, day, h, mi, s)
            status = m.group("status")
            action = f"HTTP {m.group('method')} {status}"
            if status.startswith("4") or status.startswith("5"):
                action = f"Failed HTTP {m.group('method')} (status={status})"
            return LogEvent(
                ip_address=m.group("ip"),
                timestamp=ts,
                action=action,
                extra=m.group("path")
            )
        except (ValueError, KeyError):
            return None

    def _parse_port(self, line: str) -> Optional[LogEvent]:
        m = self._PORT_PATTERN.search(line)
        if not m:
            return None
        try:
            ts = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S")
            port_str = m.group("port") or m.group("port2")
            port = int(port_str) if port_str else None
            return LogEvent(
                ip_address=m.group("ip"),
                timestamp=ts,
                action=m.group("action").strip(),
                port=port,
                extra=line
            )
        except (ValueError, KeyError, AttributeError):
            return None

    def _parse_generic(self, line: str) -> Optional[LogEvent]:
        m = self._GENERIC_PATTERN.search(line)
        if not m:
            return None
        try:
            ts_str = m.group("ts").replace("T", " ")
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            port_str = m.group("port")
            port = int(port_str) if port_str and port_str.isdigit() else None
            return LogEvent(
                ip_address=m.group("ip"),
                timestamp=ts,
                action=m.group("action").strip(),
                port=port,
                extra=line
            )
        except (ValueError, KeyError):
            return None
