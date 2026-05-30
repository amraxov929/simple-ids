[README.md](https://github.com/user-attachments/files/28422597/README.md)
Basit IDS — Intrusion Detection System


Ağ log dosyalarını okuyarak Brute Force ve Port Tarama saldırılarını tespit eden, OOP prensiplerini (Encapsulation, Inheritance, Polymorphism, Abstraction, Aggregation) eksiksiz uygulayan basit bir saldırı tespit sistemidir.



Özellikler

- SSH ve web log dosyalarını ayrıştırır
- Brute Force saldırılarını tespit eder (zaman penceresi tabanlı)
- Port tarama girişimlerini tespit eder
- Tespitler konsola renkli olarak yazdırılır ve dosyaya kaydedilir
- Kural eşikleri ve zaman pencereleri kullanıcı tarafından yapılandırılabilir
- Interaktif CLI menüsü


<pre>
Proje Yapısı

oop_project/
├── main.py                      Ana giriş noktası, CLI menüsü
├── models/
│   └── log_event.py             LogEvent veri modeli (Encapsulation)
├── rules/
│   ├── base_rule.py             Soyut temel kural sınıfı (Abstraction)
│   ├── brute_force_rule.py      Brute Force tespit kuralı (Inheritance)
│   └── port_scan_rule.py        Port tarama tespit kuralı (Inheritance)
├── alerts/
│   ├── i_alert_mechanism.py     Uyarı arayüzü (Abstraction)
│   ├── console_alert.py         Konsol uyarı mekanizması (Polymorphism)
│   └── file_alert.py            Dosya uyarı mekanizması (Polymorphism)
├── engine/
│   ├── detection_engine.py      Ana analiz motoru (Aggregation)
│   └── log_reader.py            Log dosyası okuyucu/ayrıştırıcı
├── sample_logs/
│   ├── ssh_logs.txt             Örnek SSH log dosyası
│   └── web_logs.txt             Örnek web log dosyası
├── IDS_researchpaper_EN.docx    İngilizce makale
└── IDS_researchpaper_TR .docx   Türkçe makale
</pre>



OOP Prensipleri

| Prensip | Uygulama |
|---|---|
| Encapsulation | `LogEvent` — private alanlar ve `@property` kullanımı |
| Inheritance | `BruteForceRule`, `PortScanRule` → `BaseRule`'dan türer |
| Polymorphism | Her kural `analyze()` metodunu farklı şekilde uygular |
| Abstraction | `BaseRule` (ABC), `IAlertMechanism` (ABC) soyut sınıflar |
| Aggregation | `DetectionEngine` → `BaseRule[]` listesi barındırır |



Kurulum ve Çalıştırma

Python 3.10 veya üzeri gereklidir. Ekstra kütüphane gerekmez.

bash
Repoyu klonla
git clone https://github.com/<kullanıcı-adın>/oop_project.git
cd oop_project

Uygulamayı başlat
python main.py


Menü Seçenekleri

| Seçenek | İşlev |
|---|---|
| `1` | Log dosyası yükle (örnek veya özel) |
| `2` | Yüklü tespit kurallarını listele |
| `3` | Analizi başlat |
| `4` | Kural eşiklerini yapılandır |
| `5` | Tespit edilen tehditleri görüntüle |
| `6` | Proje hakkında |
| `0` | Çıkış |

---

Çıktı Örneği

Analiz sonucunda tespit edilen tehditler hem konsola renkli olarak yazdırılır hem de `detected_threats.txt` dosyasına kaydedilir.


  TEHDİT TESPİT EDİLDİ
  Kural   : Brute Force Detection
  Kaynak  : 192.168.1.105
  Mesaj   : 7 başarısız giriş denemesi 60 saniyede tespit edildi


---
<pre>
Sınıf Diyagramı (Özet)


IAlertMechanism (ABC)
    ├── ConsoleAlert
    └── FileAlert

BaseRule (ABC)
    ├── BruteForceRule
    └── PortScanRule


DetectionEngine  ──aggregates──►  BaseRule[]
LogReader        ──produces────►  LogEvent
LogEvent

</pre>
