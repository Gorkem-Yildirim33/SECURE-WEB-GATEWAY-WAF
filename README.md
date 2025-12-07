🛡️ SECURE WEB GATEWAY & WAF

> **Modern web güvenliği standartlarına uygun, Nginx tabanlı Güvenli Web Geçidi ve Web Uygulama Güvenlik Duvarı çözümü.**



Bu proje; güvenli trafik yönlendirme, siber saldırı önleme, erişim yönetimi ve sistem otomasyonu süreçlerini kapsamlı bir mimaride birleştirir. **Alpine tabanlı Docker** mimarisi üzerinde optimize edilmiş bir yapı sunar.

---

## 📋 Proje Özeti ve Temel Yetenekler

Bu çözüm, aşağıdaki temel yetenekler üzerine inşa edilmiştir:

* **Trafik ve Güvenlik Yönetimi:** Nginx Ters Vekil (Reverse Proxy) ile trafik yönetimi.
* **WAF Koruması:** SQL Injection (SQLi) ve XSS (Cross-Site Scripting) saldırı desenlerinin engellenmesi.
* **DDoS Koruması:** Rate Limiting (Hız Sınırlama) ile yoğun trafik saldırılarına karşı direnç (5 req/sec).
* **SSL/TLS Sonlandırma:** Self-signed sertifikalar ile uçtan uca şifreleme ve zorunlu HTTPS yönlendirmesi.
* **Sistem Otomasyonu:** Bash betikleri, `awk`, `sed` araçları ve Systemd/Cron entegrasyonu ile otomatik log analizi ve süreç izleme.
* **Erişim Denetimi:** ACL, SGID ve SSH anahtar tabanlı sıkılaştırılmış güvenlik.

---

## 📂 Proje Yapısı

Proje, modülerlik ilkesine göre yapılandırılmıştır:

```text
.
├── conf/          # Nginx ve WAF konfigürasyon dosyaları
├── scripts/       # Sistem yönetimi ve analiz betikleri (Bash)
├── logs/          # İşlenmiş log dosyaları ve raporlar
├── .gitignore     # Sistem dosyaları ve hassas verilerin hariç tutulması
└── README.md      # Proje dokümantasyonu
🚀 Kurulum ve Mimari
🐳 Docker ile Çalıştırma
Tüm yapı, hafif ve güvenli Alpine Linux tabanlı bir Docker imajı üzerinde çalışır.

Bash

# Projeyi ayağa kaldırmak için:
docker run -d -p 80:80 -p 443:443 --name secure-gateway [IMAJ_ADI]
Komut çalıştırıldığında Nginx, WAF kuralları ve SSL sertifikaları hazır şekilde başlar.

🔐 Erişim ve İzinler (ACL & SGID)
Güvenlik gereği webadmin grubu oluşturulmuş ve /var/www/html dizini üzerinde özel izinler tanımlanmıştır:

ACL (Erişim Kontrol Listeleri): Web içeriğine sadece webadmin grubu yazabilir.

SGID (Set Group ID): Klasörde chmod g+s aktiftir; yeni oluşturulan dosyalar otomatik olarak webadmin grubuna dahil olur.

🛠️ Otomasyon ve Betikler
Proje, scripts/ klasörü altında modüler Bash betikleri içerir. Bu betikler Systemd Timer veya Cron ile periyodik olarak çalışır.

1. Süreç İzleme (scripts/process_monitor.sh)
Süreçleri CPU ve RAM kullanımına göre (çoktan aza) sıralar.

Sistemde asılı kalan "Zombi" (Zombie) süreçleri tespit eder ve raporlar.

2. Log Analiz Pipeline'ı (scripts/log_analyzer.sh)
awk, sed ve grep kullanılarak gelişmiş analiz sunar:

Hassas Veri Temizliği: Regex ile gereksiz bilgiler filtrelenir.

İstatistikler: En çok istek yapan IP'ler ve 4xx/5xx hata türleri sayılarak raporlanır.

Hata Yönetimi: Scriptlerde set -e ve trap kullanılarak güvenli hata yakalama sağlanmıştır.

🛡️ Güvenlik Yapılandırması
🔥 WAF (Web Application Firewall) Kuralları
Layer 7 (Uygulama Katmanı) korumaları:

SQL Injection: URL içinde UNION, SELECT desenleri tespit edilirse engellenir.

XSS: <script> etiketi içeren istekler bloklanır.

Aksiyon: Şüpheli istekler Nginx tarafından 403 Forbidden ile reddedilir.

🔒 SSH Sıkılaştırma
Sunucuya erişim şu kurallarla sınırlandırılmıştır:

PubkeyAuthentication: Sadece SSH anahtarı ile giriş yapılabilir.

PasswordAuthentication: Parola ile giriş kapalıdır (no).

PermitRootLogin: Root kullanıcısının doğrudan girişi engellenmiştir (no).

🔄 Proxy ve SSL
HTTP (Port 80) trafiği otomatik olarak HTTPS (Port 443)'e yönlendirilir (301 Redirect).

Backend sunuculara X-Forwarded-For ve Host başlıkları doğru şekilde iletilir.

⚖️ Lisans
Bu proje MIT Lisansı ile sunulmaktadır.

Gerekçe: Projenin eğitim ve açık kaynak dünyasında özgürce kullanılabilmesi, değiştirilebilmesi ve sorumluluk reddi (liability) koruması sağlaması nedeniyle senaryoya en uygun lisans olarak seçilmiştir.

Hazırlayan: [Adınız Soyadınız]
