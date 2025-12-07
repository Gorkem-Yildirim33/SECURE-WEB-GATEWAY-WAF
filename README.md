📄 PROJE 1: SECURE WEB GATEWAY & WAF
🛡️ Proje Özeti: Secure Web Gateway & WAF Bu proje, modern web güvenliği standartlarına uygun, Nginx tabanlı bir Güvenli Web Geçidi (Secure Web Gateway) ve Web Uygulama Güvenlik Duvarı (WAF) çözümüdür. Sistem; güvenli trafik yönlendirme, siber saldırı önleme, erişim yönetimi ve sistem otomasyonu süreçlerini kapsamlı bir mimaride birleştirir. Proje, aşağıdaki temel yetenekler üzerine inşa edilmiştir: Trafik ve Güvenlik Yönetimi: Nginx Ters Vekil (Reverse Proxy) sunucusu üzerinden gelen trafik yönetilirken, SQL Injection (SQLi) ve XSS saldırı desenleri WAF kuralları ile engellenir. Ayrıca Rate Limiting (Hız Sınırlama) ile DDoS saldırılarına karşı direnç sağlanır . SSL/TLS Sonlandırma: Self-signed sertifikalar ile uçtan uca şifreleme sağlanır ve tüm HTTP trafiği zorunlu olarak HTTPS protokolüne yönlendirilir . Sistem Otomasyonu ve İzleme: Bash betikleri, awk ve sed araçları kullanılarak sunucu loglarını analiz eder, 4xx/5xx hatalarını raporlar ve kaynak tüketen (zombi) süreçleri tespit eder. Bu işlemler Systemd ve Cron/Timer yapılarıyla tam otomatize edilmiştir . Erişim Denetimi (ACL & SSH): Sunucu erişimi sadece SSH anahtarları ile sınırlandırılmış; dosya sistemi üzerinde ACL (Erişim Kontrol Listeleri) ve SGID bitleri kullanılarak webadmin grubu için güvenli bir yetkilendirme mimarisi kurulmuştur .
Konteyner Mimarisi: Tüm yapı, optimize edilmiş (Alpine tabanlı) bir Docker imajı üzerinde taşınabilir ve izole bir şekilde çalıştırılmaktadır .
1️⃣ BÖLÜM 1: Kimlik İnşası, Sürümleme ve Erişim Yönetimi (Bu bölüm Git yapısı, Lisans ve Dosya İzinleri kapsar.)
📂 Klasör Yapısı ve Git Düzeni Proje, modülerlik ilkesine göre şu şekilde yapılandırılmıştır :
conf/: Nginx ve WAF konfigürasyon dosyaları.
scripts/: Sistem yönetimi ve analiz betikleri.
logs/: İşlenmiş log dosyaları.
.gitignore: Gereksiz sistem dosyaları ve hassas veriler hariç tutulmuştur .
⚖️ Lisans ve Gerekçesi Bu proje MIT Lisansı ile sunulmaktadır.
Gerekçe: Projenin eğitim ve açık kaynak dünyasında özgürce kullanılabilmesi, değiştirilebilmesi ve sorumluluk reddi (liability) koruması sağlaması nedeniyle, senaryoya en uygun lisans olarak MIT seçilmiştir .
🔐 Kullanıcı ve Grup İzinleri (ACL & SGID) Güvenlik gereği webadmin grubu oluşturulmuş ve web dizinine (/var/www/html) şu özel izinler uygulanmıştır :
ACL (Erişim Kontrol Listeleri): Web içeriğine sadece webadmin grubu yazabilir, diğer kullanıcılar sadece okuyabilir.
SGID (Set Group ID): Klasör üzerinde chmod g+s biti aktiftir. Bu sayede dizin içinde oluşturulan her yeni dosya otomatik olarak webadmin grubuna dahil olur .
2️⃣ BÖLÜM 2: Metin İşleme ve Log Analizi (Bu bölüm Process takibi ve Regex/Pipeline kapsar)
📊 Süreç (Process) Yönetimi scripts/process_monitor.sh betiği şunları yapar:
Süreçleri CPU ve RAM kullanımına göre çoktan aza sıralar .
Sistemde asılı kalan "Zombi" (Zombie) süreçleri tespit eder ve rapora ekler .
📝 Log Analiz Pipeline'ı scripts/log_analyzer.sh betiği, awk, sed ve grep araçlarını kullanarak gelişmiş bir analiz sunar :
Hassas Veri Temizliği: Regex kullanılarak loglardaki gereksiz bilgiler filtrelenir.
İstatistikler: En çok istek yapan IP adresleri ve 4xx/5xx hata türleri gruplandırılarak sayılır (count/sort) .
3️⃣ BÖLÜM 3: Servis ve Vekil Sunucu Yapılandırması (Bu bölüm Nginx Proxy, SSL ve Systemd kapsar)
🔄 Reverse Proxy ve SSL SSL/TLS: Self-signed sertifika oluşturulmuş ve HTTPS (Port 443) aktiftir .
Zorunlu Yönlendirme: HTTP (80) üzerinden gelen tüm istekler otomatik olarak HTTPS'e yönlendirilir (Redirect) .
Header İletimi: X-Forwarded-For ve Host başlıkları backend sunucuya doğru şekilde iletilir .
⚙️ Systemd Servis Yönetimi Nginx servisi, çökme durumlarına karşı dayanıklı hale getirilmiştir:
Otomatik Başlatma: Servis dosyasında Restart=on-failure ayarı yapılarak, hata durumunda servisin kendi kendine yeniden başlaması sağlanmıştır .
Logrotate: Log dosyaları günlük olarak döndürülür (rotate) ve sıkıştırılarak (compress) saklanır .
4️⃣ BÖLÜM 4: Otomasyon ve Betikleme (Bu bölüm Bash, SSH ve Cron kapsar)
🛡️ Güvenli SSH Erişimi Sunucu erişimi sıkılaştırılmıştır :
Anahtarlı Giriş: Sadece SSH anahtarı (PubkeyAuthentication) ile girişe izin verilir.
Parola Kapatma: Parola ile giriş (PasswordAuthentication no) ve root kullanıcısının doğrudan girişi (PermitRootLogin no) kapatılmıştır .
⏰ Otomasyon ve Hata Yakalama Bash betikleri modüler yapıda yazılmıştır:
Hata Yönetimi: Scriptlerde set -e ve trap kullanılarak hata durumunda işlemlerin güvenli durdurulması sağlanmıştır .
Zamanlama: Analiz scriptleri Systemd Timer (veya Cron) ile entegre edilmiş, periyodik olarak otomatik çalışmaktadır .
5️⃣ BÖLÜM 5: Güvenlik Duvarı ve WAF (Bu bölüm Rate Limiting ve Docker kapsar)
🧱 WAF ve Rate Limiting Uygulama katmanında (Layer 7) şu korumalar aktiftir:
Hız Sınırlama: Bir IP adresinden saniyede en fazla 5 istek kabul edilir (rate limiting), fazlası reddedilir .
Saldırı Engelleme: URL içinde UNION, SELECT (SQL Injection) veya <script> (XSS) desenleri tespit edilirse Nginx isteği 403 Forbidden ile bloklar .
🐳 Docker Mimarisi Proje konteynerize edilmiştir:
Optimizasyon: İmaj boyutu küçük tutulmak için Alpine tabanlı imaj kullanılmıştır .
Hazır Kurulum: docker run komutu ile Nginx, WAF kuralları ve SSL sertifikaları hazır şekilde ayağa kalkar.
Hazırlayan: [Adınız Soyadınız]
