# SSL Certificate Checker

## Overview (English)
This tool is designed to check SSL certificates of websites and gather various security-related information regarding the certificate. It provides details such as certificate issuer, validity period, and potential vulnerabilities. Additionally, the tool performs checks on the domain's DNS and HTTP security headers to identify potential security risks.

### Features:
- **Certificate Details**: Extracts and prints details such as the issuer, subject, validity period, and public key information of the SSL certificate.
- **Expiration Alarm**: Alerts when the SSL certificate is about to expire within 30 days.
- **Vulnerability Checks**: Identifies weak signature algorithms, such as MD5 and SHA-1, and checks for other vulnerabilities like POODLE.
- **DNS and Security Headers Check**: Retrieves information about name servers, DNSSEC, CAA records, SPF, and DMARC settings.
- **OCSP and CRL**: Verifies if the certificate supports OCSP and CRL for certificate revocation checks.
- **Key Length Check**: Ensures the RSA key length is at least 2048 bits.
- **TLS Version and Cipher Suite Check**: Checks if the TLS version is secure and identifies the usage of weak cipher suites.
- **HTTP Security Headers**: Checks for the presence of important HTTP security headers like HSTS, CSP, X-Frame-Options, etc.
- **Forward Secrecy Check**: Ensures the server uses Forward Secrecy by checking for ECDHE cipher suites.

### How to Run
1. **Install Go**: Ensure that you have Go installed on your system.
2. **Clone the Repository**: Clone the repository containing this tool.
3. **Run the Code**: In your terminal, navigate to the directory containing the `SslCertificateChecker.go` file and run:
   ```
   go run SslCertificateChecker.go
   ```
4. **Input the Domain**: When prompted, enter the domain name you want to check (e.g., `example.com`). The tool will automatically append `https://` to the domain.

### Example Output
After entering the domain, the tool will output detailed information about the SSL certificate, including:
- **Certificate Issuer and Subject**
- **Validity Period**
- **DNS Records and Security Headers**
- **Potential Vulnerabilities**

## Genel Bakış (Türkçe)
Bu araç, web sitelerinin SSL sertifikalarını kontrol etmek ve sertifikayla ilgili çeşitli güvenlik bilgilerini toplamak için tasarlanmıştır. Sertifika sağlayıcısı, geçerlilik süresi ve olası güvenlik açıkları gibi bilgileri sağlar. Ayrıca, alan adının DNS ve HTTP güvenlik başlıklarını kontrol ederek potansiyel güvenlik risklerini belirler.

### Özellikler:
- **Sertifika Detayları**: SSL sertifikasının sağlayıcısı, sahibi, geçerlilik süresi ve genel anahtar bilgilerini çıkarır ve yazdırır.
- **Son Kullanım Uyarısı**: SSL sertifikasının 30 gün içinde sona ereceği durumlarda uyarı verir.
- **Zafiyet Kontrolleri**: MD5 ve SHA-1 gibi zayıf imza algoritmalarını belirler ve POODLE gibi diğer zafiyetleri kontrol eder.
- **DNS ve Güvenlik Başlıkları Kontrolü**: Name server bilgileri, DNSSEC, CAA kayıtları, SPF ve DMARC ayarlarını kontrol eder.
- **OCSP ve CRL**: Sertifikanın iptal durumu için OCSP ve CRL destekleyip desteklemediğini doğrular.
- **Anahtar Uzunluğu Kontrolü**: RSA anahtar uzunluğunun en az 2048 bit olduğundan emin olur.
- **TLS Sürüm ve Şifreleme Paketi Kontrolü**: Güvenli TLS sürümü kullanılıp kullanılmadığını ve zayıf şifreleme paketlerinin kullanımını belirler.
- **HTTP Güvenlik Başlıkları**: HSTS, CSP, X-Frame-Options gibi önemli HTTP güvenlik başlıklarının mevcut olup olmadığını kontrol eder.
- **İleri Gizlilik Kontrolü**: Sunucunun İleri Gizlilik kullanıp kullanmadığını ECDHE şifreleme paketlerini kontrol ederek doğrular.

### Nasıl Çalıştırılır
1. **Go'yu Yükleyin**: Sisteminizde Go'nun kurulu olduğundan emin olun.
2. **Depoyu Klonlayın**: Bu aracı içeren depoyu klonlayın.
3. **Kodu Çalıştırın**: Terminalinizde `SslCertificateChecker.go` dosyasının bulunduğu dizine gidin ve şu komutu çalıştırın:
   ```
   go run SslCertificateChecker.go
   ```
4. **Alan Adını Girin**: İstendiğinde kontrol etmek istediğiniz alan adını girin (örn: `example.com`). Araç, otomatik olarak `https://` ekleyecektir.

### Örnek Çıktı
Alan adını girdikten sonra araç, SSL sertifikası hakkında detaylı bilgi verir, bunlar şunları içerir:
- **Sertifika Sağlayıcısı ve Sahibi**
- **Geçerlilik Süresi**
- **DNS Kayıtları ve Güvenlik Başlıkları**
- **Potansiyel Güvenlik Açıkları**

