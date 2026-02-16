# BOSS Cloaker - PHP/Plesk Sürümü

Bot koruma ve cloaking çözümü - PHP/MySQL/Plesk uyumlu versiyon.

## Özellikler

- 🛡️ **Bot Tespiti**: Google Ads, Facebook, Bing ve diğer platformların botlarını tespit
- 🎯 **Akıllı Yönlendirme**: Gerçek kullanıcıları hedef sayfaya, botları güvenli sayfaya yönlendir
- 📊 **Dashboard**: Ziyaret istatistikleri, bot oranları, gerçek zamanlı loglar
- 🚫 **Blacklist**: IP ve User-Agent bazlı engelleme
- ⚙️ **Gelişmiş Ayarlar**: 
  - Zaman bazlı planlama
  - Rate limiting
  - JS Challenge
  - Cihaz hedefleme (mobil/masaüstü)
  - Yönlendirme modları (302, meta, JS)

## Gereksinimler

- PHP 7.4+
- MySQL 5.7+ / MariaDB 10.3+
- Apache mod_rewrite
- Node.js 18+ (sadece frontend build için)

## Kurulum

### 1. Frontend Build (Windows)

```powershell
cd boss-cloaker-php
.\build-frontend.ps1
```

### 1. Frontend Build (Linux/Mac)

```bash
cd boss-cloaker-php
bash build-frontend.sh
```

### 2. Dosyaları Sunucuya Yükle

`boss-cloaker-php` klasörünün tamamını Plesk sunucunuza yükleyin.

### 3. Kurulum Sihirbazı

Tarayıcıda açın: `https://domain.com/install.php`

- Veritabanı bilgilerini girin
- Admin şifresini belirleyin
- Kurulumu tamamlayın

### 4. Güvenlik

⚠️ **ÖNEMLİ**: Kurulum tamamlandıktan sonra `install.php` dosyasını silin!

```bash
rm install.php
```

## Dosya Yapısı

```
boss-cloaker-php/
├── api/
│   ├── index.php       # Ana API router
│   ├── config.php      # Veritabanı konfigürasyonu
│   ├── storage.php     # Database storage class
│   └── lib/
│       └── detector.php # Bot tespit motoru
├── frontend/           # React frontend kaynak kodları
├── public/             # Build edilmiş frontend (Vite çıktısı)
├── .htaccess           # Apache rewrite kuralları
├── schema.sql          # MySQL veritabanı şeması
├── install.php         # Kurulum sihirbazı
└── README.md
```

## API Endpoint'leri

### Auth
- `POST /api/auth/login` - Giriş yap
- `POST /api/auth/logout` - Çıkış yap
- `GET /api/auth/me` - Mevcut kullanıcı bilgisi

### Domains
- `GET /api/domains` - Tüm domain'leri listele
- `POST /api/domains` - Yeni domain oluştur
- `PUT /api/domains/:id` - Domain güncelle
- `DELETE /api/domains/:id` - Domain sil

### Landing Pages
- `GET /api/landing-pages` - Güvenli sayfaları listele
- `POST /api/landing-pages` - Yeni sayfa oluştur
- `PUT /api/landing-pages/:id` - Sayfa güncelle
- `DELETE /api/landing-pages/:id` - Sayfa sil

### Blacklist
- `GET /api/blacklist/ip` - IP blacklist listele
- `POST /api/blacklist/ip` - IP ekle
- `DELETE /api/blacklist/ip/:id` - IP sil
- `GET /api/blacklist/ua` - UA blacklist listele
- `POST /api/blacklist/ua` - UA pattern ekle
- `DELETE /api/blacklist/ua/:id` - UA pattern sil

### Logs & Stats
- `GET /api/logs` - Access logları
- `GET /api/stats/dashboard` - Dashboard istatistikleri

### Cloaker
- `GET /r/:slug` - Cloaker endpoint (botlar safe page, gerçek kullanıcılar hedef URL)

## Kullanım

1. Admin paneline giriş yapın
2. "Domains" bölümünden yeni bir link oluşturun:
   - Domain adı (ör: "promo1")
   - Hedef URL (gerçek kullanıcıların gideceği sayfa)
   - Landing Page (botların göreceği güvenli sayfa)
   - Tespit seviyesi ve diğer ayarlar
3. Oluşturulan slug'ı kullanın: `https://domain.com/r/abc12345`

## Plesk Özel Ayarları

### SSL Yönlendirmesi
.htaccess dosyasında HTTPS yönlendirmesini aktif etmek için yorum satırını kaldırın:

```apache
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
```

### PHP Ayarları
Plesk panelinden PHP ayarlarını kontrol edin:
- `session.cookie_httponly = 1`
- `session.use_strict_mode = 1`

## Destek

Herhangi bir sorunla karşılaşırsanız:
1. Error loglarını kontrol edin
2. .htaccess dosyasının doğru yüklendiğinden emin olun
3. Veritabanı bağlantısını test edin

## Lisans

Bu proje özel kullanım içindir.
