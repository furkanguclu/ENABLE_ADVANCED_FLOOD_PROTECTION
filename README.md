# Advanced Flood Protection System

Bu sistem, Metin2 sunucularında **bağlantı fazlalığına (flood)** karşı temel bir savunma sağlar. Ani giriş saldırılarına karşı kanalların otomatik kapanmasını engellemek ve sunucunun istikrarını korumak amacıyla geliştirilmiştir.

## 🚀 Özellikler

- **IP Bazlı Giriş Takibi**  
  Her IP adresi için yapılan bağlantı denemeleri kayıt altına alınır.

- **Zaman Aşımı Tabanlı Sayaç**  
  Giriş denemeleri saniyelik olarak izlenir ve sınırı aşan IP’ler kısa süreli engellenir.

- **Sunucu Stabilitesi Koruması**  
  Aşırı yük durumunda kanalların yanlışlıkla "kapalı" görünmesinin önüne geçer.

## 🛠️ Aktif Etme

Bu sistemi aktif etmek için `CommonDefines.h` içerisine aşağıdaki satırı ekleyin:

```cpp
#define ENABLE_ADVANCED_FLOOD_PROTECTION
```

## 🔐 Nasıl Çalışır?

- `input_login.cpp` ve `input_auth.cpp` içinde login işlemi sırasında her IP adresi için saniyelik deneme sayısı tutulur.
- Eğer bir IP adresi 1 saniyede 5’ten fazla deneme yaparsa, sistem bu IP'yi geçici olarak engeller.
- Bu işlem, hem `auth` hem de `game` sunucusunda aktif çalışır.
- Kanal kapalı görünme sorunu, saldırı geçince kendiliğinden düzelir.

## 📁 Düzenlenen Dosyalar

- `input_login.cpp`
- `input_auth.cpp`
- `desc_manager.cpp`
- `desc_manager.h`
- `CommonDefines.h`

## ⚠️ Uyarı

Bu sistem yalnızca saldırıya karşı temel koruma sağlar. Daha gelişmiş güvenlik ihtiyaçları için ek proxy/firewall çözümleriyle birlikte kullanılması önerilir.

---

Proje katkılarınız ve geri bildirimleriniz için teşekkürler.
