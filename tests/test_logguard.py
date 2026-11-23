import sys
import tempfile
import unittest
from pathlib import Path


# Lazim olan modulleri buraya aliyoruz.

# Ana proje klasorunun yolunu buluyoruz.
proje_yolu = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(proje_yolu))


# Kendi yazdigimiz fonksiyonlari testlerde kullanacagiz.
from logguard import (
    find_failed_logins,
    count_failed_attempts_by_ip,
    SUSPICIOUS_THRESHOLD
)


class TestLogGuard(unittest.TestCase):

    def setUp(self):
        # Her test icin ayri bir gecici dosya olusturuyoruz.
        self.gecici_klasor = tempfile.TemporaryDirectory()
        self.log_yolu = Path(self.gecici_klasor.name) / "test.log"

    def tearDown(self):
        # Test bitince olusturdugumuz gecici dosyayi siliyoruz.
        self.gecici_klasor.cleanup()

    def test_basarisiz_girisleri_filtrele(self):

        # Test etmek icin ornek giris kayitlari hazirliyoruz.
        self.log_yolu.write_text(
            "Failed password for root from 192.0.2.10 port 22 ssh2\n"
            "Invalid user guest from 203.0.113.25 port 23\n"
            "Accepted password for admin from 192.0.2.20 port 24 ssh2\n",
            encoding="utf-8"
        )

        # Log dosyasindaki basarisiz girisleri buluyoruz.
        kayitlar = find_failed_logins(self.log_yolu)

        # Iki basarisiz kayit bulmasi gerekiyor.
        self.assertEqual(len(kayitlar), 2)

        # Basarili giris sonuc listesinde olmamali.
        self.assertTrue(
            all("Accepted password" not in satir for satir in kayitlar)
        )

    def test_ip_sayimi(self):

        # Ayni IP'den gelen birden fazla giris hazirliyoruz.
        kayitlar = [
            "Failed password for root from 192.0.2.10 port 22 ssh2",
            "Failed password for admin from 192.0.2.10 port 23 ssh2",
            "Failed password for test from 192.0.2.10 port 24 ssh2",
            "Failed password for user from 198.51.100.7 port 25 ssh2"
        ]

        # IP adreslerine gore kac giris yapildigini sayiyoruz.
        sonuc = count_failed_attempts_by_ip(kayitlar)

        # Ilk IP 3, ikinci IP ise 1 kez gelmis olmali.
        self.assertEqual(sonuc["192.0.2.10"], 3)
        self.assertEqual(sonuc["198.51.100.7"], 1)

    def test_supheli_ip_esigi(self):

        # Burada uc ve bir giris yapan iki IP kullaniyoruz.
        kayitlar = [
            "Failed password for root from 192.0.2.10 port 22 ssh2",
            "Failed password for admin from 192.0.2.10 port 23 ssh2",
            "Failed password for test from 192.0.2.10 port 24 ssh2",
            "Failed password for user from 198.51.100.7 port 25 ssh2"
        ]

        sonuc = count_failed_attempts_by_ip(kayitlar)

        # Uc deneme yapan IP supheli esigine ulasmis olmali.
        self.assertEqual(
            sonuc["192.0.2.10"],
            SUSPICIOUS_THRESHOLD
        )

        # Bir deneme yapan IP ise esigin altinda kalmali.
        self.assertLess(
            sonuc["198.51.100.7"],
            SUSPICIOUS_THRESHOLD
        )

    def test_gecersiz_ipyi_atla(self):

        # Gecersiz ve gecerli bir IP adresini birlikte kontrol ediyoruz.
        kayitlar = [
            "Failed password for root from invalid-ip port 22 ssh2",
            "Failed password for admin from 192.0.2.10 port 22 ssh2"
        ]

        sonuc = count_failed_attempts_by_ip(kayitlar)

        # Gecersiz IP atlanmali, gecerli IP ise sayilmali.
        self.assertEqual(sonuc, {"192.0.2.10": 1})

    def test_bos_kayitlar(self):

        # Hic kayit olmadiginda bos sonuc donmesini bekliyoruz.
        sonuc = count_failed_attempts_by_ip([])

        self.assertEqual(sonuc, {})

    def test_basarisiz_giris_yoksa_bos_liste_don(self):

        # Basarili giris ve normal bir log kaydi hazirliyoruz.
        self.log_yolu.write_text(
            "Accepted password for admin from 192.0.2.20 port 22 ssh2\n"
            "System started successfully\n",
            encoding="utf-8"
        )

        # Basarisiz giris bulunmadigi icin bos liste donmeli.
        kayitlar = find_failed_logins(self.log_yolu)

        self.assertEqual(kayitlar, [])

    def test_from_bilgisi_olmayan_kaydi_atla(self):

        # Bazi kayitlarda IP bilgisi eksik veya hic bulunmuyor.
        kayitlar = [
            "Failed password for root port 22 ssh2",
            "Failed password for admin from",
            "Failed password for user from 192.0.2.10 port 22 ssh2"
        ]

        sonuc = count_failed_attempts_by_ip(kayitlar)

        # Eksik bilgiler atlanmali, gecerli IP sayilmis olmali.
        self.assertEqual(sonuc, {"192.0.2.10": 1})

    def test_ipv6_adresini_say(self):

        # Gecerli bir IPv6 adresinden gelen girisleri hazirliyoruz.
        kayitlar = [
            "Failed password for root from 2001:db8::1 port 22 ssh2",
            "Invalid user guest from 2001:db8::1 port 23"
        ]

        sonuc = count_failed_attempts_by_ip(kayitlar)

        # Ayni IPv6 adresinden iki giris gelmis olmali.
        self.assertEqual(sonuc["2001:db8::1"], 2)


# Dosya calistirilinca testleri baslatiyoruz.
if __name__ == "__main__":
    unittest.main()