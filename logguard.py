
from pathlib import Path
import ipaddress
import sys


# Supheli saymak icin gereken basarisiz giris sayisini burada belirliyoruz.
SUSPICIOUS_THRESHOLD = 3


def find_failed_logins(file_path):
    """Log dosyasındaki başarısız SSH girişlerini bulur."""

    # Başarısız giriş kayıtlarını burada biriktiriyoruz.
    failed_entries = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            # Sadece başarısız giriş olduğunu gösteren kayıtları alıyoruz.
            if "Failed password" in line or "Invalid user" in line:
                failed_entries.append(line.strip())

    return failed_entries


def count_failed_attempts_by_ip(failed_entries):
    """Başarısız girişleri IP adreslerine göre sayar."""

    # Her IP adresinin kaç kez denendiğini burada tutuyoruz.
    ip_counts = {}

    for entry in failed_entries:
        # Kaydı parçalara ayırıp IP bilgisini bulmaya çalışıyoruz.
        parts = entry.split()

        # "from" bilgisi yoksa bu kaydı saymıyoruz.
        if "from" not in parts:
            continue

        from_index = parts.index("from")

        # "from" kelimesinden sonra bir bilgi yoksa kaydı atlıyoruz.
        if from_index + 1 >= len(parts):
            continue

        ip_address = parts[from_index + 1]

        try:
            # Gelen bilginin geçerli bir IP adresi olup olmadığını kontrol ediyoruz.
            ipaddress.ip_address(ip_address)
        except ValueError:
            # IP adresi geçersizse bu kaydı saymıyoruz.
            continue

        # Aynı IP tekrar geldiyse sayısını bir artırıyoruz.
        ip_counts[ip_address] = ip_counts.get(ip_address, 0) + 1

    return ip_counts


def main():
    # Program çalışırken log dosyasının yolunun verilmesini bekliyoruz.
    if len(sys.argv) != 2:
        print("Kullanım: python logguard.py sample.log")
        return

    # Komut satırından gelen dosya yolunu alıyoruz.
    file_path = Path(sys.argv[1])

    try:
        failed_entries = find_failed_logins(file_path)
    except FileNotFoundError:
        # Dosya bulunamazsa hata verip programı durduruyoruz.
        print(f"Hata: {file_path} dosyası bulunamadı.")
        return

    print("\n===== LOGGUARD ANALİZ SONUCU =====")
    print(f"Başarısız giriş sayısı: {len(failed_entries)}")
    print("\nBaşarısız giriş kayıtları:")

    # Bulduğumuz başarısız girişleri ekrana yazdırıyoruz.
    for entry in failed_entries:
        print(entry)

    # Başarısız girişleri IP adreslerine göre sayıyoruz.
    ip_counts = count_failed_attempts_by_ip(failed_entries)

    print("\nIP ADRESLERİNE GÖRE BAŞARISIZ GİRİŞLER")
    print(f"Şüpheli IP eşiği: {SUSPICIOUS_THRESHOLD}")

    if not ip_counts:
        print("IP adresi bulunamadı.")
    else:
        # En fazla başarısız giriş yapan IP adreslerini üstte gösteriyoruz.
        for ip_address, count in sorted(
            ip_counts.items(),
            key=lambda item: (-item[1], item[0])
        ):
            # Belirlediğimiz eşiğe ulaşan IP adresini şüpheli işaretliyoruz.
            status = (
                "ŞÜPHELİ"
                if count >= SUSPICIOUS_THRESHOLD
                else "Normal"
            )

            print(
                f"{ip_address} -> "
                f"{count} başarısız giriş | {status}"
            )


# Dosya doğrudan çalıştırıldığında main fonksiyonunu başlatıyoruz.
if __name__ == "__main__":
    main()
