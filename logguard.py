
from pathlib import Path
import ipaddress
import sys


SUSPICIOUS_THRESHOLD = 3


def find_failed_logins(file_path):
    """Log dosyasındaki başarısız SSH girişlerini bulur."""

    failed_entries = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            if "Failed password" in line or "Invalid user" in line:
                failed_entries.append(line.strip())

    return failed_entries


def count_failed_attempts_by_ip(failed_entries):
    """Başarısız girişleri IP adreslerine göre sayar."""

    ip_counts = {}

    for entry in failed_entries:
        parts = entry.split()

        if "from" not in parts:
            continue

        from_index = parts.index("from")

        if from_index + 1 >= len(parts):
            continue

        ip_address = parts[from_index + 1]

        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            continue

        ip_counts[ip_address] = ip_counts.get(ip_address, 0) + 1

    return ip_counts


def main():
    if len(sys.argv) != 2:
        print("Kullanım: python logguard.py sample.log")
        return

    file_path = Path(sys.argv[1])

    try:
        failed_entries = find_failed_logins(file_path)
    except FileNotFoundError:
        print(f"Hata: {file_path} dosyası bulunamadı.")
        return

    print("\n===== LOGGUARD ANALİZ SONUCU =====")
    print(f"Başarısız giriş sayısı: {len(failed_entries)}")
    print("\nBaşarısız giriş kayıtları:")

    for entry in failed_entries:
        print(entry)

    ip_counts = count_failed_attempts_by_ip(failed_entries)

    print("\nIP ADRESLERİNE GÖRE BAŞARISIZ GİRİŞLER")
    print(f"Şüpheli IP eşiği: {SUSPICIOUS_THRESHOLD}")

    if not ip_counts:
        print("IP adresi bulunamadı.")
    else:
        for ip_address, count in sorted(
            ip_counts.items(),
            key=lambda item: (-item[1], item[0])
        ):
            status = (
                "ŞÜPHELİ"
                if count >= SUSPICIOUS_THRESHOLD
                else "Normal"
            )

            print(
                f"{ip_address} -> "
                f"{count} başarısız giriş | {status}"
            )


if __name__ == "__main__":
    main()
