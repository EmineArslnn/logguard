
from pathlib import Path
import sys


def find_failed_logins(file_path):
    """Log dosyasındaki başarısız SSH girişlerini bulur."""

    failed_entries = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            if "Failed password" in line or "Invalid user" in line:
                failed_entries.append(line.strip())

    return failed_entries


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


if __name__ == "__main__":
    main()
