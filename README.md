

# LogGuard – Sunucu Log Analiz ve Anomali Tespit Aracı



LogGuard, Linux sunucularında bulunan SSH log kayıtlarını analiz ederek başarısız giriş denemelerini ve şüpheli IP adreslerini tespit etmek amacıyla geliştirilmiş Python tabanlı bir komut satırı aracıdır.



## Projenin Amacı



Sunuculara yönelik yetkisiz erişim girişimlerinin log kayıtları üzerinden takip edilmesi önemlidir. Ancak log dosyalarının manuel olarak incelenmesi zaman alabilir.



LogGuard, başarısız SSH giriş kayıtlarını filtreleyerek ve bu kayıtları IP adreslerine göre sayarak şüpheli olabilecek kaynakların daha kolay belirlenmesini sağlar.



## Hedef Kullanıcılar



- Linux sunucu yöneticileri

- Sistem ve ağ yönetimiyle ilgilenenler

- Siber güvenlik alanında kendini geliştiren öğrenciler

- Sunucu loglarını incelemek isteyen teknik kullanıcılar



## Projenin Özellikleri



- Log dosyasındaki başarısız SSH girişlerini tespit eder.

- `Failed password` ve `Invalid user` kayıtlarını filtreler.

- Başarısız giriş denemelerini IP adreslerine göre sayar.

- Geçersiz IP adreslerini sonuçlara dahil etmez.

- IPv4 ve IPv6 adreslerini destekler.

- Üç veya daha fazla başarısız giriş yapan IP adreslerini şüpheli olarak işaretler.

- Sonuçları başarısız giriş sayılarına göre sıralayarak ekrana yazdırır.



## Kullanılan Teknolojiler



- Python

- Git ve GitHub

- GitHub Actions

- Python unittest



## Kurulum



Projeyi bilgisayarınıza indirmek için:



```bash

git clone https://github.com/EmineArslnn/logguard.git

cd logguard

```



Python 3 kurulu olmalıdır. Projenin çalışması için harici Python paketi yüklemek gerekmez.



## Kullanım



Örnek log dosyasını analiz etmek için:



```bash

python logguard.py sample.log

```



Program, başarısız giriş kayıtlarını ve IP adreslerine göre giriş sayılarını ekrana yazdırır.



Başarısız giriş sayısı 3 veya daha fazla olan IP adresleri şüpheli olarak işaretlenir.



Kendi log dosyanızı analiz etmek için `sample.log` yerine analiz etmek istediğiniz dosyanın yolunu kullanabilirsiniz.



**Not:** Örnek log dosyasındaki IP adresleri test ve dokümantasyon amacıyla kullanılan adreslerdir.



## Otomatik Testler



Projedeki testleri çalıştırmak için:



```bash

python -m unittest discover -s tests -v

```



Testler aşağıdaki durumları kontrol eder:



- Başarısız girişlerin filtrelenmesi

- IP adreslerinin doğru sayılması

- Şüpheli IP eşiğinin kontrol edilmesi

- Geçersiz IP adreslerinin atlanması

- Boş kayıtların kontrol edilmesi

- Başarısız giriş bulunmadığında boş liste dönmesi

- Eksik IP bilgisinin atlanması

- IPv6 adreslerinin sayılması



Projenin GitHub Actions iş akışı, `main` dalına yapılan push ve pull request işlemlerinde otomatik testleri çalıştırır.



## Proje Yönetimi


GitHub Projects panomuz: [LogGuard Proje Panosu](https://github.com/users/EmineArslnn/projects/2)


## Geliştirici



Emine Arslan



Harran Üniversitesi – Bilgisayar Mühendisliği





