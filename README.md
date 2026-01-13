Dijital Karantina (Digital Quarantine)
Dijital Karantina, şüpheli URL’leri, web içeriklerini ve dosyaları izole bir ortamda derinlemesine analiz etmek amacıyla geliştirilmiş, çok katmanlı bir siber güvenlik analiz platformudur. Bu proje; potansiyel tehditlerin kullanıcı sistemine ulaşmadan, güvenli bir "sandbox" (kum havuzu) içerisinde davranışsal, içerik bazlı ve görsel olarak incelenmesini sağlar.

🎯 Projenin Amacı
İzole Analiz: Şüpheli yapıları yerel sisteme zarar vermeyecek bir karantina ortamında çalıştırmak.

Görsel ve Dosya Denetimi: Sadece URL değil, dosya yapısı ve sayfa görünümü üzerinden zararlı faaliyet tespiti yapmak.

Erken Teşhis: Kimlik avı (phishing) ve malware dağıtan içerikleri erken aşamada belirlemek.

Eğitim Altyapısı: Siber güvenlik öğrencileri ve meraklıları için güvenli bir pratik sahası oluşturmak.

🔍 Temel Özellikler
🌐 URL & Web Karantinası: Şüpheli linklerin headless tarayıcılar üzerinden güvenli izolasyonu.

🖼️ Görsel Analiz: Sayfa ekran görüntüleri ve DOM yapısı üzerinden görsel inceleme (Phishing tespiti için).

📂 Dosya Analiz Modülü: Şüpheli dosyaların içeriğini ve davranışlarını izole ortamda tarama.

👁️ Davranışsal Gözlem: Web sayfalarının arka planda yürüttüğü scriptlerin ve yönlendirmelerin takibi.

🖥️ Kullanıcı Dostu Arayüz: Analiz süreçlerini yönetmeyi ve raporları izlemeyi kolaylaştıran modern Frontend paneli.

🧠 Kullanım Senaryoları
Siber Güvenlik Eğitimi: Öğrencilerin zararlı yazılım davranışlarını canlı ve güvenli bir ortamda gözlemlemesi.

Olay Müdahale (Incident Response): Şüpheli link veya dosyaların manuel/otomatik ilk incelemesinin yapılması.

Güvenlik Simülasyonları: Kurumsal eğitimlerde zararlı içeriklerin nasıl çalıştığının demo edilmesi.

🧰 Kullanılan Teknolojiler
Proje, hem arka uçta güçlü bir analiz motoru hem de ön uçta kullanıcı etkileşimini sağlayan modern bir teknoloji yığını üzerine inşa edilmiştir:

Backend: Python (Analiz motoru ve mantıksal katman)

Tarayıcı Otomasyonu: Playwright / Headless Chromium (İzole web inceleme)

Frontend: HTML5, CSS3 ve JavaScript (Kullanıcı arayüzü ve veri görselleştirme)

Analiz Araçları: Görsel işleme ve dosya imza kontrol kütüphaneleri.

🚀 Gelecek Vizyonu
Proje, modüler yapısı sayesinde yeni nesil yapay zeka tabanlı tehdit algılama modellerinin entegre edilmesine ve daha geniş çaplı ağ trafiği analizlerine olanak tanıyacak şekilde geliştirilmeye devam etmektedir.
