# Dijital Karantina Projesi

Bu proje, şüpheli dosyaları, URL'leri ve görselleri güvenli bir şekilde analiz eden bir dijital karantina sistemidir.

## 🚀 Projeyi Çalıştırma

### 📋 Gereksinimler

- Python 3.8 veya üzeri
- Modern bir web tarayıcısı (Chrome, Firefox, Edge vb.)

---

## 🔧 Backend Kurulumu ve Çalıştırma

### Adım 1: Virtual Environment Aktifleştirme

Windows PowerShell'de:

```powershell
.\venv\Scripts\Activate.ps1
```

Eğer PowerShell execution policy hatası alırsanız:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Adım 2: Gerekli Paketleri Yükleme

Virtual environment aktifken:

```powershell
cd backend
pip install -r requirements.txt
```

### Adım 3: Backend'i Çalıştırma

Backend klasöründe:

```powershell
python main.py
```

Veya uvicorn ile doğrudan:

```powershell
uvicorn main:app --host 0.0.0.0 --port 5050 --reload
```

Backend başarıyla çalıştığında şu mesajı göreceksiniz:
```
INFO:     Uvicorn running on http://0.0.0.0:5050
```

**Backend artık http://localhost:5050 adresinde çalışıyor!**

---

## 🌐 Frontend Çalıştırma

Frontend, basit HTML/JS/CSS dosyalarından oluşuyor. Birkaç yöntemle çalıştırabilirsiniz:

### Yöntem 1: Python HTTP Sunucusu (Önerilen)

**Yeni bir terminal/PowerShell penceresi açın** ve frontend klasörüne gidin:

```powershell
cd frontend
python -m http.server 5500
```

Frontend artık http://localhost:5500 adresinde çalışıyor!

### Yöntem 2: VS Code Live Server

1. VS Code'da `frontend` klasörünü açın
2. `index.html` dosyasına sağ tıklayın
3. "Open with Live Server" seçeneğini seçin

### Yöntem 3: Doğrudan Dosya Açma

`frontend/index.html` dosyasına çift tıklayarak tarayıcıda açabilirsiniz. Ancak bu yöntemde bazı JavaScript özellikleri çalışmayabilir.

---

## ✅ Çalıştığını Kontrol Etme

1. **Backend kontrolü**: Tarayıcıda şu adresi açın:
   ```
   http://localhost:5050/health
   ```
   `{"status":"ok"}` yanıtını görmelisiniz.

2. **Frontend kontrolü**: Tarayıcıda şu adresi açın:
   ```
   http://localhost:5500
   ```
   Dijital Karantina arayüzünü görmelisiniz.

---

## 📝 Önemli Notlar

- **Backend ve Frontend aynı anda çalışmalıdır!**
- Backend **5050** portunda çalışır
- Frontend **5500** portunda çalışır (veya farklı bir port seçebilirsiniz)
- Frontend, backend'e `http://localhost:5050` adresinden bağlanır
- Backend CORS ayarları `localhost:5500` ve `localhost:5050` portlarını destekler

---

## 🔍 Kullanım

1. Her iki sunucuyu da başlatın (Backend ve Frontend)
2. Tarayıcıda frontend adresini açın (örn: http://localhost:5500)
3. "Fotoğraf Analizi" kartında bir görsel seçin
4. "Analizi Başlat" butonuna tıklayın
5. Analiz sonuçlarını görüntüleyin

---

## 🛠️ Sorun Giderme

### Backend başlamıyor

- Virtual environment aktif mi kontrol edin
- Gerekli paketler yüklü mü kontrol edin: `pip list`
- Port 5050 kullanımda mı kontrol edin

### Frontend backend'e bağlanamıyor

- Backend çalışıyor mu kontrol edin: http://localhost:5050/health
- Tarayıcı konsolunda (F12) hata mesajlarını kontrol edin
- CORS ayarlarını kontrol edin

### Port zaten kullanımda hatası

- Farklı portlar kullanabilirsiniz
- Backend için: `uvicorn main:app --port 8080`
- Frontend için: `python -m http.server 8081`
- Frontend'deki `API_BASE_URL` değerini güncelleyin


