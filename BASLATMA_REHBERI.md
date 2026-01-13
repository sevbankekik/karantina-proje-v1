# 🚀 Projeyi Başlatma Rehberi

Bu rehber, Dijital Karantina projesini adım adım nasıl çalıştıracağınızı gösterir.

## 📋 Gereksinimler

- Python 3.8 veya üzeri ✅ (venv klasörü mevcut)
- Modern web tarayıcısı (Chrome, Firefox, Edge)

---

## 🔧 Adım 1: Virtual Environment Aktifleştirme

**PowerShell'de proje klasöründe:**

```powershell
.\venv\Scripts\Activate.ps1
```

Eğer execution policy hatası alırsanız:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Sonra tekrar:

```powershell
.\venv\Scripts\Activate.ps1
```

Virtual environment aktif olduğunda, PowerShell prompt'unuzun başında `(venv)` göreceksiniz.

---

## 📦 Adım 2: Backend Paketlerini Yükleme

Virtual environment aktifken:

```powershell
cd backend
pip install -r requirements.txt
```

**Önemli:** Playwright için tarayıcı kurulumu gerekli (URL analizi için):

```powershell
playwright install chromium
```

---

## 🖥️ Adım 3: Backend'i Başlatma

Backend klasöründe:

```powershell
python main.py
```

Veya uvicorn ile doğrudan:

```powershell
uvicorn main:app --host 0.0.0.0 --port 5050 --reload
```

**Başarılı başlatma mesajı:**
```
INFO:     Uvicorn running on http://0.0.0.0:5050
```

Backend artık **http://localhost:5050** adresinde çalışıyor! ✅

---

## 🌐 Adım 4: Frontend'i Başlatma

**YENİ BİR PowerShell penceresi açın** (backend çalışırken):

```powershell
cd frontend
python -m http.server 5500
```

**Başarılı başlatma mesajı:**
```
Serving HTTP on 0.0.0.0 port 5500 (http://0.0.0.0:5500/) ...
```

Frontend artık **http://localhost:5500** adresinde çalışıyor! ✅

---

## ✅ Adım 5: Tarayıcıda Açma

1. Tarayıcınızda şu adresi açın:
   ```
   http://localhost:5500
   ```

2. Dijital Karantina arayüzünü göreceksiniz! 🎉

---

## 🔍 Kontrol Listesi

### Backend Kontrolü
- Tarayıcıda açın: `http://localhost:5050/health`
- Beklenen yanıt: `{"status":"ok"}`

### Frontend Kontrolü
- Tarayıcıda açın: `http://localhost:5500`
- Arayüz görünmeli

---

## 🎯 Kullanım

1. **Fotoğraf Analizi:**
   - "Fotoğraf Analizi" kartında bir görsel seçin
   - "Analizi Başlat" butonuna tıklayın
   - Analiz sonuçlarını görüntüleyin

2. **URL Analizi:**
   - "URL Analizi" kartına bir URL girin
   - "Analizi Başlat" butonuna tıklayın
   - Karantina analiz sonuçlarını görüntüleyin

---

## ⚠️ Sorun Giderme

### Backend başlamıyor
- Virtual environment aktif mi? (`(venv)` görünüyor mu?)
- Paketler yüklü mü? `pip list` ile kontrol edin
- Port 5050 kullanımda mı? Farklı port deneyin: `uvicorn main:app --port 8080`

### Frontend backend'e bağlanamıyor
- Backend çalışıyor mu? `http://localhost:5050/health` kontrol edin
- Tarayıcı konsolunda (F12) hata mesajlarını kontrol edin
- CORS ayarlarını kontrol edin

### Playwright hatası
- `playwright install chromium` komutunu çalıştırdınız mı?
- URL analizi çalışmıyorsa, görsel analizi hala çalışır

---

## 📝 Notlar

- **Backend ve Frontend aynı anda çalışmalıdır!**
- Backend: Port **5050**
- Frontend: Port **5500**
- Frontend, backend'e `http://localhost:5050` adresinden bağlanır

---

**İyi analizler! 🛡️**

