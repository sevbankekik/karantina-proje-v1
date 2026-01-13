# Test Rehberi - Görsel Analiz Sistemi

Bu rehber, görsel analiz sisteminde farklı tehditlerin nasıl tespit edildiğini ve test için nasıl test dosyaları oluşturulacağını açıklar.

---

## 🔴 1. Append-Data Malware (En Kolay Test)

### Nasıl Tespit Edilir?
JPEG dosyasının sonundaki `\xff\xd9` (EOI marker) imzasından sonra ekstra veri olup olmadığına bakılır.

### Test Dosyası Nasıl Oluşturulur?

**Windows (CMD):**
```cmd
copy /b normal_resim.jpg + test_metni.txt test_resim.jpg
```

**Python Script:**
```python
# test_append_data.py
with open('normal_resim.jpg', 'rb') as f:
    jpeg_data = f.read()

# JPEG sonuna metin ekle
append_text = b"\nGIZLI VERI: Bu bir test metnidir!"
new_file = jpeg_data + append_text

with open('test_append.jpg', 'wb') as f:
    f.write(new_file)
```

**Manuel (Hex Editor):**
1. Herhangi bir JPEG dosyasını hex editor ile aç
2. Dosyanın sonuna git
3. `FF D9` (JPEG bitiş imzası) bul
4. Bu imzadan sonra herhangi bir veri ekle (örn: "TEST123")
5. Kaydet

**Sonuç:** Sistem `\xff\xd9` sonrasındaki veriyi tespit eder ve "Append-Data Malware" olarak işaretler.

---

## 🟠 2. Trojan Şüphesi

### Nasıl Tespit Edilir?
Dosya içinde şu pattern'ler aranır:
- **PE Executable**: `50 45 00 00` (PE\0\0) - Windows .exe imzası
- **ELF Executable**: `7F 45 4C 46` (ELF) - Linux executable imzası
- **Script Pattern'leri**: PowerShell, Batch, Python, Shell, JavaScript kod parçacıkları

### Test Dosyası Nasıl Oluşturulur?

**Yöntem 1: Hex Editor ile PE İmzası Ekleme**
```python
# test_trojan_pe.py
with open('normal_resim.jpg', 'rb') as f:
    img_data = f.read()

# Dosyanın ortasına PE imzası ekle (test amaçlı)
# PE imzası: 50 45 00 00
pe_signature = b'PE\x00\x00\x00\x00\x00\x00\x00'
# İmzayı dosyanın ortasına ekle
insert_pos = len(img_data) // 2
new_data = img_data[:insert_pos] + pe_signature + b'FAKE_EXECUTABLE_DATA' + img_data[insert_pos:]

with open('test_trojan.jpg', 'wb') as f:
    f.write(new_data)
```

**Yöntem 2: Script Pattern Ekleme**
```python
# test_trojan_script.py
with open('normal_resim.jpg', 'rb') as f:
    img_data = f.read()

# PowerShell script pattern'i ekle
script_text = b'powershell -Command "Write-Host Test"'
# Dosyanın ortasına ekle
insert_pos = len(img_data) // 2
new_data = img_data[:insert_pos] + script_text + img_data[insert_pos:]

with open('test_script.jpg', 'wb') as f:
    f.write(new_data)
```

**Sonuç:** Sistem PE/ELF imzalarını veya script pattern'lerini tespit eder.

---

## 🟡 3. Steganografi Şüphesi

### Nasıl Tespit Edilir?
3 farklı yöntemle kontrol edilir:

1. **LSB (Least Significant Bit) Analizi**: 
   - Piksel değerlerinin en düşük bitlerindeki dağılım anormalse (normalde %50-50 olmalı)
   - Eğer %30'dan az veya %70'ten fazla 0/1 varsa şüpheli

2. **Dosya Boyutu Anomalisi**:
   - Beklenen dosya boyutundan %50'den fazla büyükse şüpheli
   - Formül: `beklenen_boyut = (width × height × 3) × 0.15`
   - Gerçek boyut > beklenen_boyut × 1.5 ise şüpheli

3. **Entropi Analizi**:
   - Piksel değerlerinin çeşitliliği çok azsa (10'dan az farklı değer) şüpheli

### Test Dosyası Nasıl Oluşturulur?

**Yöntem 1: Büyük Dosya Boyutu (En Kolay)**
```python
# test_stego_large.py
from PIL import Image
import numpy as np

# Küçük bir görsel oluştur (100x100 piksel)
img = Image.new('RGB', (100, 100), color='red')
img.save('small_image.png')

# Aynı görseli çok yüksek kalitede (düşük sıkıştırma) kaydet
# Bu, dosya boyutunu anormal büyük yapar
img.save('test_stego.jpg', quality=100, optimize=False)
# Dosya boyutu beklenenden çok daha büyük olacak
```

**Yöntem 2: LSB Manipülasyonu (Gelişmiş)**
```python
# test_stego_lsb.py
from PIL import Image
import numpy as np

# Basit bir görsel oluştur
img = Image.new('RGB', (100, 100), color='white')
pixels = np.array(img)

# LSB'leri manipüle et (tüm LSB'leri 1 yap)
pixels = pixels | 1  # Tüm piksel değerlerinin LSB'ini 1 yap
# Bu, LSB dağılımını anormal yapar (%100 1, %0 0)

img_modified = Image.fromarray(pixels)
img_modified.save('test_lsb.jpg')
```

**Yöntem 3: Düşük Entropi (Çok Az Renk)**
```python
# test_stego_entropy.py
from PIL import Image
import numpy as np

# Sadece 2-3 renk kullanan bir görsel oluştur
img_array = np.zeros((200, 200, 3), dtype=np.uint8)
# Sadece siyah (0,0,0) ve beyaz (255,255,255) kullan
img_array[::2] = 255  # Çizgili pattern

img = Image.fromarray(img_array)
img.save('test_entropy.jpg')
# Bu görsel çok az farklı piksel değeri içerir → düşük entropi
```

**Sonuç:** Sistem bu anomalileri tespit eder ve "Steganografi Şüphesi" olarak işaretler.

---

## 🟢 4. Malware Dropper Şüphesi

### Nasıl Tespit Edilir?
İki kriter birlikte kontrol edilir:

1. **Dosya Boyutu / Çözünürlük Oranı**:
   - Beklenen boyuttan 3x'den fazla büyükse şüpheli
   - Formül: `gerçek_boyut / beklenen_boyut > 3.0`

2. **Yüksek Entropi**:
   - Entropi değeri > 7.5 ise şüpheli (şifrelenmiş/sıkıştırılmış içerik işareti)
   - Normal görsellerde entropi: 6-7.5 arası

### Test Dosyası Nasıl Oluşturulur?

**Yöntem: Yüksek Entropi + Büyük Boyut**
```python
# test_dropper.py
from PIL import Image
import numpy as np
import random

# Küçük bir görsel oluştur (100x100)
width, height = 100, 100

# Yüksek entropi için rastgele piksel değerleri kullan
# (şifrelenmiş veri gibi görünmesi için)
random_data = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
img = Image.fromarray(random_data)

# Yüksek kalitede kaydet (büyük dosya boyutu)
img.save('test_dropper.jpg', quality=100, optimize=False)

# Ek olarak: Dosyanın sonuna rastgele veri ekle (boyutu daha da büyüt)
with open('test_dropper.jpg', 'ab') as f:
    # 50KB rastgele veri ekle
    random_payload = bytes(random.randint(0, 255) for _ in range(50000))
    f.write(random_payload)
```

**Sonuç:** Sistem hem büyük dosya boyutunu hem yüksek entropiyi tespit eder.

---

## 🔵 5. Dosya Türü Sahteciliği

### Nasıl Tespit Edilir?
Dosya uzantısı (.jpg) ile gerçek dosya header'ı karşılaştırılır:
- Uzantı: `.jpg`
- Header: `FF D8 FF` (JPEG) → ✅ Uyumlu
- Header: `89 50 4E 47` (PNG) → ❌ Sahte!

### Test Dosyası Nasıl Oluşturulur?

```python
# test_fake_type.py
# Bir PNG dosyasını .jpg uzantısıyla kaydet
from PIL import Image

# PNG görsel oluştur
img = Image.new('RGB', (100, 100), color='blue')
img.save('original.png')

# PNG dosyasını oku ve .jpg uzantısıyla kaydet (header değişmez!)
with open('original.png', 'rb') as f:
    png_data = f.read()

with open('fake.jpg', 'wb') as f:  # .jpg uzantısı ama PNG içeriği!
    f.write(png_data)
```

**Sonuç:** Sistem uzantı ile header uyumsuzluğunu tespit eder.

---

## 📊 Test Senaryoları Özeti

| Tehdit Tipi | Kolaylık | Test Yöntemi | Beklenen Sonuç |
|------------|----------|--------------|----------------|
| **Append-Data Malware** | ⭐⭐⭐ Çok Kolay | JPEG sonuna metin ekle | Risk: 90, Payload gösterilir |
| **Trojan** | ⭐⭐ Kolay | PE/ELF imzası veya script ekle | Risk: Yüksek/Orta |
| **Steganografi** | ⭐ Orta | LSB manipülasyonu veya büyük dosya | Risk: Yüksek/Orta |
| **Malware Dropper** | ⭐ Zor | Yüksek entropi + büyük dosya | Risk: Yüksek/Orta |
| **Dosya Türü Sahteciliği** | ⭐⭐⭐ Çok Kolay | PNG'yi .jpg olarak kaydet | Risk: Yüksek |

---

## 🛠️ Hızlı Test Script'i

Tüm testleri tek seferde yapan Python script'i:

```python
# create_test_files.py
from PIL import Image
import numpy as np
import random

print("Test dosyaları oluşturuluyor...")

# 1. Append-Data Malware Test
print("1. Append-Data test dosyası oluşturuluyor...")
img = Image.new('RGB', (100, 100), color='green')
img.save('base.jpg')
with open('base.jpg', 'rb') as f:
    data = f.read()
with open('test_append.jpg', 'wb') as f:
    f.write(data + b'\nGIZLI_VERI_TEST')
print("   ✓ test_append.jpg oluşturuldu")

# 2. Trojan Test (PE imzası)
print("2. Trojan test dosyası oluşturuluyor...")
with open('base.jpg', 'rb') as f:
    data = f.read()
pe_sig = b'PE\x00\x00\x00\x00FAKE_EXE_DATA'
new_data = data[:len(data)//2] + pe_sig + data[len(data)//2:]
with open('test_trojan.jpg', 'wb') as f:
    f.write(new_data)
print("   ✓ test_trojan.jpg oluşturuldu")

# 3. Steganografi Test (Büyük dosya)
print("3. Steganografi test dosyası oluşturuluyor...")
img = Image.new('RGB', (100, 100), color='blue')
img.save('test_stego.jpg', quality=100, optimize=False)
# Ek veri ekle
with open('test_stego.jpg', 'ab') as f:
    f.write(b'\x00' * 100000)  # 100KB ek veri
print("   ✓ test_stego.jpg oluşturuldu")

# 4. Dosya Türü Sahteciliği
print("4. Dosya türü sahteciliği test dosyası oluşturuluyor...")
img = Image.new('RGB', (100, 100), color='red')
img.save('original.png')
with open('original.png', 'rb') as f:
    png_data = f.read()
with open('test_fake.jpg', 'wb') as f:
    f.write(png_data)  # PNG içeriği, .jpg uzantısı
print("   ✓ test_fake.jpg oluşturuldu")

print("\n✅ Tüm test dosyaları oluşturuldu!")
print("Web arayüzünden bu dosyaları yükleyerek test edebilirsiniz.")
```

---

## ⚠️ Önemli Notlar

1. **Test Dosyaları**: Bu dosyalar sadece test amaçlıdır, gerçek zararlı içerik içermezler.

2. **Steganografi**: Gerçek steganografi teknikleri daha karmaşıktır. Bu testler basitleştirilmiş versiyonlardır.

3. **False Positive**: Sistem bazen zararsız dosyaları da şüpheli olarak işaretleyebilir (yanlış pozitif).

4. **Performance**: Büyük dosyalar analiz için daha uzun sürebilir.

---

## 📝 Test Adımları

1. Yukarıdaki script'leri kullanarak test dosyaları oluşturun
2. Backend ve frontend'i çalıştırın
3. Web arayüzünden test dosyasını yükleyin
4. Analiz sonuçlarını kontrol edin
5. Her tehdit türü için ayrı test dosyası kullanın

**İyi testler! 🧪**


