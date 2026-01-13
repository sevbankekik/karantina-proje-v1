"""
Dijital Karantina - Backend API
FastAPI ile görsel analiz servisi
"""

# Standart kütüphaneler
import hashlib
import io
import os
import logging
import asyncio
import json
import re
import struct
import math
import base64
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin
from typing import Optional

# Logging yapılandırması - Önce logger'ı tanımla
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Pydantic import kontrolü
try:
    from pydantic import BaseModel  # type: ignore
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    logger.warning("Pydantic yüklü değil. Request modelleri için dict kullanılacak.")

# FastAPI import kontrolü
try:
    from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Body  # type: ignore
    from fastapi.middleware.cors import CORSMiddleware  # type: ignore
    FASTAPI_AVAILABLE = True
except ImportError as e:
    FASTAPI_AVAILABLE = False
    logger.error(f"FastAPI yüklü değil! Lütfen 'pip install fastapi' komutunu çalıştırın. Hata: {e}")
    # Fallback için dummy sınıflar
    class FastAPI:
        def __init__(self, *args, **kwargs):
            pass
        def add_middleware(self, *args, **kwargs):
            pass
        def get(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator
        def post(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator
    class File:
        pass
    class UploadFile:
        pass
    class HTTPException(Exception):
        pass
    class CORSMiddleware:
        pass

# PIL/Pillow import kontrolü
try:
    from PIL import Image  # type: ignore
    from PIL.ExifTags import TAGS, GPSTAGS  # type: ignore
    PIL_AVAILABLE = True
except ImportError as e:
    PIL_AVAILABLE = False
    logger.error(f"Pillow yüklü değil! Lütfen 'pip install Pillow' komutunu çalıştırın. Hata: {e}")
    # Fallback için dummy sınıflar
    class Image:
        @staticmethod
        def open(*args, **kwargs):
            raise ImportError("Pillow yüklü değil!")
        class Resampling:
            LANCZOS = None
    TAGS = {}
    GPSTAGS = {}

# exifread import kontrolü
try:
    import exifread  # type: ignore
    EXIFREAD_AVAILABLE = True
except ImportError:
    EXIFREAD_AVAILABLE = False
    logger.warning("exifread kütüphanesi yüklü değil. Gelişmiş EXIF analizi sınırlı olacak. Yüklemek için: pip install exifread")

# Playwright import kontrolü
try:
    from playwright.async_api import async_playwright, Browser, Page  # type: ignore
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright kütüphanesi yüklü değil. URL analizi çalışmayacak. Yüklemek için: pip install playwright && playwright install chromium")


# FastAPI uygulaması - Sadece gerekli kütüphaneler yüklüyse
if not FASTAPI_AVAILABLE:
    logger.error("FastAPI yüklü değil! Uygulama çalışmayacak. Lütfen 'pip install fastapi uvicorn python-multipart pydantic' komutunu çalıştırın.")
    raise ImportError("FastAPI yüklü değil!")

if not PIL_AVAILABLE:
    logger.error("Pillow yüklü değil! Görsel analizi çalışmayacak. Lütfen 'pip install Pillow' komutunu çalıştırın.")
    raise ImportError("Pillow yüklü değil!")

app = FastAPI(
    title="Dijital Karantina API",
    description="Görsel analizi için sandbox servisi",
    version="1.0.0"
)

# CORS middleware - Frontend port 5500 için, Backend port 5050
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:5050",
        "http://127.0.0.1:5050"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    """API sağlık kontrolü"""
    return {"status": "ok"}


@app.get("/health/dependencies")
async def health_dependencies():
    """Bağımlılık durumu kontrolü"""
    return {
        "status": "ok",
        "dependencies": {
            "fastapi": FASTAPI_AVAILABLE,
            "pillow": PIL_AVAILABLE,
            "exifread": EXIFREAD_AVAILABLE,
            "playwright": PLAYWRIGHT_AVAILABLE
        },
        "playwright_installed": PLAYWRIGHT_AVAILABLE,
        "playwright_message": "Playwright yüklü ve hazır" if PLAYWRIGHT_AVAILABLE else "Playwright yüklü değil. URL analizi çalışmayacak."
    }


# ===== URL KARANTİNA ve DERİN ANALİZ MOTORU =====

async def analyze_url_quarantine(url: str) -> dict:
    """
    URL Karantina ve Derin Analiz Motoru
    
    Giriş: URL
    Çıkış: Karantina analiz sonuçları (ekran görüntüsü, redirect zinciri, tehdit tespiti, vb.)
    
    Args:
        url: Analiz edilecek URL
    
    Returns:
        dict: Analiz sonuçları
    """
    result = {
        "status": "success",
        "message": "Karantina Odası Analizi Tamamlandı",
        "url": url,
        "final_url": url,
        "redirect_chain": [],
        "redirect_count": 0,
        "page_title": "",
        "ssl_status": "unknown",
        "ip_address": "unknown",
        "karantina_fotografi": "",  # Base64 screenshot
        "risk_skoru": 0,
        "tespitler": [],  # Detected threats list
        "karantina_mesaji": "",
        "threats_detected": [],
        "threats_isolated": False,
        "analysis_summary": ""
    }
    
    if not PLAYWRIGHT_AVAILABLE:
        result["status"] = "error"
        result["message"] = "Playwright kütüphanesi yüklü değil. Lütfen 'pip install playwright && playwright install chromium' komutunu çalıştırın."
        return result
    
    # URL doğrulama
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
            parsed = urlparse(url)
        if not parsed.netloc:
            result["status"] = "error"
            result["message"] = "Geçersiz URL formatı. Lütfen doğru bir URL girin (örn: https://example.com)"
            return result
    except Exception as e:
        result["status"] = "error"
        result["message"] = f"URL doğrulama hatası: {str(e)}"
        return result
    
    browser: Optional[Browser] = None
    try:
        logger.info(f"URL karantina analizi başlatılıyor: {url}")
        
        # Playwright başlat
        async with async_playwright() as p:
            # Headless Chromium tarayıcısı başlat (izole ortam)
            logger.info("Headless Chromium tarayıcısı başlatılıyor...")
            browser = await p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
            )
            
            # Yeni bir context oluştur (her analiz için izole)
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )
            
            page: Page = await context.new_page()
            
            # Redirect zincirini takip et (framenavigated event ile)
            redirect_chain = []
            navigation_urls = []
            final_url = url
            
            def handle_navigation(frame):
                """Frame navigation handler - tüm yönlendirmeleri yakala"""
                try:
                    frame_url = frame.url
                    if frame_url and frame_url not in navigation_urls:
                        navigation_urls.append(frame_url)
                        if len(navigation_urls) > 1:
                            redirect_chain.append({
                                "from": navigation_urls[-2] if len(navigation_urls) > 1 else url,
                                "to": frame_url,
                                "step": len(navigation_urls)
                            })
                except:
                    pass
            
            def handle_response(response):
                """Response handler - HTTP redirect'leri yakala"""
                if response.status in [301, 302, 303, 307, 308]:
                    redirect_url = response.headers.get('location', '')
                    if redirect_url:
                        # Relative URL'yi absolute'e çevir
                        if not redirect_url.startswith('http'):
                            redirect_url = urljoin(response.url, redirect_url)
                        redirect_chain.append({
                            "from": response.url,
                            "to": redirect_url,
                            "status": response.status,
                            "type": "HTTP Redirect"
                        })
            
            page.on("framenavigated", handle_navigation)
            page.on("response", handle_response)
            
            try:
                # Sayfaya git (timeout: 30 saniye)
                logger.info(f"Sayfaya gidiliyor: {url}")
                response = await page.goto(url, wait_until="networkidle", timeout=30000)
                
                if response:
                    final_url = response.url
                    result["final_url"] = final_url
                    
                    # SSL durumu kontrolü
                    try:
                        security_details = response.request.url
                        if security_details.startswith('https://'):
                            result["ssl_status"] = "secure"
                        else:
                            result["ssl_status"] = "insecure"
                    except:
                        result["ssl_status"] = "unknown"
                    
                    # IP adresi bilgisi (response headers'dan)
                    try:
                        server_ip = response.headers.get('x-forwarded-for') or response.headers.get('x-real-ip')
                        if server_ip:
                            result["ip_address"] = server_ip
                    except:
                        pass
                
                # Sayfa başlığını al
                try:
                    page_title = await page.title()
                    result["page_title"] = page_title
                except:
                    result["page_title"] = "Başlık alınamadı"
                
                # Redirect zinciri güncelleme
                if redirect_chain:
                    result["redirect_chain"] = redirect_chain
                    result["redirect_count"] = len(redirect_chain)
                    logger.info(f"Redirect zinciri: {len(redirect_chain)} adet")
                
                # Sayfa kaynağını al (tehdit analizi için)
                try:
                    html_content = await page.content()
                except:
                    html_content = ""
                
                # Tehdit tespiti
                threats = []
                risk_score = 0
                
                # 1. Gizli formlar (display:none, visibility:hidden)
                hidden_form_patterns = [
                    r'<form[^>]*style[^>]*display\s*:\s*none[^>]*>',
                    r'<form[^>]*style[^>]*visibility\s*:\s*hidden[^>]*>',
                    r'<form[^>]*hidden[^>]*>',
                ]
                for pattern in hidden_form_patterns:
                    if re.search(pattern, html_content, re.IGNORECASE):
                        threats.append({
                            "type": "Gizli Form",
                            "description": "Sayfada gizli form tespit edildi",
                            "risk_level": "medium"
                        })
                        break
                
                # 2. Iframe tespiti
                iframe_count = html_content.lower().count('<iframe')
                if iframe_count > 0:
                    threats.append({
                        "type": "Iframe İçeriği",
                        "description": f"Sayfada {iframe_count} adet iframe tespit edildi",
                        "risk_level": "low" if iframe_count <= 2 else "medium"
                    })
                
                # 3. Şüpheli JavaScript fonksiyonları
                suspicious_js_patterns = [
                    (r'eval\s*\(', "eval() fonksiyonu", "high"),
                    (r'Function\s*\(', "Function() constructor", "medium"),
                    (r'atob\s*\(', "Base64 decode (atob)", "medium"),
                    (r'btoa\s*\(', "Base64 encode (btoa)", "low"),
                    (r'document\.write\s*\(', "document.write()", "low"),
                    (r'innerHTML\s*=', "innerHTML manipülasyonu", "low"),
                ]
                
                for pattern, name, risk_level in suspicious_js_patterns:
                    if re.search(pattern, html_content, re.IGNORECASE):
                        threats.append({
                            "type": "Şüpheli JavaScript",
                            "description": f"{name} kullanımı tespit edildi",
                            "risk_level": risk_level
                        })
                
                # 4. Dış kaynak yüklemeleri (CDN dışı)
                external_script_pattern = r'<script[^>]*src=["\'](https?://[^"\']+)["\']'
                external_scripts = re.findall(external_script_pattern, html_content, re.IGNORECASE)
                if external_scripts:
                    # Ana domain dışı script'leri say
                    main_domain = urlparse(final_url).netloc
                    foreign_scripts = [s for s in external_scripts if urlparse(s).netloc != main_domain]
                    if foreign_scripts and len(foreign_scripts) > 3:
                        threats.append({
                            "type": "Çoklu Dış Kaynak",
                            "description": f"{len(foreign_scripts)} adet farklı domain'den script yükleniyor",
                            "risk_level": "medium"
                        })
                        risk_score += 15
                
                # 5. Zararlı Yazılım Taraması - Dosya indirme linkleri
                dangerous_extensions = ['.exe', '.zip', '.bat', '.apk', '.msi', '.scr', '.com', '.pif', '.vbs', '.jar']
                download_links = []
                
                # Tüm <a> taglerini bul
                try:
                    links = await page.query_selector_all('a[href]')
                    for link in links:
                        href = await link.get_attribute('href')
                        if href:
                            # Absolute URL'ye çevir
                            absolute_url = urljoin(final_url, href)
                            # Dosya uzantısını kontrol et
                            for ext in dangerous_extensions:
                                if ext.lower() in absolute_url.lower():
                                    try:
                                        link_text = await link.inner_text()
                                        link_text = link_text.strip() if link_text else "Link"
                                    except:
                                        link_text = "Link"
                                    download_links.append({
                                        "url": absolute_url,
                                        "extension": ext,
                                        "text": link_text
                                    })
                                    break
                except Exception as e:
                    logger.warning(f"Link tarama hatası: {str(e)}")
                    # Fallback: HTML'den regex ile bul
                    link_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>'
                    all_links = re.findall(link_pattern, html_content, re.IGNORECASE)
                    for link_url in all_links:
                        absolute_url = urljoin(final_url, link_url)
                        for ext in dangerous_extensions:
                            if ext.lower() in absolute_url.lower():
                                download_links.append({
                                    "url": absolute_url,
                                    "extension": ext,
                                    "text": "Link"
                                })
                                break
                
                if download_links:
                    threats.append({
                        "type": "Otomatik İndirme Riski",
                        "description": f"{len(download_links)} adet dosya indirme linki tespit edildi ({', '.join(set([d['extension'] for d in download_links]))})",
                        "risk_level": "high",
                        "details": download_links[:10]  # İlk 10 link
                    })
                    risk_score += 30
                    logger.warning(f"Dosya indirme linkleri bulundu: {len(download_links)} adet")
                
                # 6. Phishing Kontrolü
                phishing_keywords = ['login', 'bank', 'verify', 'account', 'secure', 'sign in', 'password', 'credentials']
                page_title_lower = result["page_title"].lower()
                phishing_keywords_found = [kw for kw in phishing_keywords if kw in page_title_lower]
                
                # Password input kontrolü
                password_input_count = 0
                try:
                    password_inputs = await page.query_selector_all('input[type="password"]')
                    password_input_count = len(password_inputs)
                except:
                    # Fallback: HTML'den regex ile
                    password_pattern = r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>'
                    password_matches = re.findall(password_pattern, html_content, re.IGNORECASE)
                    password_input_count = len(password_matches)
                
                if phishing_keywords_found and password_input_count > 0:
                    threats.append({
                        "type": "Yüksek Oltalama Riski",
                        "description": f"Sayfa başlığında şüpheli kelimeler ({', '.join(phishing_keywords_found)}) ve şifre giriş alanı tespit edildi",
                        "risk_level": "high",
                        "phishing_keywords": phishing_keywords_found,
                        "password_fields_count": password_input_count
                    })
                    risk_score += 40
                    logger.warning(f"Phishing riski tespit edildi: {phishing_keywords_found}")
                elif phishing_keywords_found:
                    threats.append({
                        "type": "Oltalama Şüphesi",
                        "description": f"Sayfa başlığında şüpheli kelimeler tespit edildi: {', '.join(phishing_keywords_found)}",
                        "risk_level": "medium",
                        "phishing_keywords": phishing_keywords_found
                    })
                    risk_score += 20
                elif password_input_count > 0:
                    threats.append({
                        "type": "Şifre Giriş Alanı",
                        "description": f"Sayfada {password_input_count} adet şifre giriş alanı tespit edildi",
                        "risk_level": "low"
                    })
                    risk_score += 5
                
                # Risk skorunu hesapla (mevcut tehditlerden)
                for threat in threats:
                    if threat["risk_level"] == "high":
                        risk_score += 10
                    elif threat["risk_level"] == "medium":
                        risk_score += 5
                    elif threat["risk_level"] == "low":
                        risk_score += 2
                
                # Risk skorunu 0-100 arasında sınırla
                risk_score = min(100, max(0, risk_score))
                
                result["threats_detected"] = threats
                result["tespitler"] = threats  # Türkçe alan adı
                result["threats_isolated"] = len(threats) > 0
                result["risk_skoru"] = risk_score
                
                # Ekran görüntüsü al (Karantina Kanıtı)
                try:
                    logger.info("Sayfa ekran görüntüsü alınıyor...")
                    screenshot_bytes = await page.screenshot(full_page=True)
                    screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')
                    result["screenshot_base64"] = screenshot_base64
                    result["karantina_fotografi"] = screenshot_base64  # Türkçe alan adı
                    logger.info("Ekran görüntüsü başarıyla alındı")
                except Exception as e:
                    logger.warning(f"Ekran görüntüsü alınamadı: {str(e)}")
                    result["screenshot_base64"] = ""
                    result["karantina_fotografi"] = ""
                
                # Karantina mesajı oluştur
                if threats:
                    threat_count = len(threats)
                    high_risk_count = sum(1 for t in threats if t.get("risk_level") == "high")
                    
                    if high_risk_count > 0:
                        karantina_mesaji = (
                            f"Senin için güvenli odada inceledik ve {threat_count} adet risk tespit ettik. "
                            f"Özellikle {high_risk_count} adet yüksek riskli durum bulundu. "
                            f"Bu sayfayı açmadan önce dikkatli olmanı öneriyoruz."
                        )
                    else:
                        karantina_mesaji = (
                            f"Senin için güvenli odada inceledik ve {threat_count} adet şüpheli öğe bulduk. "
                            f"Sayfa analiz edildi ve kayıt altına alındı."
                        )
                else:
                    karantina_mesaji = (
                        "Senin için güvenli odada inceledik ve herhangi bir risk tespit etmedik. "
                        "Sayfa analiz edildi ve kayıt altına alındı."
                    )
                
                result["karantina_mesaji"] = karantina_mesaji
                
                # Analiz özeti (eski format - geriye uyumluluk için)
                if threats:
                    result["analysis_summary"] = f"Tehditler İzole Edildi: {len(threats)} adet şüpheli öğe tespit edildi. Karantina odasında güvenli şekilde analiz edildi."
                else:
                    result["analysis_summary"] = "Karantina Odası Analizi Tamamlandı: Sayfa analiz edildi ve kayıt altına alındı."
                
                logger.info(f"URL analizi tamamlandı: {final_url}, Tehdit sayısı: {len(threats)}")
                
            except Exception as page_error:
                logger.error(f"Sayfa yükleme hatası: {str(page_error)}")
                result["status"] = "error"
                result["message"] = f"Siteye ulaşılamadı. Lütfen URL'yi kontrol edin. Hata: {str(page_error)}"
            
            finally:
                await page.close()
                await context.close()
    
    except Exception as e:
        logger.error(f"URL karantina analizi hatası: {str(e)}", exc_info=True)
        result["status"] = "error"
        result["message"] = f"Analiz sırasında bir hata oluştu. Lütfen tekrar deneyin. Hata: {str(e)}"
    
    finally:
        if browser:
            try:
                await browser.close()
            except:
                pass
    
    return result


@app.post("/analyze/url")
async def analyze_url(request: dict = Body(...)):
    """
    URL Karantina ve Derin Analiz Endpoint'i
    
    Request body:
    {
        "url": "https://example.com"
    }
    
    Returns:
        dict: Karantina analiz sonuçları
    """
    try:
        # Request body'den URL'yi al
        url = request.get("url", "").strip() if isinstance(request, dict) else ""
        
        if not url:
            return {
                "status": "error",
                "message": "URL parametresi gerekli",
                "url": ""
            }
        
        # URL analizini başlat
        result = await analyze_url_quarantine(url)
        
        return result
    
    except Exception as e:
        logger.error(f"URL analiz endpoint hatası: {str(e)}", exc_info=True)
        request_url = request.get("url", "") if isinstance(request, dict) else ""
        return {
            "status": "error",
            "message": f"Analiz sırasında bir hata oluştu: {str(e)}",
            "url": request_url
        }


def get_exif_data(image):
    """EXIF metadata çıkar - Tüm tagleri kapsar (PIL 10.0+ uyumlu)"""
    exif_data = {}
    try:
        # PIL ile EXIF çıkar - Modern ve eski PIL versiyonları için uyumlu
        if hasattr(image, 'getexif'):
            # PIL 10.0+ için getexif() kullan
            try:
                exif = image.getexif()
                if exif is not None:
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        exif_data[tag] = value
            except Exception as e:
                logger.warning(f"getexif() ile EXIF çıkarılırken hata: {str(e)}")
        elif hasattr(image, '_getexif'):
            # Eski PIL versiyonları için _getexif() kullan
            try:
                exif = image._getexif()
                if exif is not None:
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        exif_data[tag] = value
            except Exception as e:
                logger.warning(f"_getexif() ile EXIF çıkarılırken hata: {str(e)}")
    except Exception as e:
        logger.warning(f"PIL EXIF çıkarılırken genel hata: {str(e)}")
    
    return exif_data


def get_all_exif_tags(file_content):
    """exifread ile TÜM EXIF taglerini çıkar (ExifRest.getAllTags benzeri) - Optimize edilmiş"""
    all_exif = {}
    try:
        if EXIFREAD_AVAILABLE:
            # exifread bazen hata verebilir, try-except ile korumalıyız
            # details=False ile daha hızlı çalışır
            tags = exifread.process_file(io.BytesIO(file_content), details=False, strict=False)
            tag_count = 0
            for tag in tags.keys():
                try:
                    # Tag isimlerini temizle ve normalize et
                    tag_name = str(tag)
                    tag_value = str(tags[tag])
                    all_exif[tag_name] = tag_value
                    tag_count += 1
                    # Performans için maksimum 200 tag al (yeterli)
                    if tag_count >= 200:
                        break
                except:
                    continue
            logger.info(f"exifread ile {len(all_exif)} EXIF tag bulundu")
        else:
            logger.info("exifread kütüphanesi yüklü değil, sadece PIL EXIF kullanılıyor")
    except Exception as e:
        logger.warning(f"exifread ile EXIF çıkarılırken hata: {str(e)}")
        # Hata olsa bile devam et, boş dict dön
    
    return all_exif


def extract_iptc_metadata(file_content):
    """IPTC metadata çıkar"""
    iptc_data = {}
    try:
        # IPTC metadata genelde dosyanın başında veya belirli offset'lerde bulunur
        # Basit pattern matching ile IPTC marker'ları ara
        iptc_markers = [
            b'\x1c\x01',  # IPTC Application Record
            b'\x1c\x02',  # IPTC Pre-Object Data
            b'\x1c\x03',  # IPTC Object Data
        ]
        
        for marker in iptc_markers:
            if marker in file_content:
                # IPTC data bulundu, basit parsing yap
                offset = file_content.find(marker)
                if offset != -1:
                    iptc_data['found'] = True
                    iptc_data['offset'] = offset
                    logger.info(f"IPTC marker bulundu: offset {offset}")
                    break
        
        # IPTC field'ları için pattern matching
        iptc_patterns = {
            'copyright': [b'Copyright', b'COPYRIGHT'],
            'caption': [b'Caption', b'CAPTION', b'Description'],
            'keywords': [b'Keywords', b'KEYWORDS'],
            'byline': [b'Byline', b'BYLINE', b'Author'],
        }
        
        for field, patterns in iptc_patterns.items():
            for pattern in patterns:
                if pattern in file_content:
                    iptc_data[field] = True
                    break
        
    except Exception as e:
        logger.warning(f"IPTC metadata çıkarılırken hata: {str(e)}")
    
    return iptc_data


def extract_xmp_metadata(file_content):
    """XMP metadata çıkar"""
    xmp_data = {}
    try:
        # XMP metadata genelde XML formatında, xpacket veya rdf:RDF içinde
        file_str = file_content.decode('utf-8', errors='ignore')
        
        # XMP marker'ları ara
        xmp_markers = [
            'xpacket',
            'rdf:RDF',
            'x:xmpmeta',
            'xmlns:xmp',
            'xmlns:photoshop',
            'xmlns:exif',
        ]
        
        xmp_found = False
        for marker in xmp_markers:
            if marker.lower() in file_str.lower():
                xmp_found = True
                break
        
        if xmp_found:
            xmp_data['found'] = True
            
            # XMP namespace'leri ara
            xmp_namespaces = {
                'photoshop': 'xmlns:photoshop',
                'exif': 'xmlns:exif',
                'xmp': 'xmlns:xmp',
                'dc': 'xmlns:dc',
                'xmpMM': 'xmlns:xmpMM',
            }
            
            for ns_name, ns_pattern in xmp_namespaces.items():
                if ns_pattern.lower() in file_str.lower():
                    xmp_data[ns_name] = True
            
            # XMP içinde düzenleme bilgileri ara
            edit_patterns = [
                'photoshop:DateCreated',
                'xmp:CreateDate',
                'xmp:ModifyDate',
                'photoshop:History',
                'xmpMM:History',
            ]
            
            for pattern in edit_patterns:
                if pattern.lower() in file_str.lower():
                    xmp_data['editing_info'] = True
                    break
            
            logger.info(f"XMP metadata bulundu: {len(xmp_data)} namespace")
    except Exception as e:
        logger.warning(f"XMP metadata çıkarılırken hata: {str(e)}")
    
    return xmp_data


def get_all_gps_coordinates(exif_data, all_exif_tags):
    """Tüm alternatif GPS koordinat etiketlerini kontrol et"""
    gps_data = {}
    gps_found = False
    
    try:
        # Standart GPS bilgisi
        if 'GPSInfo' in exif_data:
            gps_info = exif_data['GPSInfo']
            for tag_id, value in gps_info.items():
                tag = GPSTAGS.get(tag_id, tag_id)
                gps_data[tag] = value
                gps_found = True
        
        # Alternatif GPS etiketleri (exifread'den)
        gps_alternatives = [
            'GPS GPSLatitude',
            'GPS GPSLongitude',
            'GPS GPSDestLatitude',
            'GPS GPSDestLongitude',
            'EXIF GPSLatitude',
            'EXIF GPSLongitude',
            'EXIF GPSDestLatitude',
            'EXIF GPSDestLongitude',
        ]
        
        for gps_tag in gps_alternatives:
            if gps_tag in all_exif_tags:
                gps_data[gps_tag] = all_exif_tags[gps_tag]
                gps_found = True
                logger.info(f"Alternatif GPS tag bulundu: {gps_tag}")
        
        # GPS koordinatlarını decimal'e çevir
        if gps_found:
            # GPSLatitude ve GPSLongitude'u parse et
            lat = None
            lon = None
            
            # Standart GPS bilgisi
            if 'GPSLatitude' in gps_data and 'GPSLatitudeRef' in gps_data:
                lat_tuple = gps_data['GPSLatitude']
                lat_ref = gps_data['GPSLatitudeRef']
                if isinstance(lat_tuple, tuple) and len(lat_tuple) == 3:
                    lat = lat_tuple[0] + lat_tuple[1]/60.0 + lat_tuple[2]/3600.0
                    if lat_ref == 'S':
                        lat = -lat
            
            if 'GPSLongitude' in gps_data and 'GPSLongitudeRef' in gps_data:
                lon_tuple = gps_data['GPSLongitude']
                lon_ref = gps_data['GPSLongitudeRef']
                if isinstance(lon_tuple, tuple) and len(lon_tuple) == 3:
                    lon = lon_tuple[0] + lon_tuple[1]/60.0 + lon_tuple[2]/3600.0
                    if lon_ref == 'W':
                        lon = -lon
            
            # Alternatif GPS taglerinden parse et
            if lat is None or lon is None:
                for tag_name, tag_value in all_exif_tags.items():
                    if 'GPSLatitude' in tag_name and lat is None:
                        try:
                            # exifread formatından parse et: "38 [degrees], 25 [minutes], 12.345 [seconds]"
                            lat_str = str(tag_value)
                            lat = parse_dms_to_decimal(lat_str)
                            if 'GPS GPSLatitudeRef' in all_exif_tags:
                                ref = all_exif_tags['GPS GPSLatitudeRef']
                                if 'S' in str(ref).upper():
                                    lat = -lat
                        except:
                            pass
                    
                    if 'GPSLongitude' in tag_name and lon is None:
                        try:
                            lon_str = str(tag_value)
                            lon = parse_dms_to_decimal(lon_str)
                            if 'GPS GPSLongitudeRef' in all_exif_tags:
                                ref = all_exif_tags['GPS GPSLongitudeRef']
                                if 'W' in str(ref).upper():
                                    lon = -lon
                        except:
                            pass
            
            if lat is not None and lon is not None:
                gps_data['latitude_decimal'] = lat
                gps_data['longitude_decimal'] = lon
                gps_data['coordinates'] = f"Enlem: {lat:.6f}°, Boylam: {lon:.6f}°"
                gps_data['google_maps_url'] = f"https://www.google.com/maps?q={lat},{lon}"
    
    except Exception as e:
        logger.warning(f"GPS koordinatları parse edilirken hata: {str(e)}")
    
    return gps_data, gps_found


def parse_dms_to_decimal(dms_str):
    """DMS (Degrees Minutes Seconds) formatını decimal'e çevir"""
    try:
        # Format: "38 [degrees], 25 [minutes], 12.345 [seconds]"
        parts = re.findall(r'[\d.]+', dms_str)
        if len(parts) >= 3:
            degrees = float(parts[0])
            minutes = float(parts[1])
            seconds = float(parts[2])
            return degrees + minutes/60.0 + seconds/3600.0
    except:
        pass
    return None


def binary_pattern_matcher(file_content):
    """Binary kod içinde cihaz bilgilerini ara (Pattern Matcher) - Optimize edilmiş"""
    device_info = {}
    patterns = {
        'iPhone': [b'iPhone', b'IPHONE', b'Apple iPhone'],
        'Samsung': [b'Samsung', b'SAMSUNG', b'SM-', b'Galaxy'],
        'Android': [b'Android', b'ANDROID', b'android'],
        'Canon': [b'Canon', b'CANON'],
        'Nikon': [b'Nikon', b'NIKON'],
        'Sony': [b'Sony', b'SONY'],
        'Google': [b'Google', b'GOOGLE', b'Pixel'],
        'Huawei': [b'Huawei', b'HUAWEI'],
        'Xiaomi': [b'Xiaomi', b'XIAOMI', b'MI '],
    }
    
    try:
        # Büyük dosyalar için sadece ilk 1MB'ı kontrol et (performans için)
        max_bytes_to_check = 1024 * 1024  # 1MB
        content_to_check = file_content[:max_bytes_to_check] if len(file_content) > max_bytes_to_check else file_content
        
        # Binary pattern matching - daha hızlı
        for device, device_patterns in patterns.items():
            for pattern in device_patterns:
                if pattern in content_to_check:
                    device_info[device] = True
                    logger.info(f"Binary pattern match: {device} bulundu")
                    break
    except Exception as e:
        logger.warning(f"Binary pattern matching sırasında hata: {str(e)}")
    
    return device_info


def get_gps_data(exif_data):
    """GPS bilgisi çıkar"""
    try:
        gps_data = {}
        if 'GPSInfo' in exif_data:
            gps_info = exif_data['GPSInfo']
            for tag_id, value in gps_info.items():
                tag = GPSTAGS.get(tag_id, tag_id)
                gps_data[tag] = value
        return gps_data
    except Exception as e:
        logger.warning(f"GPS data çıkarılırken hata: {str(e)}")
        return {}


def parse_exif_details(exif_data, gps_data, all_exif_tags, binary_patterns, iptc_data, xmp_data):
    """EXIF verilerinden detaylı bilgileri çıkar - Tüm kaynakları kullan"""
    details = {
        "device_info": {},
        "capture_info": {},
        "location_info": {},
        "camera_settings": {},
        "software_info": {},
        "metadata_layers": {
            "exif": len(exif_data) > 0,
            "iptc": iptc_data.get('found', False),
            "xmp": xmp_data.get('found', False),
            "binary_patterns": len(binary_patterns) > 0
        }
    }
    
    try:
        # Cihaz bilgisi - Önce EXIF'ten, yoksa binary pattern'den
        make_found = False
        model_found = False
        
        if 'Make' in exif_data:
            details["device_info"]["make"] = str(exif_data['Make'])
            make_found = True
        elif 'EXIF Make' in all_exif_tags:
            details["device_info"]["make"] = str(all_exif_tags['EXIF Make'])
            make_found = True
        
        if 'Model' in exif_data:
            details["device_info"]["model"] = str(exif_data['Model'])
            model_found = True
        elif 'EXIF Model' in all_exif_tags:
            details["device_info"]["model"] = str(all_exif_tags['EXIF Model'])
            model_found = True
        
        # Binary pattern matching sonuçları
        if binary_patterns:
            detected_devices = list(binary_patterns.keys())
            if not make_found and detected_devices:
                details["device_info"]["detected_from_binary"] = ", ".join(detected_devices)
        
        if 'LensMake' in exif_data:
            details["device_info"]["lens_make"] = str(exif_data['LensMake'])
        if 'LensModel' in exif_data:
            details["device_info"]["lens_model"] = str(exif_data['LensModel'])
        
        # Çekilme tarihi ve saati
        if 'DateTime' in exif_data:
            details["capture_info"]["datetime"] = str(exif_data['DateTime'])
        if 'DateTimeOriginal' in exif_data:
            details["capture_info"]["datetime_original"] = str(exif_data['DateTimeOriginal'])
        if 'DateTimeDigitized' in exif_data:
            details["capture_info"]["datetime_digitized"] = str(exif_data['DateTimeDigitized'])
        
        # GPS/Konum bilgisi - Tüm alternatif kaynaklardan
        if gps_data:
            # Decimal koordinatlar varsa kullan
            if 'latitude_decimal' in gps_data and 'longitude_decimal' in gps_data:
                details["location_info"]["coordinates"] = gps_data.get('coordinates', '')
                details["location_info"]["google_maps_url"] = gps_data.get('google_maps_url', '')
            else:
                # Standart GPS parsing
                location_str = ""
                if 'GPSLatitude' in gps_data and 'GPSLatitudeRef' in gps_data:
                    lat = gps_data['GPSLatitude']
                    lat_ref = gps_data['GPSLatitudeRef']
                    if isinstance(lat, tuple) and len(lat) == 3:
                        lat_decimal = lat[0] + lat[1]/60.0 + lat[2]/3600.0
                        if lat_ref == 'S':
                            lat_decimal = -lat_decimal
                        location_str += f"Enlem: {lat_decimal:.6f}°"
                        details["location_info"]["latitude"] = lat_decimal
                
                if 'GPSLongitude' in gps_data and 'GPSLongitudeRef' in gps_data:
                    lon = gps_data['GPSLongitude']
                    lon_ref = gps_data['GPSLongitudeRef']
                    if isinstance(lon, tuple) and len(lon) == 3:
                        lon_decimal = lon[0] + lon[1]/60.0 + lon[2]/3600.0
                        if lon_ref == 'W':
                            lon_decimal = -lon_decimal
                        if location_str:
                            location_str += ", "
                        location_str += f"Boylam: {lon_decimal:.6f}°"
                        details["location_info"]["longitude"] = lon_decimal
                
                if location_str:
                    details["location_info"]["coordinates"] = location_str
                    if 'latitude' in details["location_info"] and 'longitude' in details["location_info"]:
                        lat = details["location_info"]["latitude"]
                        lon = details["location_info"]["longitude"]
                        details["location_info"]["google_maps_url"] = f"https://www.google.com/maps?q={lat},{lon}"
        
        # Kamera ayarları
        if 'ISOSpeedRatings' in exif_data:
            details["camera_settings"]["iso"] = str(exif_data['ISOSpeedRatings'])
        if 'FNumber' in exif_data:
            fnumber = exif_data['FNumber']
            if isinstance(fnumber, tuple):
                fnumber = fnumber[0] / fnumber[1] if len(fnumber) == 2 else fnumber[0]
            details["camera_settings"]["fnumber"] = f"f/{fnumber}"
        if 'ExposureTime' in exif_data:
            exposure = exif_data['ExposureTime']
            if isinstance(exposure, tuple):
                exposure = exposure[0] / exposure[1] if len(exposure) == 2 else exposure[0]
            details["camera_settings"]["exposure_time"] = f"{exposure}s"
        if 'FocalLength' in exif_data:
            focal = exif_data['FocalLength']
            if isinstance(focal, tuple):
                focal = focal[0] / focal[1] if len(focal) == 2 else focal[0]
            details["camera_settings"]["focal_length"] = f"{focal}mm"
        
        # Yazılım bilgisi
        if 'Software' in exif_data:
            details["software_info"]["software"] = str(exif_data['Software'])
        if 'Artist' in exif_data:
            details["software_info"]["artist"] = str(exif_data['Artist'])
        if 'Copyright' in exif_data:
            details["software_info"]["copyright"] = str(exif_data['Copyright'])
    
    except Exception as e:
        logger.warning(f"EXIF detayları parse edilirken hata: {str(e)}")
    
    return details


async def analyze_image_sync(file_content, filename, mime_type, file_size_bytes):
    """Senkron görsel analiz işlemini async olarak çalıştır - Derinlemesine analiz"""
    try:
        logger.info("PIL Image açılıyor...")
        # PIL işlemini thread pool'da çalıştır (bloklamayı önler)
        loop = asyncio.get_event_loop()
        image = await loop.run_in_executor(None, Image.open, io.BytesIO(file_content))
        logger.info("PIL Image başarıyla açıldı")
        
        # 1. Tüm EXIF taglerini çıkar (exifread ile) - Hata olsa bile devam et
        all_exif_tags = {}
        try:
            logger.info("Tüm EXIF tagleri çıkarılıyor (exifread)...")
            all_exif_tags = await loop.run_in_executor(None, get_all_exif_tags, file_content)
        except Exception as e:
            logger.warning(f"exifread analizi sırasında hata: {str(e)}")
        
        # 2. PIL ile EXIF metadata çıkar
        exif_data = {}
        try:
            logger.info("PIL ile EXIF metadata çıkarılıyor...")
            exif_data = await loop.run_in_executor(None, get_exif_data, image)
        except Exception as e:
            logger.warning(f"PIL EXIF analizi sırasında hata: {str(e)}")
        
        exif_found = len(exif_data) > 0 or len(all_exif_tags) > 0
        logger.info(f"EXIF found: {exif_found} (PIL: {len(exif_data)}, exifread: {len(all_exif_tags)})")
        
        # 3. IPTC metadata çıkar - Hata olsa bile devam et
        iptc_data = {}
        try:
            logger.info("IPTC metadata taranıyor...")
            iptc_data = await loop.run_in_executor(None, extract_iptc_metadata, file_content)
        except Exception as e:
            logger.warning(f"IPTC analizi sırasında hata: {str(e)}")
        
        # 4. XMP metadata çıkar - Hata olsa bile devam et
        xmp_data = {}
        try:
            logger.info("XMP metadata taranıyor...")
            xmp_data = await loop.run_in_executor(None, extract_xmp_metadata, file_content)
        except Exception as e:
            logger.warning(f"XMP analizi sırasında hata: {str(e)}")
        
        # 5. Binary pattern matching (cihaz bilgisi) - Hata olsa bile devam et
        binary_patterns = {}
        try:
            logger.info("Binary pattern matching yapılıyor...")
            binary_patterns = await loop.run_in_executor(None, binary_pattern_matcher, file_content)
        except Exception as e:
            logger.warning(f"Binary pattern matching sırasında hata: {str(e)}")
        
        # 6. GPS bilgisi - Tüm alternatif kaynaklardan - Hata olsa bile devam et
        gps_data = {}
        gps_found = False
        try:
            logger.info("GPS koordinatları taranıyor (tüm alternatifler)...")
            gps_data, gps_found = await loop.run_in_executor(None, get_all_gps_coordinates, exif_data, all_exif_tags)
            logger.info(f"GPS found: {gps_found}")
        except Exception as e:
            logger.warning(f"GPS analizi sırasında hata: {str(e)}")
        
        metadata_size_kb = 0
        exif_details = {
            "device_info": {},
            "capture_info": {},
            "location_info": {},
            "camera_settings": {},
            "software_info": {},
            "metadata_layers": {}
        }
        
        # Metadata katmanları kontrolü
        metadata_layers_found = exif_found or iptc_data.get('found') or xmp_data.get('found') or binary_patterns
        is_stripped = not metadata_layers_found
        
        if metadata_layers_found:
            # Metadata boyutunu hesapla
            try:
                all_metadata = {
                    'exif': exif_data,
                    'all_exif_tags': all_exif_tags,
                    'iptc': iptc_data,
                    'xmp': xmp_data,
                    'binary_patterns': binary_patterns
                }
                metadata_json = json.dumps(all_metadata, default=str)
                metadata_size_kb = round(len(metadata_json.encode('utf-8')) / 1024, 2)
                logger.info(f"Toplam metadata size: {metadata_size_kb} KB")
            except Exception as e:
                logger.warning(f"Metadata boyutu hesaplanırken hata: {str(e)}")
            
            # EXIF detaylarını parse et (tüm kaynaklarla)
            try:
                exif_details = await loop.run_in_executor(
                    None, parse_exif_details, exif_data, gps_data, all_exif_tags, binary_patterns, iptc_data, xmp_data
                )
            except Exception as e:
                logger.warning(f"EXIF detayları parse edilirken hata: {str(e)}")
        
        # Steganografi tespiti
        stego_result = {
            "steganography_detected": False,
            "steganography_confidence": 0.0,
            "steganography_reasons": []
        }
        try:
            logger.info("Steganografi analizi yapılıyor (hızlı mod)...")
            # 5 saniye timeout ile steganografi analizi (hızlı olması için)
            stego_result = await asyncio.wait_for(
                loop.run_in_executor(None, detect_steganography, image, file_size_bytes),
                timeout=5.0
            )
            logger.info(f"Steganografi tespiti: {stego_result['steganography_detected']}, Güven: {stego_result['steganography_confidence']}")
        except asyncio.TimeoutError:
            logger.warning("Steganografi analizi timeout (5 saniye), atlanıyor")
            stego_result = {
                "steganography_detected": False,
                "steganography_confidence": 0.0,
                "steganography_reasons": []
            }
        except Exception as e:
            logger.warning(f"Steganografi analizi sırasında hata: {str(e)}")
            stego_result = {
                "steganography_detected": False,
                "steganography_confidence": 0.0,
                "steganography_reasons": []
            }
        
        return {
            "exif_found": exif_found,
            "gps_found": gps_found,
            "metadata_size_kb": metadata_size_kb,
            "exif_details": exif_details,
            "iptc_found": iptc_data.get('found', False),
            "xmp_found": xmp_data.get('found', False),
            "binary_patterns": binary_patterns,
            "is_stripped": is_stripped,
            "steganography_detected": stego_result["steganography_detected"],
            "steganography_confidence": stego_result["steganography_confidence"],
            "steganography_reasons": stego_result["steganography_reasons"]
        }
    except Exception as e:
        logger.error(f"Görsel analizi sırasında hata: {str(e)}")
        return {
            "exif_found": False,
            "gps_found": False,
            "metadata_size_kb": 0,
            "iptc_found": False,
            "xmp_found": False,
            "binary_patterns": {},
            "is_stripped": True,
            "steganography_detected": False,
            "steganography_confidence": 0.0,
            "steganography_reasons": [],
            "error": str(e)
        }


def check_mime_extension_match(filename, mime_type):
    """Dosya uzantısı ile MIME type uyumluluğunu kontrol et"""
    if not filename or mime_type == "unknown":
        return False
    
    # Dosya uzantısını al
    ext = os.path.splitext(filename)[1].lower()
    
    # MIME type ve uzantı eşleşmeleri
    mime_ext_map = {
        'image/jpeg': ['.jpg', '.jpeg'],
        'image/png': ['.png'],
        'image/gif': ['.gif'],
        'image/webp': ['.webp'],
        'image/bmp': ['.bmp'],
        'image/tiff': ['.tiff', '.tif'],
        'image/svg+xml': ['.svg']
    }
    
    if mime_type in mime_ext_map:
        return ext in mime_ext_map[mime_type]
    
    return False


def detect_file_header_type(file_content):
    """Dosya header'ından gerçek dosya türünü tespit et"""
    if len(file_content) < 12:
        return "unknown", False
    
    # Dosya magic number'ları (ilk birkaç byte)
    header = file_content[:12]
    
    # JPEG: FF D8 FF
    if header[:3] == b'\xff\xd8\xff':
        return "image/jpeg", True
    # PNG: 89 50 4E 47 0D 0A 1A 0A
    elif header[:8] == b'\x89PNG\r\n\x1a\n':
        return "image/png", True
    # GIF: 47 49 46 38 (GIF8)
    elif header[:4] == b'GIF8':
        return "image/gif", True
    # BMP: 42 4D (BM)
    elif header[:2] == b'BM':
        return "image/bmp", True
    # WebP: RIFF...WEBP
    elif header[:4] == b'RIFF' and len(file_content) > 8 and file_content[8:12] == b'WEBP':
        return "image/webp", True
    # TIFF: 49 49 2A 00 (II*) veya 4D 4D 00 2A (MM*)
    elif header[:4] == b'II*\x00' or header[:4] == b'MM\x00*':
        return "image/tiff", True
    
    return "unknown", False


def find_file_footer_marker(file_content, file_type):
    """
    Dosya formatına göre bitiş imzasını (footer marker) bul
    
    Args:
        file_content: Dosya içeriği (bytes)
        file_type: Dosya türü (image/jpeg, image/png, vb.)
    
    Returns:
        int: Footer marker'ın bulunduğu index, bulunamazsa -1
    """
    try:
        if file_type == "image/jpeg":
            # JPEG EOI (End of Image) marker: FF D9
            # rfind ile son FF D9 marker'ını bul
            eoi_marker = b'\xff\xd9'
            last_index = file_content.rfind(eoi_marker)
            if last_index != -1:
                # Marker'ın bitiş pozisyonu (FF D9 = 2 byte)
                return last_index + 2
            return -1
        
        elif file_type == "image/png":
            # PNG IEND chunk: 49 45 4E 44 AE 42 60 82
            # IEND chunk'ı dosyanın sonunda olmalı
            iend_marker = b'IEND\xaeB`\x82'
            index = file_content.rfind(iend_marker)
            if index != -1:
                # IEND chunk'ın sonu (chunk size + chunk type + chunk data + CRC = 12 byte)
                return index + 12
            return -1
        
        elif file_type == "image/gif":
            # GIF terminator: 3B (;)
            # GIF89a veya GIF87a formatında dosya sonunda 3B olmalı
            index = file_content.rfind(b'\x3b')
            if index != -1:
                return index + 1
            return -1
        
        elif file_type == "image/bmp":
            # BMP dosyasında boyut header'da belirtilir (offset 2-5)
            # Ama genelde dosya sonunda padding olabilir, kesin bir footer yok
            # Bu durumda header'daki boyutu kontrol ederiz
            if len(file_content) >= 6:
                # BMP header'daki dosya boyutu (little-endian)
                declared_size = struct.unpack('<I', file_content[2:6])[0]
                if declared_size < len(file_content):
                    # Header'daki boyuttan fazla veri var
                    return declared_size
            return -1
        
        elif file_type == "image/webp":
            # WebP RIFF formatı, chunk-based
            # Son chunk'tan sonra veri olmamalı
            # Basit kontrol: RIFF header'ındaki size ile karşılaştır
            if len(file_content) >= 12:
                if file_content[:4] == b'RIFF':
                    # RIFF chunk size (offset 4-7, little-endian)
                    riff_size = struct.unpack('<I', file_content[4:8])[0]
                    # RIFF size + 8 byte (RIFF + size fields) = toplam boyut
                    expected_size = riff_size + 8
                    if expected_size < len(file_content):
                        return expected_size
            return -1
        
        # TIFF için kesin bir footer yok (header-based)
        # Diğer formatlar için de footer kontrolü yapılamaz
        
        return -1
    
    except Exception as e:
        logger.warning(f"Footer marker bulma hatası: {str(e)}")
        return -1


def detect_trailing_payload(file_content):
    """
    Dosya formatının standart bitiş imzasından sonra ekstra veri (payload) olup olmadığını kontrol et
    Bu, dosya isminden bağımsız olarak bir 'Append-Data Malware' olarak işaretlenir
    
    Args:
        file_content: Dosya içeriği (bytes) - binary mode'da okunmuş
    
    Returns:
        dict: Trailing payload tespit sonuçları
    """
    payload_detected = False
    payload_size = 0
    payload_offset = -1
    payload_content = b""
    payload_text = ""
    file_type = "unknown"
    
    try:
        if len(file_content) < 4:
            return {
                "payload_detected": False,
                "payload_size": 0,
                "payload_offset": -1,
                "payload_content": b"",
                "payload_text": "",
                "file_type": "unknown"
            }
        
        # Önce dosya türünü tespit et
        file_type, is_valid = detect_file_header_type(file_content)
        
        # JPEG için özel kontrol (en yaygın kullanım durumu)
        if file_type == "image/jpeg":
            # JPEG EOI marker: FF D9
            eoi_marker = b'\xff\xd9'
            last_eoi_pos = file_content.rfind(eoi_marker)
            
            if last_eoi_pos != -1:
                # EOI marker'ın bitiş pozisyonu
                eoi_end_pos = last_eoi_pos + 2
                
                # EOI marker'dan sonra veri var mı?
                if eoi_end_pos < len(file_content):
                    payload_offset = eoi_end_pos
                    payload_size = len(file_content) - eoi_end_pos
                    payload_content = file_content[eoi_end_pos:]
                    
                    # Payload içeriğini text olarak dene (printable karakterler)
                    try:
                        # Önce UTF-8 olarak dene
                        payload_text = payload_content.decode('utf-8', errors='ignore')
                        # Eğer çok az printable karakter varsa, latin-1 dene
                        printable_count = sum(1 for c in payload_text if c.isprintable() or c in '\n\r\t')
                        if printable_count < len(payload_text) * 0.5:
                            payload_text = payload_content.decode('latin-1', errors='ignore')
                    except:
                        try:
                            payload_text = payload_content.decode('latin-1', errors='ignore')
                        except:
                            payload_text = payload_content.hex()  # Hex olarak göster
                    
                    # Herhangi bir veri varsa payload olarak işaretle (1 byte bile olsa)
                    if payload_size > 0:
                        payload_detected = True
                        logger.warning(f"JPEG Append-Data Malware tespit edildi! Payload boyutu: {payload_size} bytes, Offset: {payload_offset}")
        
        # Diğer formatlar için genel kontrol
        elif is_valid and file_type != "unknown":
            # Footer marker'ı bul
            footer_end_pos = find_file_footer_marker(file_content, file_type)
            
            if footer_end_pos > 0 and footer_end_pos < len(file_content):
                # Footer marker'dan sonra veri var!
                payload_offset = footer_end_pos
                payload_size = len(file_content) - footer_end_pos
                payload_content = file_content[footer_end_pos:]
                
                # Payload içeriğini text olarak dene
                try:
                    payload_text = payload_content.decode('utf-8', errors='ignore')
                    printable_count = sum(1 for c in payload_text if c.isprintable() or c in '\n\r\t')
                    if printable_count < len(payload_text) * 0.5:
                        payload_text = payload_content.decode('latin-1', errors='ignore')
                except:
                    try:
                        payload_text = payload_content.decode('latin-1', errors='ignore')
                    except:
                        payload_text = payload_content.hex()
                
                # Minimum payload boyutu kontrolü (1 byte'dan fazla olmalı)
                if payload_size > 0:
                    payload_detected = True
                    logger.warning(f"Trailing payload tespit edildi! Format: {file_type}, Payload boyutu: {payload_size} bytes, Offset: {payload_offset}")
    
    except Exception as e:
        logger.warning(f"Trailing payload analizi sırasında hata: {str(e)}")
    
    return {
        "payload_detected": payload_detected,
        "payload_size": payload_size,
        "payload_offset": payload_offset,
        "payload_content": payload_content,
        "payload_text": payload_text,
        "file_type": file_type
    }


def detect_trojan_patterns(file_content, mime_type="unknown"):
    """
    Static Malware Carrier Detection - Professional Analysis Layers
    
    Analyzes file structure without execution:
    - Executable signatures anywhere in file (MZ/PE headers)
    - Script & command patterns (powershell, cmd.exe, whoami, IEX, base64)
    - Polyglot file detection (multiple format headers)
    - Entropy & size anomalies
    - Execution intent heuristics
    
    Returns:
        dict: Detection results with risk_score (0-100), indicators, etc.
    """
    trojan_detected = False
    risk_score = 0
    trojan_reasons = []
    detected_indicators = []
    execution_chains = []
    polyglot_detected = False
    
    try:
        # Scan first 2MB for performance
        max_bytes_to_check = min(2 * 1024 * 1024, len(file_content))
        content_to_check = file_content[:max_bytes_to_check]
        content_lower = content_to_check.lower()
        
        # Detect file header type
        detected_header_type, _ = detect_file_header_type(file_content)
        is_non_executable_mime = mime_type.startswith('image/') or mime_type in ['application/pdf', 'application/zip']
        
        # ===== 1. EXECUTABLE SIGNATURE DETECTION (High Weight: +35) =====
        
        # 1.1 MZ Header (DOS Executable) - 4D 5A (MZ) - Check anywhere, not just offset 0
        mz_pattern = b'MZ'
        mz_positions = []
        offset = 0
        while True:
            pos = content_to_check.find(mz_pattern, offset)
            if pos == -1:
                break
            mz_positions.append(pos)
            offset = pos + 1
            if len(mz_positions) >= 10:
                break
        
        # 1.2 PE Signature - 50 45 00 00 (PE\0\0) - Check anywhere
        pe_pattern = b'PE\x00\x00'
        pe_positions = []
        offset = 0
        while True:
            pos = content_to_check.find(pe_pattern, offset)
            if pos == -1:
                break
            pe_positions.append(pos)
            offset = pos + 1
            if len(pe_positions) >= 10:
                break
        
        # If MZ or PE found inside non-executable MIME types, mark as "Executable Container Abuse"
        if (mz_positions or pe_positions) and is_non_executable_mime:
            trojan_detected = True
            risk_score += 35
            indicator_name = "Executable Container Abuse"
            detected_indicators.append(indicator_name)
            
            if mz_positions:
                trojan_reasons.append(f"MZ header found inside {mime_type} ({len(mz_positions)} occurrences)")
            if pe_positions:
                trojan_reasons.append(f"PE signature found inside {mime_type} ({len(pe_positions)} occurrences)")
            
            logger.warning(f"Executable Container Abuse: PE/MZ signatures found in non-executable file type ({mime_type})")
        elif mz_positions or pe_positions:
            trojan_detected = True
            risk_score += 35
            if mz_positions:
                detected_indicators.append("MZ Header (DOS Executable)")
                trojan_reasons.append(f"MZ header found ({len(mz_positions)} occurrences)")
            if pe_positions:
                detected_indicators.append("PE Executable (Windows)")
                trojan_reasons.append(f"PE signature found ({len(pe_positions)} occurrences)")
        
        # 1.3 DOS Mode String - "This program cannot be run in DOS mode"
        dos_mode_string = b'This program cannot be run in DOS mode'
        if dos_mode_string in content_to_check:
            trojan_detected = True
            risk_score += 40
            detected_indicators.append("DOS Mode String (Windows EXE)")
            trojan_reasons.append("Windows executable DOS mode string bulundu")
            logger.warning("DOS mode string bulundu!")
        
        # 1.4 ELF Signature - 7F 45 4C 46 (ELF)
        elf_pattern = b'\x7fELF'
        elf_positions = []
        offset = 0
        while True:
            pos = content_to_check.find(elf_pattern, offset)
            if pos == -1:
                break
            elf_positions.append(pos)
            offset = pos + 1
            if len(elf_positions) >= 10:
                break
        
        if elf_positions:
            trojan_detected = True
            risk_score += 40
            detected_indicators.append("ELF Executable (Linux/Unix)")
            trojan_reasons.append(f"Linux/Unix executable (ELF) imzası bulundu ({len(elf_positions)} adet)")
            logger.warning(f"ELF signature bulundu! Offset'ler: {elf_positions[:5]}")
        
        # 1.5 Mach-O Signature - FE ED FA CE (macOS/iOS)
        macho_patterns = [
            b'\xfe\xed\xfa\xce',  # 32-bit big-endian
            b'\xce\xfa\xed\xfe',  # 32-bit little-endian
            b'\xfe\xed\xfa\xcf',  # 64-bit big-endian
            b'\xcf\xfa\xed\xfe',  # 64-bit little-endian
        ]
        
        for macho_pattern in macho_patterns:
            if macho_pattern in content_to_check:
                trojan_detected = True
                risk_score += 40
                detected_indicators.append("Mach-O Executable (macOS/iOS)")
                trojan_reasons.append("macOS/iOS executable (Mach-O) imzası bulundu")
                logger.warning("Mach-O signature bulundu!")
                break
        
        # ===== 2. SCRIPT & COMMAND PATTERN DETECTION (+20) =====
        
        execution_intent_detected = False
        
        # Suspicious command strings
        suspicious_commands = [
            b'powershell', b'PowerShell', b'powershell.exe',
            b'cmd.exe', b'cmd /c',
            b'whoami',
            b'IEX', b'Invoke-Expression',
            b'base64',
            b'curl', b'wget',
            b'Invoke-WebRequest', b'DownloadString',
        ]
        
        command_matches = []
        for cmd in suspicious_commands:
            if cmd in content_lower:
                command_matches.append(cmd.decode('utf-8', errors='ignore'))
                trojan_detected = True
        
        if command_matches:
            risk_score += 20
            detected_indicators.append("Suspicious Command Patterns")
            trojan_reasons.append(f"Command patterns detected: {', '.join(command_matches[:5])}")
            execution_intent_detected = True
            logger.warning(f"Suspicious command patterns found: {command_matches[:5]}")
        
        # ===== 3. POLYGLOT FILE DETECTION (+15) =====
        
        # Check for multiple format headers
        format_headers_detected = []
        
        # Check for image headers
        if content_to_check[:3] == b'\xff\xd8\xff':
            format_headers_detected.append("JPEG")
        if content_to_check[:8] == b'\x89PNG\r\n\x1a\n':
            format_headers_detected.append("PNG")
        if content_to_check[:4] == b'GIF8':
            format_headers_detected.append("GIF")
        if content_to_check[:2] == b'BM':
            format_headers_detected.append("BMP")
        
        # If we have image header + executable signature, it's polyglot
        if format_headers_detected and (mz_positions or pe_positions):
            polyglot_detected = True
            trojan_detected = True
            risk_score += 15
            detected_indicators.append("Polyglot / Trojan Carrier")
            trojan_reasons.append(f"Polyglot file detected: {format_headers_detected[0]} header + executable signature")
            logger.warning(f"Polyglot file detected: {format_headers_detected[0]} + executable signature")
        
        # ===== 4. ENTROPY & SIZE ANOMALY ANALYSIS (+10) =====
        # This is handled separately in detect_malware_dropper function
        
        # ===== 5. EXECUTION INTENT HEURISTIC (+10) =====
        
        # If file contains execution keywords but is non-executable MIME type
        if execution_intent_detected and is_non_executable_mime:
            risk_score += 10
            detected_indicators.append("Dormant Trojan Loader")
            trojan_reasons.append("Execution intent detected in non-executable file format")
            logger.warning("Execution intent heuristic: execution keywords in non-executable file")
        
        # ===== FINAL RISK SCORE CALCULATION =====
        
        # Cap risk score at 100
        risk_score = min(100, risk_score)
        
        # Determine risk level based on new scale
        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 20:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Confidence = risk_score / 100
        trojan_confidence = min(1.0, risk_score / 100.0) if risk_score > 0 else 0.0
        
        if trojan_detected:
            logger.warning(f"Static Risk Assessment: Risk score {risk_score}/100, Level: {risk_level}")
            logger.warning(f"Detected indicators: {detected_indicators}")
    
    except Exception as e:
        logger.warning(f"Trojan pattern analizi sırasında hata: {str(e)}")
    
    return {
        "trojan_detected": trojan_detected,
        "trojan_confidence": round(trojan_confidence, 2),
        "trojan_risk_score": risk_score,
        "trojan_risk_level": risk_level,
        "trojan_reasons": trojan_reasons,
        "detected_patterns": detected_indicators,
        "execution_chains": execution_chains,
        "polyglot_detected": polyglot_detected
    }


def calculate_entropy(file_content):
    """
    Dosyanın entropi değerini hesapla (0-8 arası)
    Yüksek entropi -> şifrelenmiş veya sıkıştırılmış içerik olabilir
    """
    try:
        if len(file_content) == 0:
            return 0.0
        
        # İlk 1MB'ı kullan (performans için)
        sample_size = min(1024 * 1024, len(file_content))
        sample = file_content[:sample_size]
        
        # Byte frekanslarını hesapla
        byte_counts = {}
        for byte in sample:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Entropi hesapla: H = -Σ(p(x) * log2(p(x)))
        sample_len = len(sample)
        
        # Shannon entropy formülü
        entropy = sum(-(count / sample_len) * math.log2(count / sample_len) 
                     for count in byte_counts.values() if count > 0)
        
        return round(entropy, 2)
    except Exception as e:
        logger.warning(f"Entropi hesaplama hatası: {str(e)}")
        return 0.0


def detect_malware_dropper(image, file_size_bytes, entropy):
    """
    Malware dropper (taşıyıcı) olasılığını tespit et
    Dosya boyutu / çözünürlük oranını ve entropy'yi kontrol et
    
    Returns:
        dict: Malware dropper tespit sonuçları
    """
    dropper_detected = False
    dropper_confidence = 0.0
    dropper_reasons = []
    
    try:
        if not image or not image.size:
            return {
                "dropper_detected": False,
                "dropper_confidence": 0.0,
                "dropper_reasons": []
            }
        
        width, height = image.size
        pixel_count = width * height
        
        if pixel_count == 0:
            return {
                "dropper_detected": False,
                "dropper_confidence": 0.0,
                "dropper_reasons": []
            }
        
        # Beklenen dosya boyutunu hesapla
        if image.mode == 'RGB':
            expected_size = pixel_count * 3
        elif image.mode == 'RGBA':
            expected_size = pixel_count * 4
        elif image.mode == 'L':
            expected_size = pixel_count
        else:
            expected_size = pixel_count * 3
        
        # Sıkıştırma faktörü (JPEG için ~0.1, PNG için ~0.5-0.8)
        compression_factor = 0.15  # Ortalama
        
        expected_file_size = expected_size * compression_factor
        
        # 1. Dosya boyutu / çözünürlük oranı kontrolü
        if expected_file_size > 0:
            size_ratio = file_size_bytes / expected_file_size
            
            # Dosya boyutu beklenenden 3x'den fazla büyükse şüpheli
            if size_ratio > 3.0:
                dropper_detected = True
                dropper_confidence += 0.5
                dropper_reasons.append(f"Dosya boyutu beklenenden {size_ratio:.1f}x daha büyük (anormal)")
                logger.warning(f"Anormal dosya boyutu oranı: {size_ratio:.2f}x")
            
            # 2. Entropi kontrolü (yüksek entropy -> şifrelenmiş/sıkıştırılmış içerik)
            # Görsel dosyaları için normal entropy: 6-7.5 arası
            # 7.5'ten yüksek entropy -> şüpheli içerik olabilir
            if entropy > 7.5:
                dropper_detected = True
                dropper_confidence += 0.4
                dropper_reasons.append(f"Yüksek entropy değeri ({entropy:.2f}) - şifrelenmiş veya sıkıştırılmış içerik olabilir")
                logger.warning(f"Yüksek entropy tespit edildi: {entropy:.2f}")
            
            # 3. Her ikisi de anormal ise çok yüksek risk
            if size_ratio > 3.0 and entropy > 7.5:
                dropper_confidence = min(1.0, dropper_confidence + 0.3)
                dropper_reasons.append("Hem dosya boyutu hem entropy anormal - yüksek malware taşıyıcı riski")
        
        # Güven skorunu normalize et
        dropper_confidence = min(1.0, dropper_confidence)
        
        if dropper_detected:
            logger.warning(f"Malware dropper şüphesi: {dropper_reasons}")
    
    except Exception as e:
        logger.warning(f"Malware dropper analizi sırasında hata: {str(e)}")
    
    return {
        "dropper_detected": dropper_detected,
        "dropper_confidence": round(dropper_confidence, 2),
        "dropper_reasons": dropper_reasons
    }


def create_threat_detection_summary(
    file_type_fake, trojan_detected, trojan_confidence, trojan_reasons,
    dropper_detected, dropper_confidence, dropper_reasons,
    steganography_detected, steganography_confidence, steganography_reasons,
    gps_found, metadata_size_kb, payload_detected=False, payload_size=0, payload_file_type="unknown", payload_text="",
    trojan_risk_score=0, trojan_risk_level="low", trojan_patterns=None, execution_chains=None, polyglot_detected=False
):
    """
    Tüm tehdit tespitlerini birleştir ve kullanıcı dostu özet oluştur
    
    Returns:
        list: Tehdit tespit listesi
    """
    threats = []
    
    # 1. Dosya Türü Sahteciliği
    if file_type_fake:
        threats.append({
            "threat_name": "Dosya Türü Sahteciliği",
            "risk_level": "high",
            "description": "Dosya uzantısı ile gerçek dosya türü (MIME/header) uyuşmuyor. Bu, zararlı dosyaların görsel dosyası gibi gizlenmesinde kullanılan bir yöntemdir.",
            "technical_details": "Dosya uzantısı bir görsel formatını gösteriyor ancak dosya header'ı farklı bir türü işaret ediyor.",
            "real_world_usage": "Saldırganlar zararlı dosyaları .jpg veya .png uzantısıyla gizleyerek kullanıcıların yanlışlıkla çalıştırmasını hedefler."
        })
    
    # 2. Static Risk Assessment - Trojan Carrier Detection
    if trojan_detected:
        trojan_risk_score_param = trojan_risk_score if trojan_risk_score is not None else 0
        trojan_risk_level_param = trojan_risk_level if trojan_risk_level is not None else "low"
        trojan_patterns_param = trojan_patterns if trojan_patterns is not None else []
        execution_chains_param = execution_chains if execution_chains is not None else []
        
        # Map risk level (critical -> high for UI compatibility)
        if trojan_risk_level_param == "critical":
            threat_risk_level = "high"
        else:
            threat_risk_level = trojan_risk_level_param
        
        # Build indicators text
        indicators_list = list(trojan_patterns_param) if trojan_patterns_param else []
        indicators_text = "\n".join(f"• {ind}" for ind in indicators_list) if indicators_list else "Structural indicators detected"
        
        details_text = "\n".join(f"• {reason}" for reason in trojan_reasons) if trojan_reasons else "Details not available"
        
        if execution_chains_param:
            details_text += "\n\nExecution Chains:\n" + "\n".join(f"• {ec}" for ec in execution_chains_param)
        
        # Determine threat name based on detection
        if polyglot_detected:
            threat_name = "⚠️ High-Risk Polyglot File"
        else:
            threat_name = "⚠️ Trojan Carrier Detected (Static Analysis)"
        
        threat_description = (
            f"Static risk assessment indicates this file may contain trojan payload. "
            f"File structure resembles malware carrier (dropper/loader). "
            f"Risk Score: {trojan_risk_score_param}/100. "
            f"This analysis was performed without executing the file."
        )
        
        threats.append({
            "threat_name": threat_name,
            "risk_level": threat_risk_level,
            "description": threat_description,
            "technical_details": f"Detected Indicators:\n{indicators_text}\n\nDetails:\n{details_text}",
            "real_world_usage": (
                "Attackers hide malicious code inside image, PDF, or document files. "
                "These files may extract and execute payloads when opened or under specific conditions. "
                "This analysis is static-only - the file was not executed."
            ),
            "analysis_type": "Static Risk Assessment",
            "file_executed": False,
            "active_malware_behavior": "Not detected (static analysis only)"
        })
    
    # 3. Entropy & Size Anomaly Analysis
    if dropper_detected:
        risk_level = "high" if dropper_confidence >= 0.7 else "medium"
        threats.append({
            "threat_name": "Entropy & Size Anomaly",
            "risk_level": risk_level,
            "description": f"File size and entropy analysis indicates potential malware carrier structure. Confidence: {int(dropper_confidence * 100)}%",
            "technical_details": "; ".join(dropper_reasons) if dropper_reasons else "Abnormal file structure detected",
            "real_world_usage": "Attackers hide malware in image files. When opened, malicious code may be extracted and executed."
        })
    
    # 4. Steganografi Şüphesi
    if steganography_detected:
        risk_level = "high" if steganography_confidence >= 0.7 else "medium"
        threats.append({
            "threat_name": "Steganografi Şüphesi",
            "risk_level": risk_level,
            "description": f"Görsel dosyasında steganografi (gizli mesaj gizleme) teknikleri tespit edildi. Güven: %{int(steganography_confidence * 100)}",
            "technical_details": "; ".join(steganography_reasons) if steganography_reasons else "Steganografi pattern'leri bulundu",
            "real_world_usage": "Saldırganlar gizli bilgileri, şifreleri veya zararlı kodları görsellerin içine gizleyerek iletebilir."
        })
    
    # 5. Metadata & Gizlilik Riski
    if gps_found or metadata_size_kb > 10:
        risk_level = "high" if gps_found else "medium"
        threats.append({
            "threat_name": "Gizlilik & Metadata Riski",
            "risk_level": risk_level,
            "description": "Görsel dosyasında kişisel bilgiler içeren metadata bulundu. GPS konum bilgisi, cihaz bilgileri veya çekim tarihi gibi hassas veriler paylaşıldığında gizlilik riski oluşturur.",
            "technical_details": f"GPS konum bilgisi: {'Var' if gps_found else 'Yok'}, Metadata boyutu: {metadata_size_kb:.2f} KB",
            "real_world_usage": "Metadata bilgileri paylaşıldığında, saldırganlar konum bilgisi, cihaz modeli ve çekim tarihi gibi kişisel bilgilere erişebilir."
        })
    
    # 6. Append-Data Malware (Trailing Payload)
    if payload_detected:
        # Payload text içeriğini hazırla (ilk 500 karakter, daha fazlası için truncate)
        payload_display = payload_text[:500] if payload_text and len(payload_text) > 500 else (payload_text or "")
        if payload_text and len(payload_text) > 500:
            payload_display += f"\n... (toplam {len(payload_text)} karakter, ilk 500 karakter gösteriliyor)"
        
        threat_obj = {
            "threat_name": "Append-Data Malware",
            "risk_level": "high",
            "description": f"{payload_file_type} formatının standart bitiş imzasından sonra {payload_size} byte ekstra veri (payload) tespit edildi. Bu, dosya isminden bağımsız olarak zararlı içerik taşıyabileceğini gösterir.",
            "technical_details": f"Dosya formatı: {payload_file_type}, Payload boyutu: {payload_size} bytes, Dosya formatının bitiş imzasından sonra ekstra veri bulundu.",
            "real_world_usage": "Saldırganlar zararlı kodları, şifreleri veya diğer zararlı içerikleri görsel dosyalarının sonuna ekleyerek gizler. Normal görüntüleyiciler bu ekstra veriyi görmezden gelir, ancak özel araçlarla çıkarılabilir.",
        }
        
        # Tespit edilen zararlı imza (payload içeriği)
        if payload_text:
            threat_obj["detected_signature"] = payload_display
        else:
            threat_obj["detected_signature"] = f"(Binary veri - {payload_size} byte)"
        
        threats.append(threat_obj)
    
    return threats


def detect_steganography(image, file_size_bytes):
    """
    Steganografi (gizli mesaj) tespiti yap
    
    Args:
        image: PIL Image objesi
        file_size_bytes: Dosya boyutu (bytes)
    
    Returns:
        dict: Steganografi analiz sonuçları
    """
    stego_detected = False
    stego_confidence = 0.0
    stego_reasons = []
    
    try:
        # Büyük dosyalar için analizi sınırla (performans için)
        max_pixels_to_check = 50000  # Maksimum kontrol edilecek piksel sayısı
        
        # 1. LSB (Least Significant Bit) analizi - Optimize edilmiş
        if image.mode in ('RGB', 'RGBA', 'L'):
            # Büyük görseller için resize yap (hız için)
            width, height = image.size
            pixel_count = width * height
            
            if pixel_count > max_pixels_to_check:
                # Büyük görselleri küçült (hız için)
                scale_factor = (max_pixels_to_check / pixel_count) ** 0.5
                new_width = int(width * scale_factor)
                new_height = int(height * scale_factor)
                image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
                logger.info(f"Görsel analiz için küçültüldü: {width}x{height} -> {new_width}x{new_height}")
            
            pixels = list(image.getdata())
            if len(pixels) > 0:
                # İlk 500 pikselin LSB'lerini kontrol et (daha hızlı)
                sample_size = min(500, len(pixels))
                sample_pixels = pixels[:sample_size]
                
                if image.mode == 'L':  # Grayscale
                    lsb_values = [p & 1 for p in sample_pixels]
                else:  # RGB/RGBA
                    lsb_values = []
                    for pixel in sample_pixels:
                        if isinstance(pixel, tuple):
                            lsb_values.extend([p & 1 for p in pixel[:3]])
                        else:
                            lsb_values.append(pixel & 1)
                
                if lsb_values:
                    # LSB dağılımını kontrol et (steganografi'de genelde düzensiz olur)
                    zero_count = lsb_values.count(0)
                    one_count = lsb_values.count(1)
                    total = len(lsb_values)
                    
                    if total > 0:
                        zero_ratio = zero_count / total
                        # Normal görsellerde LSB'ler yaklaşık %50-50 dağılır
                        # Steganografi'de bu oran anormal olabilir
                        if zero_ratio < 0.3 or zero_ratio > 0.7:
                            stego_detected = True
                            stego_confidence += 0.3
                            stego_reasons.append("LSB analizi anomali tespit etti")
        
        # 2. Dosya boyutu anomalisi kontrolü
        # Görsel boyutuna göre dosya boyutu beklenenden büyükse steganografi olabilir
        if image.size:
            width, height = image.size
            pixel_count = width * height
            
            # Beklenen dosya boyutu (yaklaşık)
            if image.mode == 'RGB':
                expected_size = pixel_count * 3  # RGB = 3 byte/pixel
            elif image.mode == 'RGBA':
                expected_size = pixel_count * 4  # RGBA = 4 byte/pixel
            elif image.mode == 'L':
                expected_size = pixel_count  # Grayscale = 1 byte/pixel
            else:
                expected_size = pixel_count * 3
            
            # Sıkıştırma faktörü (JPEG/PNG için)
            compression_factor = 0.1  # Genelde %10-20 sıkıştırma olur
            
            if expected_size > 0:
                expected_file_size = expected_size * compression_factor
                # Dosya boyutu beklenenden %50'den fazla büyükse şüpheli
                if file_size_bytes > expected_file_size * 1.5:
                    stego_detected = True
                    stego_confidence += 0.4
                    stego_reasons.append("Dosya boyutu beklenenden anormal büyük")
        
        # 3. Entropi analizi (basit) - Optimize edilmiş
        # Steganografi içeren görsellerde entropi farklı olabilir
        if image.mode in ('RGB', 'RGBA', 'L'):
            pixels = list(image.getdata())
            if len(pixels) > 100:
                # Sadece ilk 200 pikseli kontrol et (daha hızlı)
                value_counts = {}
                for pixel in pixels[:200]:  # İlk 200 piksel
                    if isinstance(pixel, tuple):
                        for val in pixel[:3]:
                            value_counts[val] = value_counts.get(val, 0) + 1
                    else:
                        value_counts[pixel] = value_counts.get(pixel, 0) + 1
                
                # Çok az farklı değer varsa şüpheli (steganografi işareti olabilir)
                unique_values = len(value_counts)
                if unique_values < 10 and len(pixels) > 100:
                    stego_detected = True
                    stego_confidence += 0.3
                    stego_reasons.append("Düşük entropi tespit edildi")
        
        # Güven skorunu normalize et (0-1 arası)
        stego_confidence = min(1.0, stego_confidence)
        
    except Exception as e:
        logger.warning(f"Steganografi analizi sırasında hata: {str(e)}")
    
    return {
        "steganography_detected": stego_detected,
        "steganography_confidence": round(stego_confidence, 2),
        "steganography_reasons": stego_reasons
    }


@app.post("/analyze/image")
async def analyze_image(file: UploadFile = File(...)):
    """
    Görsel analizi endpoint'i (Seviye 2 - EXIF ve metadata analizi)
    
    Args:
        file: Analiz edilecek görsel dosyası (multipart/form-data)
    
    Returns:
        dict: Analiz sonuçları (her durumda JSON response)
    """
    logger.info("=== /analyze/image endpoint çağrıldı ===")
    
    # Varsayılan response (hata durumunda kullanılacak)
    default_response = {
        "status": "error",
        "risk_score": 0,
        "message": "Analiz sırasında bir hata oluştu",
        "details": {}
    }
    
    try:
        logger.info("Dosya alınıyor...")
        # Dosya içeriğini oku
        file_content = await file.read()
        logger.info(f"Dosya başarıyla okundu, boyut: {len(file_content)} bytes")
        
        file_size_bytes = len(file_content)
        file_size_kb = round(file_size_bytes / 1024, 2)
        
        # Dosya bilgilerini çıkar
        filename = file.filename or "unknown"
        mime_type = file.content_type or "unknown"
        logger.info(f"Dosya bilgileri - Filename: {filename}, MIME: {mime_type}, Size: {file_size_kb} KB")
        
        logger.info("SHA256 hash hesaplanıyor...")
        # SHA256 hash hesapla
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        logger.info("SHA256 hash hesaplandı")
        
        # Risk skoru hesapla (başlangıç: 0)
        risk_score = 0
        
        # Dosya boyutu > 5MB ise risk +20
        if file_size_bytes > 5 * 1024 * 1024:  # 5MB = 5 * 1024 * 1024 bytes
            risk_score += 20
            logger.info("Dosya boyutu > 5MB, risk +20")
        
        # MIME type image/* değilse risk +50
        if not mime_type.startswith('image/'):
            risk_score += 50
            logger.info("MIME type image/* değil, risk +50")
        
        logger.info("Analiz fonksiyonu başlatılıyor...")
        # EXIF metadata ve steganografi analizi (timeout ile)
        exif_found = False
        gps_found = False
        metadata_size_kb = 0
        exif_details = {}
        steganography_detected = False
        steganography_confidence = 0.0
        steganography_reasons = []
        
        try:
            # 20 saniye timeout ile derinlemesine analiz yap (daha hızlı response için)
            analysis_result = await asyncio.wait_for(
                analyze_image_sync(file_content, filename, mime_type, file_size_bytes),
                timeout=20.0
            )
            logger.info("Derinlemesine analiz fonksiyonu başarıyla tamamlandı")
            
            exif_found = analysis_result.get("exif_found", False)
            gps_found = analysis_result.get("gps_found", False)
            metadata_size_kb = analysis_result.get("metadata_size_kb", 0)
            exif_details = analysis_result.get("exif_details", {})
            iptc_found = analysis_result.get("iptc_found", False)
            xmp_found = analysis_result.get("xmp_found", False)
            binary_patterns = analysis_result.get("binary_patterns", {})
            is_stripped = analysis_result.get("is_stripped", False)
            steganography_detected = analysis_result.get("steganography_detected", False)
            steganography_confidence = analysis_result.get("steganography_confidence", 0.0)
            steganography_reasons = analysis_result.get("steganography_reasons", [])
            
            if analysis_result.get("error"):
                logger.warning(f"Analiz sırasında uyarı: {analysis_result['error']}")
            
            if exif_found:
                # Metadata boyutu anormal mi? (> 50 KB)
                if metadata_size_kb > 50:
                    risk_score += 25
                    logger.info(f"Metadata anormal boyutta ({metadata_size_kb} KB), risk +25")
                
                # GPS bilgisi var mı?
                if gps_found:
                    risk_score += 30
                    logger.info("GPS bilgisi bulundu, risk +30")
            
            # Steganografi tespiti risk skorunu etkiler
            if steganography_detected:
                # Güven skoruna göre risk ekle (0-50 arası)
                stego_risk = int(steganography_confidence * 50)
                risk_score += stego_risk
                logger.info(f"Steganografi tespit edildi (güven: {steganography_confidence}), risk +{stego_risk}")
        
        except asyncio.TimeoutError:
            logger.error("Analiz timeout (20 saniye aşıldı) - Basit response dönülüyor")
            # Timeout durumunda bile basit bir response dön
            exif_found = False
            gps_found = False
            metadata_size_kb = 0
            exif_details = {
                "device_info": {},
                "capture_info": {},
                "location_info": {},
                "camera_settings": {},
                "software_info": {},
                "metadata_layers": {}
            }
            iptc_found = False
            xmp_found = False
            binary_patterns = {}
            is_stripped = True
            steganography_detected = False
            steganography_confidence = 0.0
            steganography_reasons = []
            trojan_detected = False
            trojan_confidence = 0.0
            trojan_reasons = []
            dropper_detected = False
            dropper_confidence = 0.0
            dropper_reasons = []
            entropy = 0.0
            # Risk skorunu hesapla (timeout durumunda bile)
            risk_score = 0
            risk_level = "low"
            # Timeout durumunda bile devam et, response dön
        except Exception as exif_error:
            logger.error(f"Analiz hatası: {str(exif_error)}", exc_info=True)
            # Hata durumunda bile response dön
            exif_found = False
            gps_found = False
            metadata_size_kb = 0
            exif_details = {
                "device_info": {},
                "capture_info": {},
                "location_info": {},
                "camera_settings": {},
                "software_info": {},
                "metadata_layers": {}
            }
            iptc_found = False
            xmp_found = False
            binary_patterns = {}
            is_stripped = True
            steganography_detected = False
            steganography_confidence = 0.0
            steganography_reasons = []
            trojan_detected = False
            trojan_confidence = 0.0
            trojan_reasons = []
            dropper_detected = False
            dropper_confidence = 0.0
            dropper_reasons = []
            entropy = 0.0
            payload_detected = False
            payload_size = 0
            payload_file_type = "unknown"
            payload_text = ""
        
        # MIME type ve dosya uzantısı uyumluluğu kontrolü
        logger.info("MIME type ve uzantı uyumluluğu kontrol ediliyor...")
        mime_match = check_mime_extension_match(filename, mime_type)
        file_type_fake = False
        
        # Dosya header kontrolü (gerçek dosya türü)
        actual_file_type, header_valid = detect_file_header_type(file_content)
        if not header_valid or actual_file_type != mime_type:
            file_type_fake = True
            logger.warning(f"Dosya türü sahteciliği tespit edildi! Uzantı: {filename}, MIME: {mime_type}, Header: {actual_file_type}")
        
        if not mime_match:
            risk_score += 40
            file_type_fake = True
            logger.info("MIME type ve uzantı uyumsuz, risk +40")
        
        # Static Malware Carrier Detection
        logger.info("Static malware carrier detection yapılıyor...")
        trojan_result = detect_trojan_patterns(file_content, mime_type)
        trojan_detected = trojan_result["trojan_detected"]
        trojan_confidence = trojan_result["trojan_confidence"]
        trojan_risk_score = trojan_result.get("trojan_risk_score", 0)
        trojan_risk_level = trojan_result.get("trojan_risk_level", "low")
        trojan_reasons = trojan_result["trojan_reasons"]
        trojan_patterns = trojan_result.get("detected_patterns", [])
        execution_chains = trojan_result.get("execution_chains", [])
        polyglot_detected = trojan_result.get("polyglot_detected", False)
        
        if trojan_detected:
            # Add trojan risk score to main risk score (max 50 points to avoid over-scoring)
            risk_score += min(50, trojan_risk_score)
            logger.warning(f"Static Risk Assessment: Risk score {trojan_risk_score}/100, Level: {trojan_risk_level}")
        
        # Entropi hesaplama
        logger.info("Entropi hesaplanıyor...")
        entropy = calculate_entropy(file_content)
        logger.info(f"Entropi: {entropy:.2f}")
        
        # Malware dropper detection
        logger.info("Malware dropper kontrolü yapılıyor...")
        image_for_dropper = None
        try:
            loop = asyncio.get_event_loop()
            image_for_dropper = await loop.run_in_executor(None, Image.open, io.BytesIO(file_content))
        except:
            pass
        
        dropper_result = {"dropper_detected": False, "dropper_confidence": 0.0, "dropper_reasons": []}
        if image_for_dropper:
            dropper_result = detect_malware_dropper(image_for_dropper, file_size_bytes, entropy)
            dropper_detected = dropper_result["dropper_detected"]
            dropper_confidence = dropper_result["dropper_confidence"]
            dropper_reasons = dropper_result["dropper_reasons"]
            
            if dropper_detected:
                risk_score += int(dropper_confidence * 40)
                logger.warning(f"Malware dropper şüphesi, güven: {dropper_confidence}")
        else:
            dropper_detected = False
            dropper_confidence = 0.0
            dropper_reasons = []
        
        # Trailing payload kontrolü (Append-Data Malware)
        logger.info("Trailing payload kontrolü yapılıyor (JPEG FF D9 kontrolü)...")
        payload_result = detect_trailing_payload(file_content)
        payload_detected = payload_result["payload_detected"]
        payload_size = payload_result["payload_size"]
        payload_file_type = payload_result["file_type"]
        payload_text = payload_result.get("payload_text", "")
        
        if payload_detected:
            risk_score = 90  # Risk skorunu 90'a çıkar (yüksek öncelikli tehdit)
            logger.warning(f"Append-Data Malware tespit edildi! Format: {payload_file_type}, Boyut: {payload_size} bytes")
        
        # Tehdit tespit özeti oluştur
        threats = create_threat_detection_summary(
            file_type_fake, trojan_detected, trojan_confidence, trojan_reasons,
            dropper_detected, dropper_confidence, dropper_reasons,
            steganography_detected, steganography_confidence, steganography_reasons,
            gps_found, metadata_size_kb, payload_detected, payload_size, payload_file_type, payload_text,
            trojan_risk_score=trojan_risk_score, trojan_risk_level=trojan_risk_level,
            trojan_patterns=trojan_patterns, execution_chains=execution_chains,
            polyglot_detected=polyglot_detected
        )
        
        # Risk skorunu 0-100 arasında sınırla
        risk_score = min(100, max(0, risk_score))
        
        # Risk seviyesini belirle
        if risk_score >= 70:
            risk_level = "high"
        elif risk_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        logger.info(f"Risk skoru: {risk_score}/100, Seviye: {risk_level}, Tehdit sayısı: {len(threats)}")
        logger.info("Response hazırlanıyor...")
        
        # Başarılı response
        response = {
            "status": "success",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "message": "Deep image privacy and threat analysis completed",
            "threats": threats,
            "details": {
                "filename": filename,
                "size_kb": file_size_kb,
                "mime_type": mime_type,
                "actual_file_type": actual_file_type,
                "file_type_fake": file_type_fake,
                "sha256": sha256_hash,
                "entropy": entropy,
                "exif_found": exif_found,
                "gps_found": gps_found,
                "iptc_found": iptc_found,
                "xmp_found": xmp_found,
                "binary_patterns": binary_patterns,
                "is_stripped": is_stripped,
                "metadata_size_kb": metadata_size_kb,
                "exif_details": exif_details,
                "steganography_detected": steganography_detected,
                "steganography_confidence": steganography_confidence,
                "steganography_reasons": steganography_reasons,
                "trojan_detected": trojan_detected,
                "trojan_confidence": trojan_confidence,
                "trojan_risk_score": trojan_risk_score,
                "trojan_risk_level": trojan_risk_level,
                "trojan_reasons": trojan_reasons,
                "trojan_patterns": trojan_patterns,
                "execution_chains": execution_chains,
                "polyglot_detected": polyglot_detected,
                "dropper_detected": dropper_detected,
                "dropper_confidence": dropper_confidence,
                "dropper_reasons": dropper_reasons,
                "payload_detected": payload_detected,
                "payload_size": payload_size,
                "payload_file_type": payload_file_type
            }
        }
        
        logger.info("Response dönülüyor (success)")
        return response
    
    except Exception as e:
        logger.error(f"Endpoint genel hatası: {str(e)}", exc_info=True)
        # Hata durumunda bile HTTP 200 ile JSON dön
        error_response = {
            "status": "error",
            "risk_score": 0,
            "message": f"Analiz sırasında hata oluştu: {str(e)}",
            "details": {
                "error_type": type(e).__name__
            }
        }
        logger.info("Response dönülüyor (error)")
        return error_response


# ===== DOSYA ANALİZİ - MALWARE SANDBOX SİSTEMİ =====

# Servis import'ları
try:
    from services.static_analyzer import StaticAnalyzer
    from services.docker_sandbox import DockerSandbox
    from services.quarantine_log import QuarantineLog
    SERVICES_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Services not available: {str(e)}")
    SERVICES_AVAILABLE = False
    # Dummy classes
    class StaticAnalyzer:
        pass
    class DockerSandbox:
        pass
    class QuarantineLog:
        pass

# Quarantine log instance
quarantine_log = QuarantineLog() if SERVICES_AVAILABLE else None
docker_sandbox = DockerSandbox() if SERVICES_AVAILABLE else None


@app.post("/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    """
    Dosya Analizi Endpoint'i - Profesyonel Malware Sandbox
    
    Dosyayı Docker sandbox içinde izole şekilde analiz eder:
    - Statik analiz: Hash, strings, file type, entropy, PE/ELF analizi
    - Dinamik analiz: Docker içinde çalıştırma, davranış takibi
    
    Args:
        file: Analiz edilecek dosya (multipart/form-data)
    
    Returns:
        dict: Analiz sonuçları ve karantina günlüğü kaydı
    """
    logger.info("=== /analyze/file endpoint çağrıldı ===")
    
    if not SERVICES_AVAILABLE:
        return {
            "status": "error",
            "message": "Analiz servisleri yüklenemedi",
            "risk_score": 0
        }
    
    temp_file_path = None
    try:
        # Dosyayı geçici olarak kaydet
        file_content = await file.read()
        filename = file.filename or "unknown"
        file_size = len(file_content)
        
        logger.info(f"Dosya alındı: {filename}, Boyut: {file_size} bytes")
        
        # Geçici dosya oluştur
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(filename).suffix) as tmp_file:
            tmp_file.write(file_content)
            temp_file_path = tmp_file.name
        
        # Statik analiz
        logger.info("Statik analiz başlatılıyor...")
        static_analyzer = StaticAnalyzer(temp_file_path)
        static_results = static_analyzer.analyze()
        
        # Hash'i al (karantina ID için)
        file_hash = static_results.get('hashes', {}).get('sha256', 'unknown')
        
        # Risk skoru hesapla
        risk_score = 0
        risk_level = "low"
        
        # Entropi kontrolü
        entropy = static_results.get('entropy', 0)
        if entropy > 7.5:
            risk_score += 20
            logger.warning(f"Yüksek entropy: {entropy}")
        
        # PE/ELF analizi
        pe_analysis = static_results.get('pe_analysis')
        if pe_analysis and pe_analysis.get('is_pe'):
            risk_score += 10
            # Şüpheli import'lar
            imports = pe_analysis.get('imports', [])
            suspicious_imports = ['VirtualAlloc', 'CreateRemoteThread', 'WriteProcessMemory', 
                                 'ShellExecute', 'WinExec', 'system']
            for imp in imports:
                if any(susp in imp for susp in suspicious_imports):
                    risk_score += 15
                    break
        
        # Dosya tipi kontrolü
        file_type = static_results.get('file_type', {})
        mime_type = file_type.get('mime_type', '')
        if 'executable' in mime_type or filename.endswith(('.exe', '.dll', '.bat', '.cmd', '.scr', '.com')):
            risk_score += 30
        
        # Dinamik analiz (Docker sandbox)
        dynamic_results = {}
        docker_available = False
        if docker_sandbox and docker_sandbox.check_docker_available():
            logger.info("Docker sandbox analizi başlatılıyor...")
            try:
                dynamic_results = docker_sandbox.analyze_file_in_sandbox(temp_file_path, filename)
                docker_available = True
                
                # Dinamik analiz sonuçlarına göre risk skoru güncelle
                if dynamic_results.get('success'):
                    dyn_analysis = dynamic_results.get('dynamic_analysis', {})
                    if dyn_analysis.get('executed'):
                        risk_score += 20
                        # Network aktivitesi
                        if dyn_analysis.get('network_calls'):
                            risk_score += 25
                            logger.warning("Network aktivitesi tespit edildi!")
                        # Dosya işlemleri
                        if len(dyn_analysis.get('file_operations', [])) > 10:
                            risk_score += 15
            except Exception as e:
                logger.error(f"Docker sandbox analizi hatası: {str(e)}")
                dynamic_results = {'error': str(e)}
        else:
            logger.warning("Docker mevcut değil, sadece statik analiz yapılıyor")
            dynamic_results = {
                'executed': False,
                'error': 'Docker not available for dynamic analysis'
            }
        
        # Risk seviyesini belirle
        if risk_score >= 70:
            risk_level = "high"
        elif risk_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Risk skorunu 0-100 arasında sınırla
        risk_score = min(100, max(0, risk_score))
        
        # Karantina günlüğüne kaydet
        analysis_results = {
            'static_analysis': static_results,
            'dynamic_analysis': dynamic_results,
            'docker_available': docker_available,
            'analysis_timestamp': datetime.utcnow().isoformat()
        }
        
        log_entry = quarantine_log.create_log_entry(
            filename=filename,
            file_hash=file_hash,
            analysis_results=analysis_results,
            risk_score=risk_score,
            risk_level=risk_level
        )
        
        logger.info(f"Dosya analizi tamamlandı: {filename}, Risk: {risk_score}/100 ({risk_level})")
        
        # Response oluştur
        response = {
            "status": "success",
            "message": "Dosya analizi tamamlandı",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "filename": filename,
            "file_size": file_size,
            "file_hash": file_hash,
            "quarantine_id": log_entry['id'],
            "analysis": {
                "static": static_results,
                "dynamic": dynamic_results,
                "docker_available": docker_available
            },
            "quarantine_log": {
                "id": log_entry['id'],
                "timestamp": log_entry['timestamp'],
                "status": log_entry['status']
            }
        }
        
        return response
    
    except Exception as e:
        logger.error(f"Dosya analizi hatası: {str(e)}", exc_info=True)
        return {
            "status": "error",
            "message": f"Analiz sırasında hata oluştu: {str(e)}",
            "risk_score": 0
        }
    
    finally:
        # Geçici dosyayı temizle
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except:
                pass


@app.get("/quarantine/log")
async def get_quarantine_logs(limit: int = 50, 
                               filename: Optional[str] = None,
                               hash: Optional[str] = None,
                               risk_level: Optional[str] = None):
    """
    Karantina Günlüğü Endpoint'i
    
    Args:
        limit: Maksimum kayıt sayısı
        filename: Dosya adına göre filtrele
        hash: Hash'e göre filtrele
        risk_level: Risk seviyesine göre filtrele (low/medium/high)
    
    Returns:
        dict: Karantina günlüğü kayıtları
    """
    if not quarantine_log:
        return {
            "status": "error",
            "message": "Quarantine log servisi mevcut değil",
            "logs": []
        }
    
    try:
        if filename or hash or risk_level:
            logs = quarantine_log.search_logs(
                filename=filename,
                hash=hash,
                risk_level=risk_level,
                limit=limit
            )
        else:
            logs = quarantine_log.get_all_logs(limit=limit)
        
        return {
            "status": "success",
            "count": len(logs),
            "logs": logs
        }
    except Exception as e:
        logger.error(f"Quarantine log hatası: {str(e)}")
        return {
            "status": "error",
            "message": str(e),
            "logs": []
        }


@app.get("/quarantine/log/{log_id}")
async def get_quarantine_log_entry(log_id: str):
    """
    Belirli bir karantina günlüğü kaydını getir
    
    Args:
        log_id: Günlük kaydı ID'si
    
    Returns:
        dict: Günlük kaydı detayları
    """
    if not quarantine_log:
        return {
            "status": "error",
            "message": "Quarantine log servisi mevcut değil"
        }
    
    try:
        log_entry = quarantine_log.get_log_entry(log_id)
        if log_entry:
            return {
                "status": "success",
                "log": log_entry
            }
        else:
            return {
                "status": "error",
                "message": "Log entry not found"
            }
    except Exception as e:
        logger.error(f"Quarantine log entry hatası: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }


@app.delete("/quarantine/log/{log_id}")
async def delete_quarantine_log_entry(log_id: str):
    """
    Karantina günlüğü kaydını sil
    
    Args:
        log_id: Günlük kaydı ID'si
    
    Returns:
        dict: Silme işlemi sonucu
    """
    if not quarantine_log:
        return {
            "status": "error",
            "message": "Quarantine log servisi mevcut değil"
        }
    
    try:
        success = quarantine_log.delete_log_entry(log_id)
        if success:
            return {
                "status": "success",
                "message": f"Log entry {log_id} deleted"
            }
        else:
            return {
                "status": "error",
                "message": "Log entry not found or could not be deleted"
            }
    except Exception as e:
        logger.error(f"Delete quarantine log entry hatası: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }

if __name__ == "__main__":
    try:
        import uvicorn  # type: ignore
        # 5050 portunda çalıştır
        uvicorn.run(app, host="0.0.0.0", port=5050)
    except ImportError:
        logger.error("Uvicorn yüklü değil! Lütfen 'pip install uvicorn[standard]' komutunu çalıştırın.")
        print("\n" + "="*60)
        print("HATA: Gerekli kütüphaneler yüklü değil!")
        print("="*60)
        print("\nLütfen aşağıdaki komutu çalıştırın:")
        print("pip install -r requirements.txt")
        print("\nVeya tek tek:")
        print("pip install fastapi uvicorn[standard] python-multipart pydantic Pillow exifread")
        print("="*60 + "\n")
        raise