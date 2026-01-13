/**
 * Dijital Karantina - Frontend Application
 * Backend API ile entegre analiz servisi
 */

// API Configuration
const API_BASE_URL = 'http://localhost:5050';

// DOM Elements
const fileInput = document.getElementById('file-input');
const fileUploadArea = document.getElementById('file-upload-area');
const fileList = document.getElementById('file-list');
const urlInput = document.getElementById('url-input');
const imageInput = document.getElementById('image-input');
const imageUploadArea = document.getElementById('image-upload-area');
const imagePreview = document.getElementById('image-preview');
const analyzeButton = document.getElementById('analyze-button');
const resultsSection = document.getElementById('results-section');
const resultsContent = document.getElementById('results-content');

// State
let selectedFiles = [];
let selectedUrl = '';
let selectedImage = null;

/**
 * Initialize application
 */
function init() {
    setupFileUpload();
    setupUrlInput();
    setupImageUpload();
    setupAnalyzeButton();
    console.log('Dijital Karantina uygulaması başlatıldı.');
}

/**
 * Setup file upload functionality
 */
function setupFileUpload() {
    // Click to upload
    fileUploadArea.addEventListener('click', () => {
        fileInput.click();
    });

    // File selection
    fileInput.addEventListener('change', (e) => {
        handleFileSelection(e.target.files);
    });

    // Drag and drop
    fileUploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileUploadArea.classList.add('dragover');
    });

    fileUploadArea.addEventListener('dragleave', () => {
        fileUploadArea.classList.remove('dragover');
    });

    fileUploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        fileUploadArea.classList.remove('dragover');
        handleFileSelection(e.dataTransfer.files);
    });
}

/**
 * Handle file selection
 */
function handleFileSelection(files) {
    selectedFiles = Array.from(files);
    displayFileList();
    console.log('Seçilen dosyalar:', selectedFiles.map(f => f.name));
}

/**
 * Display selected files
 */
function displayFileList() {
    fileList.innerHTML = '';
    
    if (selectedFiles.length === 0) {
        return;
    }

    selectedFiles.forEach((file, index) => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        
        const fileName = document.createElement('span');
        fileName.textContent = `${file.name} (${formatFileSize(file.size)})`;
        
        const removeBtn = document.createElement('button');
        removeBtn.textContent = '✕';
        removeBtn.style.cssText = 'background: transparent; border: none; color: var(--text-muted); cursor: pointer; font-size: 1.2rem; padding: 0 0.5rem;';
        removeBtn.addEventListener('click', () => {
            selectedFiles.splice(index, 1);
            displayFileList();
        });

        fileItem.appendChild(fileName);
        fileItem.appendChild(removeBtn);
        fileList.appendChild(fileItem);
    });
}

/**
 * Format file size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Setup URL input functionality
 */
function setupUrlInput() {
    urlInput.addEventListener('input', (e) => {
        selectedUrl = e.target.value.trim();
        console.log('Girilen URL:', selectedUrl);
    });

    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            analyzeButton.click();
        }
    });
}

/**
 * Setup image upload functionality
 */
function setupImageUpload() {
    // Click to upload
    imageUploadArea.addEventListener('click', () => {
        imageInput.click();
    });

    // Image selection
    imageInput.addEventListener('change', (e) => {
        handleImageSelection(e.target.files[0]);
    });

    // Drag and drop
    imageUploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        imageUploadArea.classList.add('dragover');
    });

    imageUploadArea.addEventListener('dragleave', () => {
        imageUploadArea.classList.remove('dragover');
    });

    imageUploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        imageUploadArea.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            handleImageSelection(e.dataTransfer.files[0]);
        }
    });
}

/**
 * Handle image selection
 */
function handleImageSelection(file) {
    if (!file) return;

    if (!file.type.startsWith('image/')) {
        alert('Lütfen geçerli bir görsel dosyası seçin.');
        return;
    }

    selectedImage = file;
    console.log('Seçilen görsel:', file.name);

    // Display preview
    const reader = new FileReader();
    reader.onload = (e) => {
        imagePreview.innerHTML = `<img src="${e.target.result}" alt="Önizleme">`;
        imagePreview.classList.add('active');
    };
    reader.readAsDataURL(file);

    // EXIF bilgilerini çıkar ve göster
    extractAndDisplayEXIF(file);
}

/**
 * EXIF bilgilerini çıkar ve göster
 */
function extractAndDisplayEXIF(file) {
    const exifInfo = document.getElementById('exifInfo');
    
    // Önce içeriği temizle ve göster
    exifInfo.innerHTML = '<p style="color: var(--text-secondary);">EXIF bilgileri çıkarılıyor...</p>';
    exifInfo.style.display = 'block';

    // EXIF.js kullanarak EXIF bilgilerini çıkar
    if (typeof EXIF !== 'undefined') {
        EXIF.getData(file, function() {
            const make = EXIF.getTag(this, "Make") || "Bilinmiyor";
            const model = EXIF.getTag(this, "Model") || "Bilinmiyor";
            const datetime = EXIF.getTag(this, "DateTimeOriginal") || EXIF.getTag(this, "DateTime") || "Bilinmiyor";
            
            // GPS koordinatlarını çıkar
            let gpsLat = EXIF.getTag(this, "GPSLatitude");
            let gpsLon = EXIF.getTag(this, "GPSLongitude");
            const gpsLatRef = EXIF.getTag(this, "GPSLatitudeRef");
            const gpsLonRef = EXIF.getTag(this, "GPSLongitudeRef");
            
            let gpsDisplay = "Bilinmiyor";
            if (gpsLat && gpsLon) {
                // GPS koordinatlarını decimal formata çevir
                let latDecimal = convertDMSToDD(gpsLat, gpsLatRef);
                let lonDecimal = convertDMSToDD(gpsLon, gpsLonRef);
                if (latDecimal !== null && lonDecimal !== null) {
                    gpsDisplay = `${latDecimal.toFixed(6)}, ${lonDecimal.toFixed(6)}`;
                } else {
                    gpsDisplay = `${gpsLat}, ${gpsLon}`;
                }
            }
            
            // EXIF bilgilerini HTML olarak oluştur
            const exifHTML = `
                <div style="margin-bottom: 0.75rem;">
                    <h4 style="color: var(--accent-primary); font-size: 1rem; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
                        <span>📋</span>
                        <span>EXIF Bilgileri (Frontend)</span>
                    </h4>
                </div>
                <div style="display: grid; gap: 0.5rem;">
                    <div style="display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid rgba(255,255,255,0.1);">
                        <span style="color: var(--text-secondary); font-weight: 600;">Cihaz:</span>
                        <span style="color: var(--text-primary);">${make} ${model}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid rgba(255,255,255,0.1);">
                        <span style="color: var(--text-secondary); font-weight: 600;">Tarih:</span>
                        <span style="color: var(--text-primary);">${datetime}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 0.5rem 0;">
                        <span style="color: var(--text-secondary); font-weight: 600;">GPS:</span>
                        <span style="color: ${gpsDisplay !== 'Bilinmiyor' ? 'var(--accent-warning)' : 'var(--text-primary)'}; font-family: monospace; font-size: 0.9rem;">
                            ${gpsDisplay}
                        </span>
                    </div>
                </div>
            `;
            
            exifInfo.innerHTML = exifHTML;
        });
    } else {
        exifInfo.innerHTML = '<p style="color: var(--text-muted);">EXIF kütüphanesi yüklenemedi.</p>';
    }
}

/**
 * DMS (Degrees, Minutes, Seconds) formatını Decimal Degrees'a çevir
 */
function convertDMSToDD(dms, ref) {
    if (!dms || !Array.isArray(dms) || dms.length < 3) {
        return null;
    }
    
    try {
        let dd = dms[0] + dms[1]/60 + dms[2]/(60*60);
        if (ref === "S" || ref === "W") {
            dd = dd * -1;
        }
        return dd;
    } catch (e) {
        return null;
    }
}

/**
 * Setup analyze button
 */
function setupAnalyzeButton() {
    analyzeButton.addEventListener('click', () => {
        startAnalysis();
    });
}

/**
 * Start analysis - Backend API'ye bağlanır
 * Görsel ve URL analizini destekler
 */
async function startAnalysis() {
    console.log('=== Analiz Başlatıldı ===');
    
    // Analiz tipini belirle: Dosya, URL veya Görsel
    const hasFile = selectedFiles && selectedFiles.length > 0;
    const hasUrl = selectedUrl && selectedUrl.trim().length > 0;
    const hasImage = selectedImage !== null;
    
    if (!hasFile && !hasUrl && !hasImage) {
        alert('Lütfen analiz edilecek bir dosya yükleyin, URL girin veya görsel seçin.');
        return;
    }
    
    // Disable button during analysis
    analyzeButton.disabled = true;
    analyzeButton.innerHTML = '<span class="button-icon">⏳</span><span class="button-text">Analiz ediliyor...</span>';
    
    try {
        // Öncelik sırası: Dosya > URL > Görsel
        if (hasFile) {
            console.log('Dosya analizi başlatılıyor (Malware Sandbox)...');
            await performFileAnalysis();
        } else if (hasUrl) {
            console.log('URL analizi başlatılıyor...');
            await performUrlAnalysis();
        } else if (hasImage) {
            console.log('Görsel analizi başlatılıyor...');
            await performImageAnalysis();
        }
    } catch (error) {
        console.error('Analiz hatası:', error);
        
        // Hata detaylarını göster
        const errorMessage = error.message || 'Bilinmeyen hata';
        let analysisType = 'Analiz';
        if (hasFile) analysisType = 'Dosya Analizi';
        else if (hasUrl) analysisType = 'URL Analizi';
        else if (hasImage) analysisType = 'Görsel Analizi';
        
        const errorResults = {
            type: analysisType,
            status: 'error',
            message: `Analiz başarısız: ${errorMessage}`,
            risk_score: 0
        };
        
        displayResults(errorResults);
        
        // Kısa ve anlaşılır hata mesajı
        const shortMessage = errorMessage.length > 80 ? errorMessage.substring(0, 80) + '...' : errorMessage;
        alert(`Analiz hatası:\n\n${shortMessage}\n\nLütfen tekrar deneyin.`);
    } finally {
        // Re-enable button
        analyzeButton.disabled = false;
        analyzeButton.innerHTML = '<span class="button-icon">🔍</span><span class="button-text">Analizi Başlat</span>';
        
        // Show results section
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
}

/**
 * Perform file analysis - Backend API'ye istek atar (Malware Sandbox)
 */
async function performFileAnalysis() {
    console.log('Dosya analizi başlatılıyor (Malware Sandbox)...');
    console.log('Analiz edilen dosyalar:', selectedFiles.map(f => f.name));
    
    // İlk dosyayı analiz et (şimdilik tek dosya)
    const file = selectedFiles[0];
    
    try {
        // FormData oluştur
        const formData = new FormData();
        formData.append('file', file);
        
        // Backend API'ye istek at - 120 saniye timeout (Docker analizi uzun sürebilir)
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 120000);
        
        const response = await fetch(`${API_BASE_URL}/analyze/file`, {
            method: 'POST',
            body: formData,
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ detail: 'Sunucu hatası' }));
            throw new Error(errorData.detail || errorData.message || `HTTP ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Backend yanıtı:', data);
        
        // Sonuçları formatla ve göster
        const results = {
            type: 'Dosya Analizi (Malware Sandbox)',
            files: selectedFiles.map(f => ({
                name: f.name,
                size: formatFileSize(f.size),
                type: f.type
            })),
            status: data.status,
            message: data.message,
            risk_score: data.risk_score || 0,
            risk_level: data.risk_level || 'low',
            filename: data.filename,
            file_hash: data.file_hash,
            quarantine_id: data.quarantine_id,
            analysis: data.analysis || {},
            quarantine_log: data.quarantine_log || {}
        };
        
        displayFileResults(results);
    } catch (error) {
        console.error('Dosya analizi hatası:', error);
        if (error.name === 'AbortError') {
            throw new Error('Analiz zaman aşımına uğradı (120 saniye). Lütfen tekrar deneyin.');
        }
        throw error;
    }
}

/**
 * Perform URL analysis - Backend API'ye istek atar
 */
async function performUrlAnalysis() {
    console.log('URL analizi başlatılıyor...');
    
    // URL validasyonu ve normalizasyonu
    let urlToAnalyze = selectedUrl.trim();
    
    if (!urlToAnalyze || urlToAnalyze.length === 0) {
        throw new Error('Lütfen geçerli bir URL girin.');
    }
    
    // URL formatını normalize et - http:// veya https:// yoksa ekle
    if (!urlToAnalyze.startsWith('http://') && !urlToAnalyze.startsWith('https://')) {
        urlToAnalyze = 'http://' + urlToAnalyze;
    }
    
    console.log('Analiz edilen URL:', urlToAnalyze);
    
    try {
        // Backend API'ye istek at
        const response = await fetch(`${API_BASE_URL}/analyze/url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: urlToAnalyze })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ detail: 'Sunucu hatası' }));
            throw new Error(errorData.detail || `HTTP ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Backend yanıtı:', data);
        
        // URL analizi için özel görüntüleme fonksiyonu
        if (data.status === 'success') {
            displayUrlResults(data);
        } else {
            // Hata durumu
            const errorResults = {
                type: 'URL Analizi',
                url: urlToAnalyze,
                status: 'error',
                message: data.message || 'Analiz sırasında bir hata oluştu',
                risk_score: 0
            };
            displayResults(errorResults);
        }
    } catch (error) {
        console.error('URL analizi hatası:', error);
        throw error;
    }
}

/**
 * Perform image analysis - Backend API'ye istek atar
 */
async function performImageAnalysis() {
    console.log('Görsel analizi başlatılıyor...');
    console.log('Analiz edilen görsel:', selectedImage.name);
    
    try {
        // FormData oluştur
        const formData = new FormData();
        formData.append('file', selectedImage);
        
        // Backend API'ye istek at - SADECE /analyze/image endpoint'i (timeout ile)
        let response;
        try {
            // 25 saniye timeout ile istek at (backend timeout'undan daha uzun)
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 25000);
            
            response = await fetch(`${API_BASE_URL}/analyze/image`, {
                method: 'POST',
                body: formData,
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
        } catch (fetchError) {
            console.error('Fetch hatası:', fetchError);
            if (fetchError.name === 'AbortError') {
                throw new Error('Analiz zaman aşımına uğradı. Lütfen tekrar deneyin.');
            }
            throw new Error(`Backend'e bağlanılamadı. Server çalışıyor mu? (${API_BASE_URL})`);
        }
        
        if (!response.ok) {
            let errorData;
            try {
                errorData = await response.json();
            } catch (e) {
                errorData = { detail: `HTTP ${response.status}: ${response.statusText}` };
            }
            throw new Error(errorData.detail || errorData.message || `HTTP ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Backend yanıtı:', data);
        
        // Status kontrolü - Backend her durumda response döndürüyor
        if (data.status !== 'success') {
            // Backend'den gelen hata mesajını kullan
            const errorMsg = data.message || 'Analiz başarısız oldu';
            throw new Error(errorMsg);
        }
        
        // Backend'den gelen details objesinden bilgileri al
        const details = data.details || {};
        const threats = data.threats || [];
        
        // Sonuçları formatla ve göster
        const results = {
            type: 'Görsel Analizi',
            image: details.filename || selectedImage.name,
            size: details.size_kb ? `${details.size_kb} KB` : formatFileSize(selectedImage.size),
            status: data.status,
            message: data.message,
            risk_score: data.risk_score,
            risk_level: data.risk_level,
            details: details,
            threats: threats
        };
        
        displayResults(results);
    } catch (error) {
        console.error('Görsel analizi hatası:', error);
        throw error;
    }
}

/**
 * Display file analysis results - Malware Sandbox
 */
function displayFileResults(data) {
    console.log('Dosya analizi sonuçları gösteriliyor:', data);
    
    // Risk seviyesine göre renk
    let statusColor = '#10b981'; // Yeşil
    let statusGlow = 'rgba(16, 185, 129, 0.5)';
    let statusText = 'Güvenli';
    
    const riskScore = data.risk_score || 0;
    const riskLevel = data.risk_level || 'low';
    
    if (riskScore >= 70 || riskLevel === 'high') {
        statusColor = '#ef4444'; // Kırmızı
        statusGlow = 'rgba(239, 68, 68, 0.5)';
        statusText = 'Yüksek Risk';
    } else if (riskScore >= 40 || riskLevel === 'medium') {
        statusColor = '#f59e0b'; // Turuncu
        statusGlow = 'rgba(245, 158, 11, 0.5)';
        statusText = 'Orta Risk';
    }
    
    const analysis = data.analysis || {};
    const staticAnalysis = analysis.static || {};
    const dynamicAnalysis = analysis.dynamic || {};
    const dockerAvailable = analysis.docker_available || false;
    
    let html = `
        <div class="result-card" style="border-left: 4px solid ${statusColor}; background: linear-gradient(135deg, rgba(0,0,0,0.05) 0%, rgba(0,0,0,0.02) 100%);">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <h2 style="color: var(--accent-primary); font-size: 1.5rem; margin: 0;">🛡️ Dosya Analizi - Malware Sandbox</h2>
                <div style="display: flex; align-items: center; gap: 1rem;">
                    <div style="text-align: right;">
                        <div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.25rem;">Risk Skoru</div>
                        <div style="font-size: 1.75rem; font-weight: 700; color: ${statusColor}; text-shadow: 0 0 10px ${statusGlow};">
                            ${riskScore}/100
                        </div>
                    </div>
                    <div style="padding: 0.5rem 1rem; background: ${statusColor}; color: white; border-radius: 6px; font-weight: 600; font-size: 0.9rem;">
                        ${statusText}
                    </div>
                </div>
            </div>
            
            <div class="card-body">
                <div style="background: rgba(0, 217, 255, 0.1); padding: 1rem; border-radius: 6px; margin-bottom: 1.5rem;">
                    <div class="info-row" style="margin-bottom: 0.5rem;">
                        <span class="info-label">Dosya Adı:</span>
                        <span class="info-value" style="font-family: monospace;">${data.filename || 'Bilinmiyor'}</span>
                    </div>
                    <div class="info-row" style="margin-bottom: 0.5rem;">
                        <span class="info-label">SHA256 Hash:</span>
                        <span class="info-value" style="font-family: monospace; font-size: 0.85rem; word-break: break-all;">${data.file_hash || 'N/A'}</span>
                    </div>
                    <div class="info-row" style="margin-bottom: 0.5rem;">
                        <span class="info-label">Karantina ID:</span>
                        <span class="info-value" style="font-family: monospace;">${data.quarantine_id || 'N/A'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Analiz Zamanı:</span>
                        <span class="info-value">${data.quarantine_log?.timestamp ? new Date(data.quarantine_log.timestamp).toLocaleString('tr-TR') : 'N/A'}</span>
                    </div>
                </div>
                
                <!-- Statik Analiz -->
                <div class="result-card" style="border-left-color: var(--accent-primary); margin-bottom: 1.5rem;">
                    <div class="card-header">
                        <h3 style="color: var(--accent-primary);">📊 Statik Analiz</h3>
                    </div>
                    <div class="card-body">
    `;
    
    // Hash'ler
    const hashes = staticAnalysis.hashes || {};
    if (Object.keys(hashes).length > 0) {
        html += `
            <div style="margin-bottom: 1rem;">
                <h4 style="color: var(--text-primary); font-size: 1rem; margin-bottom: 0.75rem;">Hash Değerleri</h4>
                <div style="background: rgba(0,0,0,0.05); padding: 1rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem;">
                    ${hashes.md5 ? `<div style="margin-bottom: 0.5rem;"><strong>MD5:</strong> ${hashes.md5}</div>` : ''}
                    ${hashes.sha1 ? `<div style="margin-bottom: 0.5rem;"><strong>SHA1:</strong> ${hashes.sha1}</div>` : ''}
                    ${hashes.sha256 ? `<div style="margin-bottom: 0.5rem;"><strong>SHA256:</strong> ${hashes.sha256}</div>` : ''}
                    ${hashes.sha512 ? `<div><strong>SHA512:</strong> ${hashes.sha512}</div>` : ''}
                </div>
            </div>
        `;
    }
    
    // Dosya tipi
    const fileType = staticAnalysis.file_type || {};
    html += `
        <div style="margin-bottom: 1rem;">
            <h4 style="color: var(--text-primary); font-size: 1rem; margin-bottom: 0.75rem;">Dosya Tipi</h4>
            <div class="info-row">
                <span class="info-label">MIME Type:</span>
                <span class="info-value">${fileType.mime_type || 'Bilinmiyor'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Açıklama:</span>
                <span class="info-value">${fileType.description || 'N/A'}</span>
            </div>
        </div>
    `;
    
    // Entropi
    const entropy = staticAnalysis.entropy || 0;
    html += `
        <div style="margin-bottom: 1rem;">
            <h4 style="color: var(--text-primary); font-size: 1rem; margin-bottom: 0.75rem;">Entropi Analizi</h4>
            <div class="info-row">
                <span class="info-label">Entropi Değeri:</span>
                <span class="info-value" style="color: ${entropy > 7.5 ? 'var(--accent-danger)' : 'var(--accent-success)'};">
                    ${entropy}/8.0 ${entropy > 7.5 ? '⚠️ (Yüksek - Şifrelenmiş içerik olabilir)' : '✓ (Normal)'}
                </span>
            </div>
        </div>
    `;
    
    // PE Analizi
    const peAnalysis = staticAnalysis.pe_analysis;
    if (peAnalysis && peAnalysis.is_pe) {
        html += `
            <div style="margin-bottom: 1rem;">
                <h4 style="color: var(--accent-danger); font-size: 1rem; margin-bottom: 0.75rem;">⚠️ PE (Windows Executable) Analizi</h4>
                <div style="background: rgba(239, 68, 68, 0.1); padding: 1rem; border-radius: 4px;">
                    <div class="info-row">
                        <span class="info-label">Entry Point:</span>
                        <span class="info-value" style="font-family: monospace;">${peAnalysis.entry_point || 'N/A'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Section Sayısı:</span>
                        <span class="info-value">${peAnalysis.number_of_sections || 0}</span>
                    </div>
                    ${peAnalysis.imports && peAnalysis.imports.length > 0 ? `
                        <div style="margin-top: 0.75rem;">
                            <div style="font-weight: 600; margin-bottom: 0.5rem;">Import'lar (${peAnalysis.imports.length} adet):</div>
                            <div style="max-height: 150px; overflow-y: auto; font-family: monospace; font-size: 0.85rem; background: rgba(0,0,0,0.05); padding: 0.5rem; border-radius: 4px;">
                                ${peAnalysis.imports.slice(0, 20).map(imp => `<div>• ${imp}</div>`).join('')}
                                ${peAnalysis.imports.length > 20 ? `<div>... ve ${peAnalysis.imports.length - 20} adet daha</div>` : ''}
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }
    
    // Strings
    const strings = staticAnalysis.strings || [];
    if (strings.length > 0) {
        html += `
            <div style="margin-bottom: 1rem;">
                <h4 style="color: var(--text-primary); font-size: 1rem; margin-bottom: 0.75rem;">Strings (${strings.length} adet)</h4>
                <div style="max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 0.85rem; background: rgba(0,0,0,0.05); padding: 0.5rem; border-radius: 4px;">
                    ${strings.slice(0, 50).map(s => `<div>${s}</div>`).join('')}
                    ${strings.length > 50 ? `<div>... ve ${strings.length - 50} adet daha</div>` : ''}
                </div>
            </div>
        `;
    }
    
    html += `</div></div>`;
    
    // Dinamik Analiz
    html += `
        <div class="result-card" style="border-left-color: ${dockerAvailable ? 'var(--accent-success)' : 'var(--accent-warning)'}; margin-bottom: 1.5rem;">
            <div class="card-header">
                <h3 style="color: ${dockerAvailable ? 'var(--accent-success)' : 'var(--accent-warning)'};">
                    ${dockerAvailable ? '🐳 Dinamik Analiz (Docker Sandbox)' : '⚠️ Dinamik Analiz (Docker Mevcut Değil)'}
                </h3>
            </div>
            <div class="card-body">
    `;
    
    if (dynamicAnalysis.executed) {
        html += `
            <div style="background: rgba(239, 68, 68, 0.1); padding: 1rem; border-radius: 4px; margin-bottom: 1rem;">
                <div class="info-row">
                    <span class="info-label">Çalıştırıldı:</span>
                    <span class="info-value" style="color: var(--accent-danger);">✓ Evet</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Exit Code:</span>
                    <span class="info-value">${dynamicAnalysis.exit_code !== null ? dynamicAnalysis.exit_code : 'N/A'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Çalışma Süresi:</span>
                    <span class="info-value">${dynamicAnalysis.execution_time ? dynamicAnalysis.execution_time.toFixed(2) + ' saniye' : 'N/A'}</span>
                </div>
            </div>
        `;
        
        // Network aktivitesi
        const networkCalls = dynamicAnalysis.network_calls || [];
        if (networkCalls.length > 0) {
            html += `
                <div style="margin-bottom: 1rem;">
                    <h4 style="color: var(--accent-danger); font-size: 1rem; margin-bottom: 0.75rem;">🌐 Network Aktivitesi (${networkCalls.length} adet)</h4>
                    <div style="max-height: 150px; overflow-y: auto; font-family: monospace; font-size: 0.85rem; background: rgba(239, 68, 68, 0.1); padding: 0.5rem; border-radius: 4px;">
                        ${networkCalls.map(call => `<div>• ${call}</div>`).join('')}
                    </div>
                </div>
            `;
        }
        
        // Dosya işlemleri
        const fileOps = dynamicAnalysis.file_operations || [];
        if (fileOps.length > 0) {
            html += `
                <div style="margin-bottom: 1rem;">
                    <h4 style="color: var(--text-primary); font-size: 1rem; margin-bottom: 0.75rem;">📁 Dosya İşlemleri (${fileOps.length} adet)</h4>
                    <div style="max-height: 150px; overflow-y: auto; font-family: monospace; font-size: 0.85rem; background: rgba(0,0,0,0.05); padding: 0.5rem; border-radius: 4px;">
                        ${fileOps.map(op => `<div>• ${op}</div>`).join('')}
                    </div>
                </div>
            `;
        }
    } else {
        html += `
            <div style="background: rgba(245, 158, 11, 0.1); padding: 1rem; border-radius: 4px;">
                <p style="color: var(--accent-warning); margin: 0;">
                    ${dynamicAnalysis.error || 'Dinamik analiz yapılamadı. Docker sandbox mevcut değil veya dosya çalıştırılamadı.'}
                </p>
            </div>
        `;
    }
    
    html += `</div></div>`;
    
    // Karantina Günlüğü
    html += `
        <div class="result-card" style="border-left-color: var(--accent-primary);">
            <div class="card-header">
                <h3 style="color: var(--accent-primary);">📋 Karantina Günlüğü</h3>
            </div>
            <div class="card-body">
                <div style="background: rgba(0, 217, 255, 0.1); padding: 1rem; border-radius: 4px;">
                    <div class="info-row">
                        <span class="info-label">Durum:</span>
                        <span class="info-value" style="color: ${data.quarantine_log?.status === 'quarantined' ? 'var(--accent-danger)' : 'var(--accent-success)'};">
                            ${data.quarantine_log?.status === 'quarantined' ? '🔒 Karantinada' : '✓ Analiz Edildi'}
                        </span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Kayıt ID:</span>
                        <span class="info-value" style="font-family: monospace;">${data.quarantine_id || 'N/A'}</span>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    html += `</div></div>`;
    resultsContent.innerHTML = html;
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Display URL analysis results - Güvenlik Paneli
 */
function displayUrlResults(data) {
    console.log('URL sonuçları gösteriliyor:', data);
    
    // Risk seviyesine göre renk belirleme
    let statusColor = '#10b981'; // Yeşil (güvenli)
    let statusGlow = 'rgba(16, 185, 129, 0.5)'; // Yeşil glow
    let statusText = 'Güvenli';
    
    const riskScore = data.risk_skoru || data.risk_score || 0;
    
    if (riskScore >= 50) {
        statusColor = '#ef4444'; // Kırmızı (tehlikeli)
        statusGlow = 'rgba(239, 68, 68, 0.5)';
        statusText = 'Tehlikeli';
    } else if (riskScore >= 20) {
        statusColor = '#f59e0b'; // Turuncu (şüpheli)
        statusGlow = 'rgba(245, 158, 11, 0.5)';
        statusText = 'Şüpheli';
    }
    
    // Tespitler listesi
    const tespitler = data.tespitler || data.threats_detected || [];
    
    let tespitlerHTML = '';
    if (tespitler.length > 0) {
        tespitlerHTML = tespitler.map(tespit => {
            const riskIcon = tespit.risk_level === 'high' ? '🔴' : 
                           tespit.risk_level === 'medium' ? '🟠' : '🟡';
            return `
                <div class="karantina-log-item">
                    <div class="log-icon">${riskIcon}</div>
                    <div class="log-content">
                        <div class="log-title">${tespit.type || 'Tespit'}</div>
                        <div class="log-description">${tespit.description || ''}</div>
                        ${tespit.details ? `
                            <div class="log-details">
                                ${tespit.details.slice(0, 3).map(detail => 
                                    `<div class="log-detail-item">• ${detail.url || detail.text || 'Link'}</div>`
                                ).join('')}
                                ${tespit.details.length > 3 ? `<div class="log-detail-item">... ve ${tespit.details.length - 3} adet daha</div>` : ''}
                            </div>
                        ` : ''}
                    </div>
                </div>
            `;
        }).join('');
    } else {
        tespitlerHTML = `
            <div class="karantina-log-item">
                <div class="log-icon">✓</div>
                <div class="log-content">
                    <div class="log-title">Risk Tespit Edilmedi</div>
                    <div class="log-description">Sayfa güvenli görünüyor</div>
                </div>
            </div>
        `;
    }
    
    // Karantina görseli
    const screenshotSrc = data.karantina_fotografi || data.screenshot_base64 || '';
    
    // Redirect bilgisi
    const redirectInfo = data.redirect_count > 0 
        ? `<div class="redirect-info">⚠️ ${data.redirect_count} adet yönlendirme tespit edildi</div>`
        : '';
    
    const html = `
        <div class="url-security-panel" style="border-color: ${statusColor}; box-shadow: 0 0 30px ${statusGlow};">
            <!-- Durum Işığı -->
            <div class="status-indicator" style="background: ${statusColor}; box-shadow: 0 0 20px ${statusGlow};">
                <div class="status-pulse" style="background: ${statusColor};"></div>
                <span class="status-text">${statusText}</span>
            </div>
            
            <!-- Panel İçeriği -->
            <div class="security-panel-content">
                <!-- Sol: Karantina Penceresi -->
                <div class="karantina-window">
                    <div class="monitor-frame">
                        <div class="monitor-screen">
                            ${screenshotSrc ? 
                                `<img src="data:image/png;base64,${screenshotSrc}" alt="Karantina Ekran Görüntüsü" class="screenshot-img">` :
                                `<div class="no-screenshot">Ekran görüntüsü alınamadı</div>`
                            }
                        </div>
                        <div class="monitor-base"></div>
                    </div>
                    <div class="monitor-label">KARANTINA KAMERASI</div>
                    ${redirectInfo}
                </div>
                
                <!-- Sağ: Laboratuvar Notları -->
                <div class="laboratory-notes">
                    <div class="notes-header">
                        <h3>📋 Karantina Günlüğü</h3>
                        <div class="risk-score-badge" style="background: ${statusColor};">
                            Risk: ${riskScore}/100
                        </div>
                    </div>
                    <div class="notes-content">
                        <div class="karantina-message">
                            ${data.karantina_mesaji || data.message || 'Karantina analizi tamamlandı'}
                        </div>
                        <div class="karantina-logs">
                            ${tespitlerHTML}
                        </div>
                        
                        <!-- Ek Bilgiler -->
                        ${data.page_title ? `
                            <div class="info-section">
                                <strong>Sayfa Başlığı:</strong> ${data.page_title}
                            </div>
                        ` : ''}
                        ${data.final_url && data.final_url !== data.url ? `
                            <div class="info-section">
                                <strong>Son URL:</strong> ${data.final_url}
                            </div>
                        ` : ''}
                        ${data.ssl_status ? `
                            <div class="info-section">
                                <strong>SSL Durumu:</strong> 
                                <span style="color: ${data.ssl_status === 'secure' ? '#10b981' : '#ef4444'};">
                                    ${data.ssl_status === 'secure' ? '🔒 Güvenli' : '⚠️ Güvensiz'}
                                </span>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
            
            <!-- Alt: Butonlar -->
            <div class="security-panel-actions">
                <button class="security-btn danger-btn" id="proceed-anyway-btn">
                    ⚠️ Riskleri Anladım, Yine de Git
                </button>
                <button class="security-btn safe-btn" id="return-safe-btn">
                    🏠 Güvenli Alana Dön
                </button>
            </div>
        </div>
    `;
    
    resultsContent.innerHTML = html;
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    
    // Buton event handler'larını ekle
    const proceedBtn = document.getElementById('proceed-anyway-btn');
    const returnBtn = document.getElementById('return-safe-btn');
    
    if (proceedBtn) {
        proceedBtn.addEventListener('click', () => {
            const targetUrl = data.final_url || data.url;
            window.open(targetUrl, '_blank');
        });
    }
    
    if (returnBtn) {
        returnBtn.addEventListener('click', () => {
            resultsSection.style.display = 'none';
            window.scrollTo({top: 0, behavior: 'smooth'});
        });
    }
}

/**
 * Display analysis results - Detaylı kart tabanlı UI
 */
function displayResults(results) {
    // Status kontrolü - success değilse hata göster
    if (results.status !== 'success') {
        let html = `
            <div class="result-card" style="border-left-color: var(--accent-danger);">
                <div class="card-header">
                    <h3 style="color: var(--accent-danger);">${results.type} - Hata</h3>
                </div>
                <div class="card-body">
                    <p style="color: var(--text-secondary);">${results.message || 'Analiz sırasında bir hata oluştu'}</p>
                </div>
            </div>
        `;
        resultsContent.innerHTML = html;
        return;
    }
    
    const details = results.details || {};
    const riskLevel = results.risk_level || (results.risk_score >= 70 ? 'high' : results.risk_score >= 40 ? 'medium' : 'low');
    
    // Risk seviyesine göre renk ve etiket
    let riskColor, riskLabel, riskAdvice;
    if (riskLevel === 'high') {
        riskColor = 'var(--accent-danger)';
        riskLabel = 'Yüksek Risk';
        riskAdvice = 'Bu görsel gizli bilgiler içerebilir. Paylaşmadan önce dikkatli olun.';
    } else if (riskLevel === 'medium') {
        riskColor = 'var(--accent-warning)';
        riskLabel = 'Orta Risk';
        riskAdvice = 'Bu görsel bazı gizli bilgiler içerebilir. Paylaşmadan önce kontrol edin.';
    } else {
        riskColor = 'var(--accent-success)';
        riskLabel = 'Düşük Risk';
        riskAdvice = 'Bu görsel genel olarak güvenli görünüyor.';
    }
    
    let html = '';
    
    // Simülasyon Etiketi
    html += `
        <div style="background: rgba(0, 217, 255, 0.15); border: 2px solid var(--accent-primary); border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; text-align: center;">
            <p style="color: var(--accent-primary); font-size: 1.1rem; font-weight: 600; margin: 0;">
                🧪 Test & Simülasyon Analizi – Gerçek zararlı içermez
            </p>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.5rem; margin-bottom: 0;">
                Bu analiz gerçek zararlı yazılım çalıştırmadan, dosya yapısı ve metadata üzerinden tehdit tespiti yapar.
            </p>
        </div>
    `;
    
    // 1. Risk Skoru Kartı
    html += `
        <div class="result-card" style="border-left-color: ${riskColor};">
            <div class="card-header">
                <h3 style="color: var(--accent-primary);">🛡️ Güvenlik Analizi</h3>
            </div>
            <div class="card-body">
                <div style="text-align: center; padding: 1rem 0;">
                    <div style="font-size: 3rem; font-weight: 700; color: ${riskColor}; margin-bottom: 0.5rem;">
                        ${results.risk_score || 0}
                    </div>
                    <div style="font-size: 1.2rem; color: ${riskColor}; font-weight: 600; margin-bottom: 1rem;">
                        ${riskLabel}
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.9rem; padding: 0.75rem; background: rgba(0,0,0,0.2); border-radius: 4px;">
                        ${riskAdvice}
                    </p>
                </div>
            </div>
        </div>
    `;
    
    // 2. Tehdit Tespitleri (YENİ)
    const threats = results.threats || [];
    if (threats.length > 0) {
        html += `
            <div class="result-card" style="border-left-color: var(--accent-danger);">
                <div class="card-header">
                    <h3 style="color: var(--accent-primary);">⚠️ Tespit Edilen Tehditler</h3>
                </div>
                <div class="card-body">
        `;
        
        threats.forEach((threat, index) => {
            let threatColor, threatIcon;
            if (threat.risk_level === 'high') {
                threatColor = 'var(--accent-danger)';
                threatIcon = '🔴';
            } else if (threat.risk_level === 'medium') {
                threatColor = 'var(--accent-warning)';
                threatIcon = '🟠';
            } else {
                threatColor = 'var(--accent-success)';
                threatIcon = '🟢';
            }
            
            html += `
                <div style="background: ${threatColor}15; border-left: 4px solid ${threatColor}; border-radius: 6px; padding: 1.25rem; margin-bottom: ${index < threats.length - 1 ? '1rem' : '0'};">
                    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem;">
                        <span style="font-size: 1.5rem;">${threatIcon}</span>
                        <div>
                            <h4 style="color: ${threatColor}; font-size: 1.1rem; font-weight: 700; margin: 0;">
                                ${threat.threat_name}
                            </h4>
                            <span style="color: ${threatColor}; font-size: 0.85rem; font-weight: 600;">
                                Risk Seviyesi: ${threat.risk_level === 'high' ? 'Yüksek' : threat.risk_level === 'medium' ? 'Orta' : 'Düşük'}
                            </span>
                        </div>
                    </div>
                    <p style="color: var(--text-primary); font-size: 0.95rem; line-height: 1.6; margin-bottom: 0.75rem;">
                        ${threat.description}
                    </p>
                    ${threat.detected_signature ? `
                    <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid var(--accent-danger); border-radius: 4px; padding: 1rem; margin-top: 0.75rem; margin-bottom: 0.75rem;">
                        <h5 style="color: var(--accent-danger); font-size: 0.95rem; font-weight: 600; margin: 0 0 0.5rem 0;">
                            🔍 Tespit Edilen Zararlı İmza:
                        </h5>
                        <pre style="color: var(--text-primary); font-size: 0.85rem; font-family: 'Courier New', monospace; white-space: pre-wrap; word-wrap: break-word; margin: 0; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 4px; overflow-x: auto; max-height: 300px; overflow-y: auto;">${threat.detected_signature}</pre>
                    </div>
                    ` : ''}
                    <details style="margin-top: 0.75rem;">
                        <summary style="color: var(--accent-primary); cursor: pointer; font-size: 0.9rem; font-weight: 600; user-select: none;">
                            Detaylı Bilgi ▼
                        </summary>
                        <div style="margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid rgba(255,255,255,0.1);">
                            <div style="margin-bottom: 0.5rem;">
                                <strong style="color: var(--text-secondary); font-size: 0.85rem;">Teknik Detay:</strong>
                                <p style="color: var(--text-secondary); font-size: 0.85rem; margin-top: 0.25rem;">${threat.technical_details || 'Detay bulunamadı'}</p>
                            </div>
                            <div>
                                <strong style="color: var(--text-secondary); font-size: 0.85rem;">Gerçek Hayat Kullanımı:</strong>
                                <p style="color: var(--text-secondary); font-size: 0.85rem; margin-top: 0.25rem;">${threat.real_world_usage || 'Bilgi bulunamadı'}</p>
                            </div>
                        </div>
                    </details>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
    }
    
    // 3. Dosya Bilgileri Kartı
    html += `
        <div class="result-card">
            <div class="card-header">
                <h3 style="color: var(--accent-primary);">📄 Dosya Bilgileri</h3>
            </div>
            <div class="card-body">
                <div class="info-row">
                    <span class="info-label">Dosya Adı:</span>
                    <span class="info-value">${details.filename || results.image || 'Bilinmiyor'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Boyut:</span>
                    <span class="info-value">${results.size || 'Bilinmiyor'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">MIME Type:</span>
                    <span class="info-value">${details.mime_type || 'Bilinmiyor'}</span>
                </div>
                ${details.actual_file_type ? `
                <div class="info-row">
                    <span class="info-label">Gerçek Dosya Türü (Header):</span>
                    <span class="info-value" style="${details.file_type_fake ? 'color: var(--accent-danger); font-weight: 600;' : ''}">
                        ${details.actual_file_type} ${details.file_type_fake ? '⚠️' : ''}
                    </span>
                </div>
                ` : ''}
                ${details.entropy !== undefined ? `
                <div class="info-row">
                    <span class="info-label">Entropi:</span>
                    <span class="info-value">${details.entropy.toFixed(2)}</span>
                </div>
                ` : ''}
                <div class="info-row">
                    <span class="info-label">SHA256 Hash:</span>
                    <span class="info-value" style="font-family: monospace; font-size: 0.85rem; word-break: break-all;">${details.sha256 || 'Bilinmiyor'}</span>
                </div>
            </div>
        </div>
    `;
    
    // 3. EXIF Metadata Kartı
    const exifFound = details.exif_found;
    html += `
        <div class="result-card" style="${exifFound ? 'border-left-color: var(--accent-warning);' : ''}">
            <div class="card-header">
                <h3 style="color: var(--accent-primary);">📋 EXIF Metadata</h3>
                <span style="color: ${exifFound ? 'var(--accent-warning)' : 'var(--text-muted)'}; font-size: 0.9rem;">
                    ${exifFound ? '⚠️ Bulundu' : '✓ Bulunamadı'}
                </span>
            </div>
            <div class="card-body">
    `;
    
    // Metadata katmanları kontrolü
    const isStripped = details.is_stripped;
    const iptcFound = details.iptc_found;
    const xmpFound = details.xmp_found;
    const binaryPatterns = details.binary_patterns || {};
    
    if (isStripped && !exifFound && !iptcFound && !xmpFound && Object.keys(binaryPatterns).length === 0) {
        // Dosya stripped - metadata yok
        html += `
            <div style="background: rgba(100, 116, 139, 0.15); padding: 1.5rem; border-radius: 6px; border-left: 4px solid var(--text-muted); margin-bottom: 1rem; text-align: center;">
                <p style="color: var(--text-muted); font-size: 1.1rem; font-weight: 600; margin-bottom: 0.75rem;">🔒 Dijital Olarak Temizlenmiş</p>
                <p style="color: var(--text-secondary); font-size: 0.95rem; line-height: 1.6;">
                    Dosya dijital olarak temizlenmiş (stripped). Orijinal metadata katmanları mevcut değil.<br>
                    EXIF, IPTC ve XMP metadata bulunamadı. Binary pattern matching de sonuç vermedi.
                </p>
            </div>
        `;
    } else if (exifFound || iptcFound || xmpFound || Object.keys(binaryPatterns).length > 0) {
        // Metadata bulundu - uyarı göster
        const metadataLayers = [];
        if (exifFound) metadataLayers.push('EXIF');
        if (iptcFound) metadataLayers.push('IPTC');
        if (xmpFound) metadataLayers.push('XMP');
        if (Object.keys(binaryPatterns).length > 0) metadataLayers.push('Binary Patterns');
        
        html += `
            <div style="background: rgba(245, 158, 11, 0.15); padding: 1rem; border-radius: 4px; border-left: 3px solid var(--accent-warning); margin-bottom: 1.5rem;">
                <p style="color: var(--accent-warning); font-weight: 600; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
                    <span>⚠️</span>
                    <span>Bu görsel metadata içeriyor (${metadataLayers.join(', ')}). Metadata boyutu ne olursa olsun, gizli bilgiler (konum, cihaz bilgisi, çekim tarihi, düzenleme bilgileri vb.) içerebilir. Paylaşmadan önce dikkatli olun.</span>
                </p>
            </div>
        `;
        
        // Metadata katmanları bilgisi
        if (metadataLayers.length > 1) {
            html += `
                <div style="background: rgba(0, 217, 255, 0.1); padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem;">
                    <p style="color: var(--accent-primary); font-size: 0.9rem; margin-bottom: 0.5rem;"><strong>Tespit Edilen Metadata Katmanları:</strong></p>
                    <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                        ${metadataLayers.map(layer => `<span style="background: var(--bg-card); padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.85rem; color: var(--accent-primary);">${layer}</span>`).join('')}
                    </div>
                </div>
            `;
        }
    }
    
    if (exifFound && details.exif_details) {
        const exif = details.exif_details;
        
        // Cihaz Bilgisi
        if (Object.keys(exif.device_info || {}).length > 0) {
            html += '<div class="info-section">';
            html += '<h4 class="section-title">📱 Cihaz Bilgisi</h4>';
            if (exif.device_info.make) {
                html += `<div class="info-row"><span class="info-label">Kamera Markası:</span><span class="info-value">${exif.device_info.make}</span></div>`;
            }
            if (exif.device_info.model) {
                html += `<div class="info-row"><span class="info-label">Cihaz Modeli:</span><span class="info-value">${exif.device_info.model}</span></div>`;
            }
            if (exif.device_info.detected_from_binary) {
                html += `<div class="info-row"><span class="info-label">Binary Pattern:</span><span class="info-value" style="color: var(--accent-warning);">${exif.device_info.detected_from_binary}</span></div>`;
            }
            if (exif.device_info.lens_make) {
                html += `<div class="info-row"><span class="info-label">Lens Markası:</span><span class="info-value">${exif.device_info.lens_make}</span></div>`;
            }
            if (exif.device_info.lens_model) {
                html += `<div class="info-row"><span class="info-label">Lens Modeli:</span><span class="info-value">${exif.device_info.lens_model}</span></div>`;
            }
            html += '</div>';
        } else if (Object.keys(binaryPatterns).length > 0) {
            html += '<div class="info-section">';
            html += '<h4 class="section-title">📱 Cihaz Bilgisi (Binary Pattern)</h4>';
            const detectedDevices = Object.keys(binaryPatterns).join(', ');
            html += `<div class="info-row"><span class="info-label">Tespit Edilen:</span><span class="info-value" style="color: var(--accent-warning);">${detectedDevices}</span></div>`;
            html += '</div>';
        } else {
            html += '<div class="info-section"><p style="color: var(--text-muted); font-size: 0.9rem;">Cihaz bilgisi bulunamadı.</p></div>';
        }
        
        // Çekilme Bilgisi
        if (Object.keys(exif.capture_info || {}).length > 0) {
            html += '<div class="info-section">';
            html += '<h4 class="section-title">📅 Çekim Tarihi ve Saati</h4>';
            if (exif.capture_info.datetime_original) {
                html += `<div class="info-row"><span class="info-label">Orijinal Çekim:</span><span class="info-value">${exif.capture_info.datetime_original}</span></div>`;
            } else if (exif.capture_info.datetime) {
                html += `<div class="info-row"><span class="info-label">Tarih/Saat:</span><span class="info-value">${exif.capture_info.datetime}</span></div>`;
            }
            if (exif.capture_info.datetime_digitized) {
                html += `<div class="info-row"><span class="info-label">Dijitalleştirme:</span><span class="info-value">${exif.capture_info.datetime_digitized}</span></div>`;
            }
            html += '</div>';
        } else {
            html += '<div class="info-section"><p style="color: var(--text-muted); font-size: 0.9rem;">Çekim tarihi bilgisi bulunamadı.</p></div>';
        }
        
        // Konum Bilgisi (Kritik)
        if (details.gps_found && exif.location_info && Object.keys(exif.location_info).length > 0) {
            html += '<div class="info-section" style="background: rgba(239, 68, 68, 0.15); padding: 1.25rem; border-radius: 6px; border-left: 4px solid var(--accent-danger); margin-top: 1rem;">';
            html += '<h4 class="section-title" style="color: var(--accent-danger); font-size: 1.1rem;">📍 GPS Konum Bilgisi (KRİTİK)</h4>';
            if (exif.location_info.coordinates) {
                html += `<div class="info-row" style="margin-bottom: 0.75rem;"><span class="info-label" style="color: var(--accent-danger); font-weight: 600;">Koordinatlar:</span><span class="info-value" style="color: var(--accent-danger); font-weight: 600; font-family: monospace;">${exif.location_info.coordinates}</span></div>`;
            }
            if (exif.location_info.google_maps_url) {
                html += `<div class="info-row" style="margin-bottom: 0.75rem;"><span class="info-label">Harita:</span><a href="${exif.location_info.google_maps_url}" target="_blank" style="color: var(--accent-primary); text-decoration: none; font-weight: 600;">📍 Konumu Haritada Görüntüle →</a></div>`;
            }
            html += '<div style="background: rgba(239, 68, 68, 0.2); padding: 0.75rem; border-radius: 4px; margin-top: 0.75rem;">';
            html += '<p style="color: var(--accent-danger); font-size: 0.9rem; font-weight: 600; margin: 0; line-height: 1.5;">⚠️ KRİTİK: Bu görsel tam konum bilgisi (GPS koordinatları) içeriyor! Bu bilgi paylaşıldığında tam adresiniz ortaya çıkabilir. Paylaşmadan önce mutlaka dikkatli olun.</p>';
            html += '</div>';
            html += '</div>';
        } else {
            html += '<div class="info-section"><p style="color: var(--accent-success); font-size: 0.9rem;">✓ GPS konum bilgisi bulunamadı.</p></div>';
        }
        
        // Kamera Ayarları
        if (Object.keys(exif.camera_settings || {}).length > 0) {
            html += '<div class="info-section">';
            html += '<h4 class="section-title">⚙️ Kamera Ayarları</h4>';
            if (exif.camera_settings.iso) {
                html += `<div class="info-row"><span class="info-label">ISO Değeri:</span><span class="info-value">${exif.camera_settings.iso}</span></div>`;
            }
            if (exif.camera_settings.fnumber) {
                html += `<div class="info-row"><span class="info-label">Diyafram (f-stop):</span><span class="info-value">${exif.camera_settings.fnumber}</span></div>`;
            }
            if (exif.camera_settings.exposure_time) {
                html += `<div class="info-row"><span class="info-label">Pozlama Süresi:</span><span class="info-value">${exif.camera_settings.exposure_time}</span></div>`;
            }
            if (exif.camera_settings.focal_length) {
                html += `<div class="info-row"><span class="info-label">Odak Uzaklığı:</span><span class="info-value">${exif.camera_settings.focal_length}</span></div>`;
            }
            html += '</div>';
        } else {
            html += '<div class="info-section"><p style="color: var(--text-muted); font-size: 0.9rem;">Kamera ayarları bilgisi bulunamadı.</p></div>';
        }
        
        // Yazılım Bilgisi
        if (Object.keys(exif.software_info || {}).length > 0) {
            html += '<div class="info-section">';
            html += '<h4 class="section-title">💻 Yazılım ve Düzenleme Bilgisi</h4>';
            if (exif.software_info.software) {
                html += `<div class="info-row"><span class="info-label">Kullanılan Yazılım:</span><span class="info-value">${exif.software_info.software}</span></div>`;
            }
            if (exif.software_info.artist) {
                html += `<div class="info-row"><span class="info-label">Sanatçı/Kullanıcı:</span><span class="info-value">${exif.software_info.artist}</span></div>`;
            }
            if (exif.software_info.copyright) {
                html += `<div class="info-row"><span class="info-label">Telif Hakkı:</span><span class="info-value">${exif.software_info.copyright}</span></div>`;
            }
            html += '</div>';
        } else {
            html += '<div class="info-section"><p style="color: var(--text-muted); font-size: 0.9rem;">Yazılım bilgisi bulunamadı.</p></div>';
        }
        
        // Metadata boyutu bilgisi (her zaman göster)
        if (details.metadata_size_kb > 0) {
            const sizeWarning = details.metadata_size_kb > 50 
                ? ' <span style="color: var(--accent-warning); font-weight: 600;">(Anormal büyük - ekstra dikkat!)</span>' 
                : ' <span style="color: var(--text-muted); font-size: 0.85rem;">(Küçük olsa bile gizli bilgiler içerebilir)</span>';
            html += `
                <div class="info-section" style="margin-top: 1.5rem; padding-top: 1rem; border-top: 2px solid var(--border-color);">
                    <div class="info-row">
                        <span class="info-label">Metadata Boyutu:</span>
                        <span class="info-value">${details.metadata_size_kb} KB${sizeWarning}</span>
                    </div>
                </div>
            `;
        }
    } else if (isStripped) {
        // Stripped durumu - teknik açıklama
        html += `
            <div style="text-align: center; padding: 2rem;">
                <p style="color: var(--text-muted); font-size: 1.1rem; margin-bottom: 0.75rem;">🔒</p>
                <p style="color: var(--text-secondary); font-size: 0.95rem; line-height: 1.6; margin-bottom: 1rem;">
                    <strong style="color: var(--text-primary);">Dosya dijital olarak temizlenmiş (stripped).</strong><br>
                    Orijinal metadata katmanları mevcut değil.
                </p>
                <div style="background: rgba(100, 116, 139, 0.1); padding: 1rem; border-radius: 4px; text-align: left; margin-top: 1rem;">
                    <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 0.5rem;"><strong>Kontrol Edilen Katmanlar:</strong></p>
                    <ul style="color: var(--text-secondary); font-size: 0.85rem; margin-left: 1.5rem; line-height: 1.8;">
                        <li>EXIF metadata: Bulunamadı</li>
                        <li>IPTC metadata: Bulunamadı</li>
                        <li>XMP metadata: Bulunamadı</li>
                        <li>Binary pattern matching: Sonuç yok</li>
                    </ul>
                </div>
            </div>
        `;
    } else {
        html += `
            <div style="text-align: center; padding: 2rem;">
                <p style="color: var(--accent-success); font-size: 1.1rem; margin-bottom: 0.5rem;">✓</p>
                <p style="color: var(--text-muted);">EXIF metadata bulunamadı.</p>
            </div>
        `;
    }
    
    html += '</div></div>';
    
    // 4. Steganografi Kartı
    if (details.steganography_detected !== undefined) {
        html += `
            <div class="result-card" style="border-left-color: ${details.steganography_detected ? 'var(--accent-danger)' : 'var(--accent-success)'};">
                <div class="card-header">
                    <h3 style="color: var(--accent-primary);">🔒 Steganografi Analizi</h3>
                    <span style="color: ${details.steganography_detected ? 'var(--accent-danger)' : 'var(--accent-success)'}; font-size: 0.9rem;">
                        ${details.steganography_detected ? '⚠️ Tespit Edildi!' : '✓ Tespit Edilmedi'}
                    </span>
                </div>
                <div class="card-body">
        `;
        
        if (details.steganography_detected) {
            html += `<div style="background: rgba(239, 68, 68, 0.1); padding: 1rem; border-radius: 4px; border-left: 3px solid var(--accent-danger);">`;
            html += `<p style="color: var(--accent-danger); font-weight: 600; margin-bottom: 0.75rem;">Gizli mesaj tespit edildi!</p>`;
            html += `<div class="info-row"><span class="info-label">Güven Skoru:</span><span class="info-value" style="color: var(--accent-danger);">${(details.steganography_confidence * 100).toFixed(0)}%</span></div>`;
            if (details.steganography_reasons && details.steganography_reasons.length > 0) {
                html += `<p style="color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.75rem; margin-bottom: 0.5rem;"><strong>Tespit Nedenleri:</strong></p>`;
                html += '<ul style="margin-left: 1.5rem; color: var(--text-secondary); font-size: 0.9rem;">';
                details.steganography_reasons.forEach(reason => {
                    html += `<li style="margin-bottom: 0.25rem;">${reason}</li>`;
                });
                html += '</ul>';
            }
            html += '</div>';
        } else {
            html += '<p style="color: var(--accent-success); text-align: center; padding: 1rem;">Görselde steganografi (gizli mesaj) tespit edilmedi.</p>';
        }
        
        html += '</div></div>';
    }
    
    // 5. Güvenlik Bilinçlendirme Özeti
    html += `
        <div class="result-card" style="border-left-color: var(--accent-primary); background: rgba(0, 217, 255, 0.05);">
            <div class="card-header">
                <h3 style="color: var(--accent-primary);">📚 Güvenlik Bilinçlendirme Özeti</h3>
            </div>
            <div class="card-body">
                <div style="background: rgba(0, 217, 255, 0.1); padding: 1.25rem; border-radius: 6px; margin-bottom: 1rem;">
                    <h4 style="color: var(--accent-primary); font-size: 1rem; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem;">
                        <span>🧪</span>
                        <span>Bu Analiz Hakkında</span>
                    </h4>
                    <p style="color: var(--text-primary); font-size: 0.95rem; line-height: 1.7; margin-bottom: 0.75rem;">
                        Bu analiz, <strong>gerçek zararlı yazılım çalıştırmadan</strong> dosya yapısı, metadata, boyut, entropi ve format tutarlılığı üzerinden tehdit tespiti yapar. Dosyaların içeriği çalıştırılmaz veya zararlı kod tetiklenmez.
                    </p>
                    <p style="color: var(--text-secondary); font-size: 0.9rem; line-height: 1.6; margin: 0;">
                        Analiz sonuçları sadece dosya özelliklerine dayanır ve %100 kesinlik garantisi vermez. Tespit edilen yapılar gerçek bir tehdit olabileceği gibi yanlış pozitif (false positive) de olabilir.
                    </p>
                </div>
                
                <div style="background: rgba(245, 158, 11, 0.1); padding: 1.25rem; border-radius: 6px; border-left: 4px solid var(--accent-warning); margin-bottom: 1rem;">
                    <h4 style="color: var(--accent-warning); font-size: 1rem; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem;">
                        <span>🎯</span>
                        <span>Gerçek Hayatta Nasıl Kullanılıyor?</span>
                    </h4>
                    <ul style="color: var(--text-primary); font-size: 0.95rem; line-height: 1.8; margin: 0; padding-left: 1.5rem;">
                        <li style="margin-bottom: 0.5rem;">
                            <strong>Trojan & Malware Taşıyıcıları:</strong> Saldırganlar zararlı yazılımları görsel dosyalarına gizleyerek gönderir. Kullanıcı dosyayı açtığında zararlı kod çalıştırılır.
                        </li>
                        <li style="margin-bottom: 0.5rem;">
                            <strong>Dosya Türü Sahteciliği:</strong> Zararlı dosyalar .jpg, .png gibi güvenli görünen uzantılarla gizlenir. Sistem bunları görsel olarak algılar ama gerçekte executable dosyalardır.
                        </li>
                        <li style="margin-bottom: 0.5rem;">
                            <strong>Steganografi:</strong> Gizli bilgiler, şifreler veya zararlı kodlar görsellerin içine gizlenerek iletilir. Normal görünen bir görsel aslında tehlikeli içerik taşıyabilir.
                        </li>
                        <li style="margin-bottom: 0.5rem;">
                            <strong>Metadata İstismarı:</strong> GPS konum bilgisi, cihaz modeli ve çekim tarihi gibi metadata bilgileri, sosyal mühendislik saldırılarında kullanılabilir.
                        </li>
                    </ul>
                </div>
                
                <div style="background: rgba(239, 68, 68, 0.1); padding: 1.25rem; border-radius: 6px; border-left: 4px solid var(--accent-danger);">
                    <h4 style="color: var(--accent-danger); font-size: 1rem; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem;">
                        <span>⚠️</span>
                        <span>Önemli Güvenlik Uyarısı</span>
                    </h4>
                    <p style="color: var(--text-primary); font-size: 0.95rem; line-height: 1.7; margin: 0; font-weight: 600;">
                        Kaynağını bilmediğiniz dosyaları açmayın! Bilinmeyen kaynaklardan gelen görseller, URL'ler veya dosyalar güvenlik riski oluşturabilir. Özellikle e-posta eklentileri, sosyal medya paylaşımları veya şüpheli web sitelerinden gelen dosyalara karşı dikkatli olun.
                    </p>
                </div>
            </div>
        </div>
    `;
    
    resultsContent.innerHTML = html;
}

// Initialize app when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

