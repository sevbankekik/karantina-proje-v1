"""
Statik Analiz Servisi
Hash, strings, file type, entropy, PE/ELF analizi
"""

import hashlib
import os
import subprocess
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class StaticAnalyzer:
    """Statik dosya analizi"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
    
    def calculate_hashes(self) -> Dict[str, str]:
        """Tüm hash algoritmalarını hesapla"""
        hashes = {}
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
                hashes['sha512'] = hashlib.sha512(data).hexdigest()
        except Exception as e:
            logger.error(f"Hash hesaplama hatası: {str(e)}")
        return hashes
    
    def extract_strings(self, min_length: int = 4, max_count: int = 500) -> List[str]:
        """Dosyadan string'leri çıkar"""
        strings = []
        try:
            # strings komutu kullan
            result = subprocess.run(
                ['strings', '-n', str(min_length), self.file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                all_strings = result.stdout.strip().split('\n')
                strings = all_strings[:max_count]
        except FileNotFoundError:
            # strings komutu yoksa, Python ile basit string extraction
            try:
                with open(self.file_path, 'rb') as f:
                    data = f.read()
                    # ASCII printable karakterleri bul
                    current_string = b''
                    for byte in data:
                        if 32 <= byte <= 126:  # Printable ASCII
                            current_string += bytes([byte])
                        else:
                            if len(current_string) >= min_length:
                                strings.append(current_string.decode('utf-8', errors='ignore'))
                                if len(strings) >= max_count:
                                    break
                            current_string = b''
            except Exception as e:
                logger.error(f"String extraction error: {str(e)}")
        except Exception as e:
            logger.error(f"String extraction error: {str(e)}")
        return strings
    
    def detect_file_type(self) -> Dict[str, Any]:
        """Dosya tipini tespit et"""
        file_info = {
            'mime_type': 'unknown',
            'description': 'unknown',
            'extension': Path(self.file_path).suffix.lower()
        }
        
        try:
            # file komutu kullan
            result = subprocess.run(
                ['file', '-b', '--mime-type', self.file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                file_info['mime_type'] = result.stdout.strip()
            
            result = subprocess.run(
                ['file', '-b', self.file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                file_info['description'] = result.stdout.strip()
        except FileNotFoundError:
            # file komutu yoksa, uzantıya göre tahmin et
            ext = file_info['extension']
            mime_map = {
                '.exe': 'application/x-msdownload',
                '.dll': 'application/x-msdownload',
                '.pdf': 'application/pdf',
                '.zip': 'application/zip',
                '.doc': 'application/msword',
                '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            }
            file_info['mime_type'] = mime_map.get(ext, 'application/octet-stream')
        except Exception as e:
            logger.error(f"File type detection error: {str(e)}")
        
        return file_info
    
    def calculate_entropy(self) -> float:
        """Dosya entropisini hesapla (0-8 arası)"""
        try:
            import math
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            if len(data) == 0:
                return 0.0
            
            # İlk 1MB'ı kullan (performans için)
            sample = data[:min(1024 * 1024, len(data))]
            
            # Byte frekansları
            byte_counts = {}
            for byte in sample:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            # Shannon entropy
            entropy = 0.0
            sample_len = len(sample)
            for count in byte_counts.values():
                if count > 0:
                    p = count / sample_len
                    entropy -= p * math.log2(p)
            
            return round(entropy, 2)
        except Exception as e:
            logger.error(f"Entropy calculation error: {str(e)}")
            return 0.0
    
    def analyze_pe_file(self) -> Optional[Dict[str, Any]]:
        """PE (Windows executable) dosyasını analiz et"""
        pe_info = {}
        try:
            import pefile
            pe = pefile.PE(self.file_path)
            
            pe_info['is_pe'] = True
            pe_info['machine'] = hex(pe.FILE_HEADER.Machine)
            pe_info['number_of_sections'] = pe.FILE_HEADER.NumberOfSections
            pe_info['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            pe_info['image_base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
            
            # Import'ları çıkar
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(f"{dll_name}!{imp.name.decode('utf-8', errors='ignore')}")
            pe_info['imports'] = imports[:100]  # İlk 100 import
            pe_info['import_count'] = len(imports)
            
            # Export'ları çıkar
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('utf-8', errors='ignore'))
            pe_info['exports'] = exports[:50]
            pe_info['export_count'] = len(exports)
            
            # Section'ları çıkar
            sections = []
            for section in pe.sections:
                sections.append({
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': hex(section.Characteristics)
                })
            pe_info['sections'] = sections
            
            # Resources
            resources = []
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    resources.append({
                        'type': str(resource_type.name) if resource_type.name else hex(resource_type.id)
                    })
            pe_info['resources'] = resources[:20]
            
            pe.close()
            return pe_info
        except ImportError:
            logger.warning("pefile library not available")
            return None
        except Exception as e:
            logger.error(f"PE analysis error: {str(e)}")
            return {'error': str(e)}
    
    def analyze_elf_file(self) -> Optional[Dict[str, Any]]:
        """ELF (Linux executable) dosyasını analiz et"""
        elf_info = {}
        try:
            with open(self.file_path, 'rb') as f:
                header = f.read(64)
            
            if len(header) < 64:
                return None
            
            # ELF magic number kontrolü
            if header[:4] != b'\x7fELF':
                return None
            
            elf_info['is_elf'] = True
            elf_info['class'] = '32-bit' if header[4] == 1 else '64-bit'
            elf_info['endian'] = 'little' if header[5] == 1 else 'big'
            elf_info['type'] = header[16]
            elf_info['machine'] = header[18] if header[4] == 1 else int.from_bytes(header[18:20], 'little')
            
            # readelf kullan (varsa)
            try:
                result = subprocess.run(
                    ['readelf', '-h', self.file_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    elf_info['readelf_output'] = result.stdout[:1000]
            except FileNotFoundError:
                pass
            
            return elf_info
        except Exception as e:
            logger.error(f"ELF analysis error: {str(e)}")
            return None
    
    def analyze(self) -> Dict[str, Any]:
        """Tam statik analiz"""
        results = {
            'hashes': self.calculate_hashes(),
            'file_type': self.detect_file_type(),
            'file_size': self.file_size,
            'entropy': self.calculate_entropy(),
            'strings': self.extract_strings(),
            'pe_analysis': None,
            'elf_analysis': None
        }
        
        # PE analizi
        file_type = results['file_type'].get('mime_type', '')
        if 'executable' in file_type or self.file_path.endswith(('.exe', '.dll', '.sys', '.scr')):
            results['pe_analysis'] = self.analyze_pe_file()
        
        # ELF analizi
        if 'elf' in file_type.lower() or self.file_path.endswith(('.elf', '.so', '.bin')):
            results['elf_analysis'] = self.analyze_elf_file()
        
        return results

