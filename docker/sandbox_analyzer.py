#!/usr/bin/env python3
"""
Malware Sandbox Analyzer
Docker konteynırı içinde dosya analizi yapan script
"""

import os
import sys
import json
import hashlib
import subprocess
import time
import signal
from pathlib import Path
from typing import Dict, List, Any

# Timeout (saniye)
TIMEOUT = int(os.getenv('SANDBOX_TIMEOUT', '60'))

class SandboxAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.results = {
            'static_analysis': {},
            'dynamic_analysis': {},
            'behavior_log': [],
            'network_activity': [],
            'file_operations': [],
            'process_tree': [],
            'errors': []
        }
    
    def calculate_hashes(self) -> Dict[str, str]:
        """Dosya hash'lerini hesapla"""
        hashes = {}
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
                hashes['sha512'] = hashlib.sha512(data).hexdigest()
        except Exception as e:
            self.results['errors'].append(f"Hash hesaplama hatası: {str(e)}")
        return hashes
    
    def extract_strings(self, min_length: int = 4) -> List[str]:
        """Dosyadan string'leri çıkar"""
        strings = []
        try:
            result = subprocess.run(
                ['strings', '-n', str(min_length), self.file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                strings = result.stdout.strip().split('\n')
        except subprocess.TimeoutExpired:
            self.results['errors'].append("Strings extraction timeout")
        except Exception as e:
            self.results['errors'].append(f"Strings extraction error: {str(e)}")
        return strings
    
    def detect_file_type(self) -> Dict[str, Any]:
        """Dosya tipini tespit et"""
        file_info = {}
        try:
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
        except Exception as e:
            self.results['errors'].append(f"File type detection error: {str(e)}")
        return file_info
    
    def analyze_pe_file(self) -> Dict[str, Any]:
        """PE (Windows executable) dosyasını analiz et"""
        pe_info = {}
        try:
            import pefile
            pe = pefile.PE(self.file_path)
            
            pe_info['is_pe'] = True
            pe_info['machine'] = hex(pe.FILE_HEADER.Machine)
            pe_info['number_of_sections'] = pe.FILE_HEADER.NumberOfSections
            pe_info['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            
            # Import'ları çıkar
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(f"{dll_name}!{imp.name.decode('utf-8', errors='ignore')}")
            pe_info['imports'] = imports[:50]  # İlk 50 import
            
            # Section'ları çıkar
            sections = []
            for section in pe.sections:
                sections.append({
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'size': section.SizeOfRawData
                })
            pe_info['sections'] = sections
            
            pe.close()
        except ImportError:
            pe_info['error'] = "pefile library not available"
        except Exception as e:
            pe_info['error'] = str(e)
        return pe_info
    
    def run_dynamic_analysis(self) -> Dict[str, Any]:
        """Dinamik analiz - dosyayı çalıştır ve davranışı izle"""
        dynamic_results = {
            'executed': False,
            'exit_code': None,
            'execution_time': 0,
            'strace_output': '',
            'network_calls': [],
            'file_operations': []
        }
        
        # Dosya executable mı kontrol et
        if not os.access(self.file_path, os.X_OK):
            dynamic_results['error'] = "File is not executable"
            return dynamic_results
        
        try:
            # strace ile çalıştır
            start_time = time.time()
            strace_cmd = [
                'strace',
                '-f',  # Follow forks
                '-e', 'trace=network,file,process',
                '-o', '/tmp/strace_output.txt',
                self.file_path
            ]
            
            process = subprocess.Popen(
                strace_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT
            )
            
            try:
                stdout, stderr = process.communicate(timeout=TIMEOUT)
                execution_time = time.time() - start_time
                
                dynamic_results['executed'] = True
                dynamic_results['exit_code'] = process.returncode
                dynamic_results['execution_time'] = execution_time
                dynamic_results['stdout'] = stdout.decode('utf-8', errors='ignore')[:1000]
                dynamic_results['stderr'] = stderr.decode('utf-8', errors='ignore')[:1000]
                
                # strace output'unu oku
                try:
                    with open('/tmp/strace_output.txt', 'r') as f:
                        strace_output = f.read()
                        dynamic_results['strace_output'] = strace_output[:5000]  # İlk 5000 karakter
                        
                        # Network çağrılarını parse et
                        network_calls = []
                        for line in strace_output.split('\n'):
                            if 'socket' in line or 'connect' in line or 'sendto' in line:
                                network_calls.append(line.strip())
                        dynamic_results['network_calls'] = network_calls[:20]
                        
                        # Dosya işlemlerini parse et
                        file_ops = []
                        for line in strace_output.split('\n'):
                            if 'open' in line or 'read' in line or 'write' in line:
                                file_ops.append(line.strip())
                        dynamic_results['file_operations'] = file_ops[:20]
                except:
                    pass
                    
            except subprocess.TimeoutExpired:
                process.kill()
                dynamic_results['error'] = f"Execution timeout ({TIMEOUT}s)"
                dynamic_results['execution_time'] = TIMEOUT
                
        except Exception as e:
            dynamic_results['error'] = str(e)
        
        return dynamic_results
    
    def analyze(self) -> Dict[str, Any]:
        """Tam analiz"""
        print(f"Analyzing file: {self.file_path}", file=sys.stderr)
        
        # Statik analiz
        self.results['static_analysis']['hashes'] = self.calculate_hashes()
        self.results['static_analysis']['file_type'] = self.detect_file_type()
        self.results['static_analysis']['strings'] = self.extract_strings()[:100]  # İlk 100 string
        
        # PE analizi (eğer PE dosyasıysa)
        file_type = self.results['static_analysis']['file_type'].get('mime_type', '')
        if 'executable' in file_type or self.file_path.endswith(('.exe', '.dll', '.sys')):
            self.results['static_analysis']['pe_analysis'] = self.analyze_pe_file()
        
        # Dinamik analiz
        self.results['dynamic_analysis'] = self.run_dynamic_analysis()
        
        return self.results

def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'File path required'}), file=sys.stderr)
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(json.dumps({'error': 'File not found'}), file=sys.stderr)
        sys.exit(1)
    
    analyzer = SandboxAnalyzer(file_path)
    results = analyzer.analyze()
    
    # Sonuçları JSON olarak çıktıla
    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    main()

