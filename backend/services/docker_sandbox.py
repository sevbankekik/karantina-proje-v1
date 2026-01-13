"""
Docker Sandbox Yönetimi
Dosyaları Docker konteynırı içinde izole şekilde analiz eder
"""

import os
import json
import subprocess
import logging
import tempfile
import shutil
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class DockerSandbox:
    """Docker sandbox yönetimi"""
    
    def __init__(self, docker_compose_path: Optional[str] = None):
        self.docker_compose_path = docker_compose_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            '..', 'docker', 'docker-compose.yml'
        )
        self.sandbox_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'sandbox')
        self.reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'reports')
        
        # Dizinleri oluştur
        os.makedirs(self.sandbox_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def check_docker_available(self) -> bool:
        """Docker'ın mevcut olup olmadığını kontrol et"""
        try:
            result = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def check_docker_compose_available(self) -> bool:
        """Docker Compose'un mevcut olup olmadığını kontrol et"""
        try:
            result = subprocess.run(
                ['docker-compose', '--version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # docker compose (v2) deneyelim
            try:
                result = subprocess.run(
                    ['docker', 'compose', 'version'],
                    capture_output=True,
                    timeout=5
                )
                return result.returncode == 0
            except:
                return False
    
    def build_sandbox_image(self) -> bool:
        """Sandbox Docker image'ini build et"""
        try:
            docker_dir = os.path.dirname(self.docker_compose_path)
            result = subprocess.run(
                ['docker', 'build', '-t', 'malware_sandbox', '-f', 
                 os.path.join(docker_dir, 'Dockerfile.sandbox'), docker_dir],
                capture_output=True,
                timeout=300  # 5 dakika timeout
            )
            if result.returncode == 0:
                logger.info("Sandbox image built successfully")
                return True
            else:
                logger.error(f"Sandbox build failed: {result.stderr.decode()}")
                return False
        except Exception as e:
            logger.error(f"Sandbox build error: {str(e)}")
            return False
    
    def analyze_file_in_sandbox(self, file_path: str, filename: str) -> Dict[str, Any]:
        """Dosyayı Docker sandbox içinde analiz et"""
        results = {
            'success': False,
            'static_analysis': {},
            'dynamic_analysis': {},
            'error': None
        }
        
        if not self.check_docker_available():
            results['error'] = "Docker not available"
            return results
        
        # Dosyayı sandbox dizinine kopyala
        sandbox_file_path = os.path.join(self.sandbox_dir, filename)
        try:
            shutil.copy2(file_path, sandbox_file_path)
        except Exception as e:
            results['error'] = f"File copy error: {str(e)}"
            return results
        
        # Docker konteynırı içinde analiz et
        try:
            # Docker run komutu
            docker_cmd = [
                'docker', 'run',
                '--rm',
                '--network', 'none',  # İzole network
                '--read-only',  # Read-only filesystem
                '--tmpfs', '/tmp:noexec,nosuid,size=100m',
                '--tmpfs', '/var/tmp:noexec,nosuid,size=100m',
                '--security-opt', 'no-new-privileges:true',
                '--cap-drop', 'ALL',
                '--cap-add', 'SYS_PTRACE',
                '--cap-add', 'NET_RAW',
                '--memory', '512m',
                '--cpus', '1',
                '-v', f'{self.sandbox_dir}:/sandbox/input:ro',
                '-v', f'{self.reports_dir}:/sandbox/output:rw',
                'malware_sandbox',
                'python3', '/sandbox/sandbox_analyzer.py', f'/sandbox/input/{filename}'
            ]
            
            logger.info(f"Running Docker sandbox analysis for {filename}")
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 dakika timeout
            )
            
            if result.returncode == 0:
                try:
                    # JSON output'u parse et
                    analysis_results = json.loads(result.stdout)
                    results['success'] = True
                    results['static_analysis'] = analysis_results.get('static_analysis', {})
                    results['dynamic_analysis'] = analysis_results.get('dynamic_analysis', {})
                    results['behavior_log'] = analysis_results.get('behavior_log', [])
                    results['network_activity'] = analysis_results.get('network_activity', [])
                    results['file_operations'] = analysis_results.get('file_operations', [])
                except json.JSONDecodeError:
                    results['error'] = "Failed to parse analysis results"
                    results['raw_output'] = result.stdout[:1000]
            else:
                results['error'] = f"Docker execution failed: {result.stderr[:500]}"
                results['raw_output'] = result.stdout[:1000]
                
        except subprocess.TimeoutExpired:
            results['error'] = "Analysis timeout (120s)"
        except Exception as e:
            results['error'] = f"Sandbox analysis error: {str(e)}"
        finally:
            # Geçici dosyayı temizle
            try:
                if os.path.exists(sandbox_file_path):
                    os.remove(sandbox_file_path)
            except:
                pass
        
        return results
    
    def analyze_file_direct(self, file_path: str) -> Dict[str, Any]:
        """Docker olmadan direkt analiz (fallback)"""
        # Docker yoksa, basit bir analiz yap
        from .static_analyzer import StaticAnalyzer
        
        analyzer = StaticAnalyzer(file_path)
        static_results = analyzer.analyze()
        
        return {
            'success': True,
            'static_analysis': static_results,
            'dynamic_analysis': {
                'executed': False,
                'error': 'Docker not available for dynamic analysis'
            },
            'docker_available': False
        }

