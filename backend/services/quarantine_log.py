"""
Karantina Günlüğü Servisi
Analiz sonuçlarını kaydeder ve yönetir
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class QuarantineLog:
    """Karantina günlüğü yönetimi"""
    
    def __init__(self, log_dir: Optional[str] = None):
        self.log_dir = log_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            '..', 'reports', 'quarantine_logs'
        )
        os.makedirs(self.log_dir, exist_ok=True)
    
    def create_log_entry(self, 
                         filename: str,
                         file_hash: str,
                         analysis_results: Dict[str, Any],
                         risk_score: int,
                         risk_level: str) -> Dict[str, Any]:
        """Yeni bir karantina günlüğü kaydı oluştur"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            'id': file_hash[:16],  # İlk 16 karakter hash'i ID olarak kullan
            'timestamp': timestamp,
            'filename': filename,
            'file_hash': file_hash,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'analysis_results': analysis_results,
            'status': 'quarantined' if risk_score >= 50 else 'analyzed'
        }
        
        # JSON dosyasına kaydet
        log_file = os.path.join(self.log_dir, f"{log_entry['id']}.json")
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(log_entry, f, indent=2, ensure_ascii=False)
            logger.info(f"Quarantine log entry created: {log_entry['id']}")
        except Exception as e:
            logger.error(f"Failed to save log entry: {str(e)}")
        
        return log_entry
    
    def get_log_entry(self, log_id: str) -> Optional[Dict[str, Any]]:
        """Belirli bir günlük kaydını getir"""
        log_file = os.path.join(self.log_dir, f"{log_id}.json")
        if not os.path.exists(log_file):
            return None
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load log entry: {str(e)}")
            return None
    
    def get_all_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Tüm günlük kayıtlarını getir"""
        logs = []
        try:
            log_files = sorted(
                Path(self.log_dir).glob('*.json'),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )[:limit]
            
            for log_file in log_files:
                try:
                    with open(log_file, 'r', encoding='utf-8') as f:
                        log_entry = json.load(f)
                        logs.append(log_entry)
                except Exception as e:
                    logger.warning(f"Failed to load log file {log_file}: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to get all logs: {str(e)}")
        
        return logs
    
    def search_logs(self, 
                    filename: Optional[str] = None,
                    hash: Optional[str] = None,
                    risk_level: Optional[str] = None,
                    limit: int = 50) -> List[Dict[str, Any]]:
        """Günlük kayıtlarında arama yap"""
        all_logs = self.get_all_logs(limit=limit * 2)  # Daha fazla getir, sonra filtrele
        filtered_logs = []
        
        for log in all_logs:
            match = True
            
            if filename and filename.lower() not in log.get('filename', '').lower():
                match = False
            
            if hash and hash.lower() not in log.get('file_hash', '').lower():
                match = False
            
            if risk_level and log.get('risk_level', '').lower() != risk_level.lower():
                match = False
            
            if match:
                filtered_logs.append(log)
                if len(filtered_logs) >= limit:
                    break
        
        return filtered_logs
    
    def delete_log_entry(self, log_id: str) -> bool:
        """Günlük kaydını sil"""
        log_file = os.path.join(self.log_dir, f"{log_id}.json")
        if os.path.exists(log_file):
            try:
                os.remove(log_file)
                logger.info(f"Log entry deleted: {log_id}")
                return True
            except Exception as e:
                logger.error(f"Failed to delete log entry: {str(e)}")
                return False
        return False

