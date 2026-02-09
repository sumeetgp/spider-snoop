
"""
Static Analysis Engine
Performs heuristic analysis on files: Entropy, Magic Numbers, Macros.
"""
import math
import os
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class StaticAnalyzer:
    def analyze(self, file_path: str) -> Dict[str, Any]:
        results = {
            "entropy": 0.0,
            "is_packed": False,
            "magic_match": True,
            "suspicious_macros": []
        }
        
        try:
            # 1. Entropy & Packing
            with open(file_path, 'rb') as f:
                data = f.read()
                entropy = self._calculate_entropy(data)
                results["entropy"] = round(entropy, 4)
                
                # Heuristic: High entropy (> 7.0) often implies packing or encryption
                # compressed files (zip/png) also have high entropy, so filtering by extension is needed in policy
                if entropy > 7.5: 
                    results["is_packed"] = True

            # 2. Magic Number Check
            results["magic_match"] = self._check_magic(file_path, data[:16])

            # 3. Macro Scanning (Office Docs)
            if file_path.endswith(('.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm', '.xml')):
                results["suspicious_macros"] = self._scan_macros(file_path, data)

        except Exception as e:
            logger.error(f"Static analysis failed for {file_path}: {e}")
            results["error"] = str(e)
            
        return results

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
            
        occurences = [0] * 256
        for byte in data:
            occurences[byte] += 1
            
        entropy = 0
        len_data = len(data)
        for count in occurences:
            if count == 0:
                continue
            p = count / len_data
            entropy -= p * math.log2(p)
            
        return entropy

    def _check_magic(self, file_path: str, header: bytes) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        
        # Define known headers
        magic_map = {
            '.pdf': [b'%PDF-'],
            '.exe': [b'MZ'],
            '.dll': [b'MZ'],
            '.zip': [b'PK\x03\x04'],
            '.docx': [b'PK\x03\x04'],
            '.xlsx': [b'PK\x03\x04'],
            '.jar': [b'PK\x03\x04'],
            '.png': [b'\x89PNG\r\n\x1a\n'],
            '.jpg': [b'\xff\xd8\xff'],
            '.jpeg': [b'\xff\xd8\xff'],
            '.elf': [b'\x7fELF']
        }
        
        if ext in magic_map:
            for magic in magic_map[ext]:
                if header.startswith(magic):
                    return True
            return False
            
        return True # Unknown extension, assume match (fail open)

    def _scan_macros(self, file_path: str, data: bytes) -> List[str]:
        findings = []
        try:
            from oletools.olevba import VBA_Parser
            vba = VBA_Parser(file_path, data=data)
            
            if vba.detect_vba_macros():
                results = vba.analyze_macros()
                for kw_type, keyword, description in results:
                    if kw_type in ['Suspicious', 'AutoExec']:
                        findings.append(f"{kw_type}: {keyword} - {description}")
            
            vba.close()
        except ImportError:
            logger.warning("oletools not installed, skipping macro scan")
        except Exception as e:
            logger.warning(f"Macro scan failed: {e}")
            
        return findings
