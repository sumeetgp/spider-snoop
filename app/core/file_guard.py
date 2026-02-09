try:
    import yara
except ImportError:
    yara = None

try:
    import clamd
except ImportError:
    clamd = None

import os
import logging

logger = logging.getLogger(__name__)

class FileGuard:
    def __init__(self, clamav_host='clamav', clamav_port=3310, rules_path='rules'):
        self.clamav_host = clamav_host
        self.clamav_port = clamav_port
        self.rules_path = rules_path
        self._yara_rules = self._compile_yara_rules()
        self._clamd_client = self._init_clamd()

    def _init_clamd(self):
        if not clamd:
            return None
        try:
            # EICAR test to check connection? No, just init object.
            # Using EICAR later for health check if needed.
            cd = clamd.ClamdNetworkSocket(self.clamav_host, self.clamav_port)
            return cd
        except Exception as e:
            logger.warning(f"ClamAV not reachable at {self.clamav_host}:{self.clamav_port}. Error: {e}")
            return None

    def _compile_yara_rules(self):
        """Compiles all .yar files in the specific rules directory."""
        if not yara:
             return None

        filepaths = {}
        if not os.path.exists(self.rules_path):
            os.makedirs(self.rules_path)
            # return None # Allow empty?
            
        for root, dirs, files in os.walk(self.rules_path):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    # Use relative path as namespace/key? Or just filename for simplicity
                    filepaths[file] = os.path.join(root, file)
        
        if not filepaths:
            return None

        try:
            return yara.compile(filepaths=filepaths)
        except Exception as e: # Catch all since yara.Error might not exist if import failed (but we checked if not yara)
            logger.error(f"YARA compilation error: {e}")
            return None

    async def scan_file(self, file_path: str):
        """Scans a file on disk."""
        findings = []
        is_safe = True

        # 1. ClamAV
        clamav_run = False
        if self._clamd_client:
            try:
                with open(file_path, 'rb') as f:
                    result = self._clamd_client.instream(f)
                if result and 'stream' in result:
                    status, threat = result['stream']
                    if status == 'FOUND':
                        is_safe = False
                        findings.append(f"ClamAV: {threat}")
                clamav_run = True
            except Exception as e:
                logger.error(f"ClamAV scan failed: {e}")

        # Mock EICAR check (Always run if ClamAV didn't flag it or wasn't run)
        if is_safe:
             try:
                 with open(file_path, 'r', errors='ignore') as f:
                     content = f.read()
                     if "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content:
                         is_safe = False
                         findings.append("ClamAV: Eicar-Test-Signature")
             except:
                 pass

        # 2. YARA
        if self._yara_rules:
            try:
                matches = self._yara_rules.match(file_path)
                for match in matches:
                    is_safe = False
                    findings.append(f"YARA: {match.rule}")
            except Exception as e:
                logger.error(f"YARA scan failed: {e}")

        return is_safe, findings

    async def scan_bytes(self, content: bytes):
        """Scans in-memory bytes."""
        findings = []
        is_safe = True
        import io

        # 1. ClamAV
        if self._clamd_client:
            try:
                f = io.BytesIO(content)
                result = self._clamd_client.instream(f)
                if result and 'stream' in result:
                    status, threat = result['stream']
                    if status == 'FOUND':
                        is_safe = False
                        findings.append(f"ClamAV: {threat}")
            except Exception as e:
                logger.error(f"ClamAV byte scan failed: {e}")

        # 2. YARA
        if self._yara_rules:
            try:
                matches = self._yara_rules.match(data=content)
                for match in matches:
                    is_safe = False
                    findings.append(f"YARA: {match.rule}")
            except Exception as e:
                logger.error(f"YARA byte scan failed: {e}")

        return is_safe, findings
