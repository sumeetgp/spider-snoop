
"""
Metadata Extractor Engine
Extracts extended metadata from various file formats for security context.
"""
import os
import logging
import datetime
from typing import Dict, Any
from PIL import Image
from pypdf import PdfReader
import zipfile
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class MetadataExtractor:
    def extract(self, file_path: str) -> Dict[str, Any]:
        """
        Main entry point. Detects file type and extracts metadata.
        Returns a dictionary of key-value pairs.
        """
        metadata = {
            "file_size": os.path.getsize(file_path),
            "file_name": os.path.basename(file_path),
            "extension": os.path.splitext(file_path)[1].lower()
        }
        
        ext = metadata["extension"]
        
        try:
            if ext == '.pdf':
                metadata.update(self._extract_pdf(file_path))
            elif ext in ['.jpg', '.jpeg', '.png', '.tiff', '.bmp', '.gif']:
                metadata.update(self._extract_image(file_path))
            elif ext in ['.docx', '.xlsx', '.pptx']:
                 metadata.update(self._extract_office_xml(file_path))
            # Todo: Add EXE/ELF support with pefile/pyelftools if needed
            
        except Exception as e:
            logger.error(f"Metadata extraction failed for {file_path}: {e}")
            metadata["extraction_error"] = str(e)
            
        return metadata

    def _extract_pdf(self, file_path: str) -> Dict[str, Any]:
        data = {}
        try:
            reader = PdfReader(file_path)
            if reader.metadata:
                # Normalize keys
                if reader.metadata.title: data["title"] = reader.metadata.title
                if reader.metadata.author: data["author"] = reader.metadata.author
                if reader.metadata.creator: data["toolchain"] = reader.metadata.creator
                if reader.metadata.producer: data["producer"] = reader.metadata.producer
                
                # Check for JS/Actions
                try:
                    # Simple heuristic checks
                    text = str(reader.trailer)
                    if "/JS" in text or "/JavaScript" in text:
                        data["has_javascript"] = True
                    if "/OpenAction" in text:
                        data["has_open_action"] = True
                except:
                    pass
        except Exception as e:
            logger.warning(f"PDF extraction warning: {e}")
        return data

    def _extract_image(self, file_path: str) -> Dict[str, Any]:
        data = {}
        try:
            with Image.open(file_path) as img:
                data["format"] = img.format
                data["mode"] = img.mode
                data["size"] = f"{img.width}x{img.height}"
                
                # Exif Data Check
                exif = img._getexif()
                if exif:
                    data["has_exif"] = True
                    # Look for specific interesting tags (GPS, Camera, Software)
                    # 305: Software, 271: Make, 272: Model
                    # We won't dump everything to avoid noise
                    if 305 in exif: data["software"] = str(exif[305])
                    if 271 in exif: data["camera_make"] = str(exif[271])
        except Exception as e:
            logger.warning(f"Image extraction warning: {e}")
        return data

    def _extract_office_xml(self, file_path: str) -> Dict[str, Any]:
        """Parse docProps/core.xml from Office Open XML format (docx/xlsx/pptx)"""
        data = {}
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                if 'docProps/core.xml' in z.namelist():
                     with z.open('docProps/core.xml') as f:
                         tree = ET.parse(f)
                         root = tree.getroot()
                         
                         # Namespaces usually: 
                         # dc: http://purl.org/dc/elements/1.1/
                         # cp: http://schemas.openxmlformats.org/package/2006/metadata/core-properties
                         
                         namespaces = {
                             'dc': 'http://purl.org/dc/elements/1.1/',
                             'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                             'dcterms': 'http://purl.org/dc/terms/'
                         }
                         
                         creator = root.find('.//dc:creator', namespaces)
                         if creator is not None: data["author"] = creator.text
                         
                         modifier = root.find('.//cp:lastModifiedBy', namespaces)
                         if modifier is not None: data["last_modified_by"] = modifier.text
                         
                         created = root.find('.//dcterms:created', namespaces)
                         if created is not None: data["created_at"] = created.text
                         
                         modified = root.find('.//dcterms:modified', namespaces)
                         if modified is not None: data["modified_at"] = modified.text

        except Exception as e:
             logger.warning(f"Office XML extraction warning: {e}")
        return data
