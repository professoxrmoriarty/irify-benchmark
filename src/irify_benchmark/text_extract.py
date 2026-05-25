from __future__ import annotations

import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


def extract_pdf_text(path: Path) -> str:
    try:
        import fitz

        with fitz.open(str(path)) as document:
            return "\n".join(page.get_text() for page in document)
    except Exception:
        import PyPDF2

        reader = PyPDF2.PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)


def extract_docx_text(path: Path) -> str:
    namespace = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    with zipfile.ZipFile(path) as archive:
        xml = archive.read("word/document.xml")
    root = ET.fromstring(xml)
    paragraphs: list[str] = []
    for paragraph in root.iter(namespace + "p"):
        text = "".join(node.text or "" for node in paragraph.iter(namespace + "t")).strip()
        if text:
            paragraphs.append(text)
    return "\n".join(paragraphs)

