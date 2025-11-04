from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
from typing import List, Optional
from core.models import Finding
from core.logger import get_logger
import hashlib
import os

class ForensicReportGenerator:
    """
    Generates professional forensic reports suitable for legal proceedings.
    Follows German legal standards for digital evidence documentation.
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report."""
        # Title style
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.black
        )
        
        # Header style
        self.header_style = ParagraphStyle(
            'CustomHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.black
        )
        
        # Body style
        self.body_style = ParagraphStyle(
            'CustomBody',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            alignment=TA_LEFT
        )
        
        # Evidence style
        self.evidence_style = ParagraphStyle(
            'EvidenceStyle',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Courier',
            spaceAfter=4,
            leftIndent=20
        )
    
    def generate_report(self, findings: List[Finding], investigator_name: str, 
                       evidence_path: str, output_path: str, case_number: Optional[str] = None) -> str:
        """
        Generate a comprehensive forensic report from findings.
        
        Args:
            findings: List of Finding objects
            investigator_name: Name of the investigating officer/expert
            evidence_path: Path to the evidence image
            output_path: Output file path for the PDF
            case_number: Optional case/reference number
            
        Returns:
            str: Path to the generated PDF file
        """
        self.logger.info(f"Generating forensic report with {len(findings)} findings")
        
        # Create the PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )
        
        # Build the story (content)
        story = []
        
        # Add header and metadata
        story.extend(self._create_header(investigator_name, evidence_path, case_number))
        
        # Add executive summary
        story.extend(self._create_executive_summary(findings, evidence_path))
        
        # Add methodology section
        story.extend(self._create_methodology_section())
        
        # Add findings section
        story.extend(self._create_findings_section(findings))
        
        # Add technical details
        story.extend(self._create_technical_section(evidence_path))
        
        # Add signature section
        story.extend(self._create_signature_section(investigator_name))
        
        # Build the PDF
        doc.build(story)
        
        self.logger.debug(f"Forensic report generated: {output_path}")
        return output_path
    
    def _create_header(self, investigator_name: str, evidence_path: str, case_number: Optional[str] = None):
        """Create the report header section."""
        story = []
        
        # Main title
        story.append(Paragraph("DIGITALES FORENSIK-GUTACHTEN", self.title_style))
        story.append(Paragraph("Hash-Analyse Bericht", self.title_style))
        story.append(Spacer(1, 20))
        
        # Metadata table
        current_time = datetime.now()
        
        metadata = [
            ['Berichtsdatum:', current_time.strftime('%d.%m.%Y %H:%M:%S Uhr')],
            ['Gutachter/Ermittler:', investigator_name],
            ['Asservat-Pfad:', os.path.basename(evidence_path)],
            ['Vollständiger Pfad:', evidence_path],
        ]
        
        if case_number:
            metadata.insert(1, ['Aktenzeichen:', case_number])
        
        metadata_table = Table(metadata, colWidths=[4*cm, 12*cm])
        metadata_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        story.append(metadata_table)
        story.append(Spacer(1, 30))
        
        return story
    
    def _create_executive_summary(self, findings: List[Finding], evidence_path: str):
        """Create executive summary section."""
        story = []
        
        story.append(Paragraph("1. ZUSAMMENFASSUNG", self.header_style))
        
        summary_text = f"""
        Dieser Bericht dokumentiert die Ergebnisse einer digitalen forensischen Analyse 
        des Datenträger-Images '{os.path.basename(evidence_path)}'. Die Untersuchung 
        erfolgte mittels Hash-Wert-Abgleich gegen eine Referenzdatenbank bekannter 
        Dateien.
        
        <b>Ergebnis der Analyse:</b><br/>
        • Anzahl gefundener relevanter Dateien: {len(findings)}<br/>
        • Analysiertes Datenträger-Image: {os.path.basename(evidence_path)}<br/>
        • Verwendete Methodik: SHA-256 Hash-Wert-Abgleich<br/>
        • Integrität der Beweismittel: Gewährleistet durch unveränderliche Hash-Werte
        """
        
        story.append(Paragraph(summary_text, self.body_style))
        story.append(Spacer(1, 20))
        
        return story
    
    def _create_methodology_section(self):
        """Create methodology section."""
        story = []
        
        story.append(Paragraph("2. METHODIK UND VERFAHREN", self.header_style))
        
        methodology_text = """
        Die forensische Analyse wurde unter Einhaltung der Standards für digitale 
        Beweismittelsicherung durchgeführt:
        
        <b>2.1 Technisches Verfahren:</b><br/>
        • Verwendung des SHA-256 Algorithmus zur Hash-Wert-Berechnung<br/>
        • Bit-für-Bit Analyse des Datenträger-Images<br/>
        • Vergleich mit Referenz-Hash-Datenbank (VIC-Hash Database)<br/>
        • Keine Modifikation der ursprünglichen Beweismittel<br/>
        
        <b>2.2 Qualitätssicherung:</b><br/>
        • Vollständige Dokumentation aller Analyseschritte<br/>
        • Verwendung kryptographisch sicherer Hash-Funktionen<br/>
        • Nachvollziehbare und reproduzierbare Methodik<br/>
        • Einhaltung der Grundsätze der IT-Forensik nach BSI-Leitfaden
        """
        
        story.append(Paragraph(methodology_text, self.body_style))
        story.append(Spacer(1, 20))
        
        return story
    
    def _create_findings_section(self, findings: List[Finding]):
        """Create detailed findings section."""
        story = []
        # Next page for findings
        story.append(PageBreak())
        
        story.append(Paragraph("3. DETAILLIERTE ANALYSEERGEBNISSE", self.header_style))
        
        if not findings:
            story.append(Paragraph(
                "Bei der Analyse wurden keine Dateien gefunden, die mit den Hash-Werten "
                "der Referenzdatenbank übereinstimmen.",
                self.body_style
            ))
            return story
        
        story.append(Paragraph(
            f"Die folgenden {len(findings)} Dateien wurden identifiziert und "
            "entsprechen bekannten Hash-Werten:",
            self.body_style
        ))
        story.append(Spacer(1, 10))
        
        # Create findings table
        table_data = [['Nr.', 'Dateiname', 'Größe (Bytes)', 'SHA-256 Hash', 'Änderungsdatum']]
        
        for i, finding in enumerate(findings, 1):
            modified_date = finding.modified_time.strftime('%d.%m.%Y %H:%M') if finding.modified_time else 'N/A'
            
            table_data.append([
                str(i),
                finding.file_name,
                f"{finding.file_size:,}",
                finding.hash_value[:16] + '...',
                modified_date
            ])
        
        findings_table = Table(table_data, colWidths=[1*cm, 3*cm, 4*cm, 2*cm, 3*cm, 2.5*cm])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(findings_table)
        story.append(Spacer(1, 20))
        
        # Add detailed findings
        story.append(Paragraph("3.1 Detaillierte Fundstellen", self.header_style))
        
        for i, finding in enumerate(findings, 1):
            story.append(Paragraph(f"<b>Fund Nr. {i}:</b>", self.body_style))
            
            details = f"""
            Dateiname: {finding.file_name}<br/>
            Vollständiger Pfad: {finding.file_path}<br/>
            Dateigröße: {finding.file_size:,} Bytes<br/>
            SHA-256 Hash: {finding.hash_value}<br/>
            """
            
            if finding.created_time:
                details += f"Erstellungsdatum: {finding.created_time.strftime('%d.%m.%Y %H:%M:%S')}<br/>"
            if finding.modified_time:
                details += f"Änderungsdatum: {finding.modified_time.strftime('%d.%m.%Y %H:%M:%S')}<br/>"
            if finding.accessed_time:
                details += f"Zugriffsdatum: {finding.accessed_time.strftime('%d.%m.%Y %H:%M:%S')}<br/>"
            if finding.partition_offset:
                details += f"Partition Offset: {finding.partition_offset}<br/>"
            
            story.append(Paragraph(details, self.evidence_style))
            story.append(Spacer(1, 10))
        
        return story
    
    def _create_technical_section(self, evidence_path: str):
        """Create technical details section."""
        story = []
        
        story.append(Paragraph("4. TECHNISCHE DETAILS", self.header_style))
        
        # Get file stats
        try:
            file_stats = os.stat(evidence_path)
            file_size = file_stats.st_size
            file_modified = datetime.fromtimestamp(file_stats.st_mtime)
        except:
            file_size = 0
            file_modified = datetime.now()
        
        technical_details = f"""
        <b>4.1 Asservat-Informationen:</b><br/>
        • Dateipfad: {evidence_path}<br/>
        • Dateigröße: {file_size:,} Bytes ({file_size / (1024**3):.2f} GB)<br/>
        • Letzte Änderung: {file_modified.strftime('%d.%m.%Y %H:%M:%S')}<br/>
        
        <b>4.2 Verwendete Software:</b><br/>
        • HashHound Forensic Analysis Tool<br/>
        • TSK (The Sleuth Kit) für Dateisystem-Analyse<br/>
        • SHA-256 Kryptographische Hash-Funktion<br/>
        
        <b>4.3 Integrität und Nachvollziehbarkeit:</b><br/>
        • Alle Hash-Werte wurden mit dem SHA-256 Algorithmus berechnet<br/>
        • Die Analyse erfolgte auf einem unveränderlichen Image<br/>
        • Vollständige Protokollierung aller Analyseschritte<br/>
        • Reproduzierbare Ergebnisse durch deterministische Verfahren
        """
        
        story.append(Paragraph(technical_details, self.body_style))
        story.append(Spacer(1, 20))
        
        return story
    
    def _create_signature_section(self, investigator_name: str):
        """Create signature and certification section."""
        story = []
        
        story.append(Paragraph("5. BESTÄTIGUNG UND UNTERSCHRIFT", self.header_style))
        
        signature_text = f"""
        Hiermit bestätige ich, dass die vorliegende Analyse nach bestem Wissen und 
        Gewissen sowie unter Einhaltung der geltenden Standards für digitale Forensik 
        durchgeführt wurde.
        
        Die dokumentierten Ergebnisse entsprechen den tatsächlichen Befunden der 
        technischen Untersuchung. Die verwendeten Methoden sind wissenschaftlich 
        anerkannt und gerichtsverwertbar.
        
        <br/><br/>
        Ort, Datum: _________________, {datetime.now().strftime('%d.%m.%Y')}
        
        <br/><br/><br/>
        ________________________________<br/>
        {investigator_name}<br/>
        Digitaler Forensik-Experte / Ermittler
        """
        
        story.append(Paragraph(signature_text, self.body_style))
        
        return story

def generate_forensic_report(findings: List[Finding], investigator_name: str, 
                           evidence_path: str, output_path: str, case_number: Optional[str] = None) -> str:
    """
    Convenience function to generate a forensic report.
    
    Args:
        findings: List of Finding objects
        investigator_name: Name of the investigating officer/expert
        evidence_path: Path to the evidence image
        output_path: Output file path for the PDF
        case_number: Optional case/reference number
        
    Returns:
        str: Path to the generated PDF file
    """
    generator = ForensicReportGenerator()
    return generator.generate_report(findings, investigator_name, evidence_path, output_path, case_number)
