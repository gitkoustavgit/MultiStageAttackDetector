"""
build_final_template_report.py

Assembles the finalized report into Final_Template.docx preserving all original styles,
fonts, section layouts, and formatting.
"""

import os
import shutil
import zipfile
import copy
import docx
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

BLACK = RGBColor(0, 0, 0)
FONT_NAME = "Times New Roman"

PROJECT_TITLE = "CONTEXT-AWARE AI-BASED DETECTION OF MULTI-STAGE WEB INJECTION ATTACKS USING SEQUENTIAL HTTP REQUEST ANALYSIS"
PROJECT_TITLE_TITLECASE = "Context-Aware AI-Based Detection of Multi-Stage Web Injection Attacks Using Sequential HTTP Request Analysis"
PROGRAMME_NAME = "Computer Science and Engineering with Specialization in Information Security"

STUDENTS = [
    ("23BCI0056", "KOUSTAV MITRA"),
    ("23BCI0060", "M. SRIKAR BHARADWAJ"),
    ("23BCE2262", "R. PHANINDRA SANJAY"),
]

GUIDE_NAME = "Dr. Ganesh Shamrao Khekare"
GUIDE_DESIG = "Assistant Professor Sr. Grade 2"
GUIDE_DEPT = "School of Computer Science and Engineering (SCOPE)"

TPL_PATH = r"C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\Final_Template.docx.bak"
REP_PATH = r"C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\BCSE497J Project I Report.docx"
OUT_PATH = r"C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\Final_Template.docx"
MEDIA_DIR = r"C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\MultiStageAttackDetector\extracted_images"

REMAP_RELS = {
    "rId10": ("rId100", "media/image2.png"),
    "rId11": ("rId101", "media/image3.png"),
    "rId12": ("rId102", "media/image4.png"),
    "rId13": ("rId103", "media/image5.png"),
    "rId14": ("rId104", "media/image6.png"),
    "rId15": ("rId105", "media/image7.png"),
    "rId16": ("rId106", "media/image8.png"),
    "rId19": ("rId107", "media/image9.png"),
    "rId20": ("rId108", "media/image10.png"),
    "rId21": ("rId109", "media/image11.png"),
    "rId22": ("rId110", "media/image12.png"),
}

def set_run_font(run, size_pt=12, bold=False, italic=False, font_name=FONT_NAME, color=BLACK):
    run.font.name = font_name
    if size_pt:
        run.font.size = Pt(size_pt)
    run.bold = bold
    run.italic = italic
    run.font.color.rgb = color
    # clear highlight
    run.font.highlight_color = None

def format_cell(cell, text="", bold=False, italic=False, size_pt=11, align=WD_ALIGN_PARAGRAPH.LEFT):
    p = cell.paragraphs[0]
    p.text = ""
    p.alignment = align
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.05
    if text:
        r = p.add_run(text)
        set_run_font(r, size_pt=size_pt, bold=bold, italic=italic)

def style_table(table, col_widths=None):
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = 'Table Grid'
    if col_widths:
        for row in table.rows:
            for idx, width in enumerate(col_widths):
                if idx < len(row.cells):
                    row.cells[idx].width = Inches(width)
    for row in table.rows:
        trPr = row._tr.get_or_add_trPr()
        trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))

def set_cell_bg(cell, hex_color="F2F2F2"):
    tcPr = cell._element.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tcPr.append(shd)

def main():
    print("Loading Final_Template.docx.bak...")
    doc = docx.Document(TPL_PATH)
    doc_rep = docx.Document(REP_PATH)

    # ---------------------------------------------------------
    # 1. COVER PAGE (Paragraphs 0 to 24)
    # ---------------------------------------------------------
    print("Updating Cover Page...")
    # P2: Project Title
    p2 = doc.paragraphs[2]
    p2.text = ""
    p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p2.paragraph_format.line_spacing = 1.5
    p2.paragraph_format.space_before = Pt(6)
    p2.paragraph_format.space_after = Pt(4)
    r2 = p2.add_run(PROJECT_TITLE)
    set_run_font(r2, size_pt=18, bold=True)

    # P3: Hint -> Clear
    p3 = doc.paragraphs[3]
    p3.text = ""

    # P12: Programme
    p12 = doc.paragraphs[12]
    p12.text = ""
    p12.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r12 = p12.add_run(PROGRAMME_NAME)
    set_run_font(r12, size_pt=19, bold=True)

    # P16: Hint -> Clear
    p16 = doc.paragraphs[16]
    p16.text = ""

    # Table 0: Students
    t0 = doc.tables[0]
    for r_idx, (reg, name) in enumerate(STUDENTS):
        format_cell(t0.rows[r_idx].cells[0], reg, bold=True, size_pt=16, align=WD_ALIGN_PARAGRAPH.LEFT)
        format_cell(t0.rows[r_idx].cells[1], name, bold=True, size_pt=16, align=WD_ALIGN_PARAGRAPH.LEFT)

    # Table 1: Guide
    t1 = doc.tables[1]
    format_cell(t1.rows[0].cells[0], GUIDE_NAME, bold=True, size_pt=16, align=WD_ALIGN_PARAGRAPH.CENTER)
    format_cell(t1.rows[1].cells[0], GUIDE_DESIG, bold=False, size_pt=16, align=WD_ALIGN_PARAGRAPH.CENTER)
    format_cell(t1.rows[2].cells[0], GUIDE_DEPT, bold=False, size_pt=16, align=WD_ALIGN_PARAGRAPH.CENTER)

    # ---------------------------------------------------------
    # 2. DECLARATION (P25 to P44)
    # ---------------------------------------------------------
    print("Updating Declaration...")
    p27 = doc.paragraphs[27]
    p27.text = ""
    p27.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p27.paragraph_format.line_spacing = 1.5
    r27_1 = p27.add_run("I hereby declare that the project entitled ")
    set_run_font(r27_1, size_pt=12)
    r27_title = p27.add_run(f'"{PROJECT_TITLE_TITLECASE}"')
    set_run_font(r27_title, size_pt=12, bold=True)
    r27_2 = p27.add_run(
        " submitted by me, for the award of the degree of Bachelor of Technology in Computer Science and Engineering to "
        "Vellore Institute of Technology is a record of bonafide work carried out by me under the supervision of "
    )
    set_run_font(r27_2, size_pt=12)
    r27_guide = p27.add_run(f"{GUIDE_NAME}.")
    set_run_font(r27_guide, size_pt=12, bold=True)

    # P37: Candidate signatures
    p37 = doc.paragraphs[37]
    p37.text = ""
    r37 = p37.add_run("Signature of the Candidate(s):\n\n")
    set_run_font(r37, size_pt=12, bold=True)
    for reg, name in STUDENTS:
        r_cand = p37.add_run(f"{name} ({reg})\n")
        set_run_font(r_cand, size_pt=11, bold=False)

    # P43: Hint -> Clear
    p43 = doc.paragraphs[43]
    p43.text = ""

    # ---------------------------------------------------------
    # 3. CERTIFICATE (P45 to P70)
    # ---------------------------------------------------------
    print("Updating Certificate...")
    p47 = doc.paragraphs[47]
    p47.text = ""
    p47.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p47.paragraph_format.line_spacing = 1.5
    r47_1 = p47.add_run("This is to certify that the project entitled ")
    set_run_font(r47_1, size_pt=12)
    r47_title = p47.add_run(f'"{PROJECT_TITLE_TITLECASE}"')
    set_run_font(r47_title, size_pt=12, bold=True)
    r47_2 = p47.add_run(" submitted by ")
    set_run_font(r47_2, size_pt=12)
    cand_str = ", ".join([f"{name} ({reg})" for reg in [s[0] for s in STUDENTS] for name in [s[1] for s in STUDENTS if s[0] == reg]])
    r47_cands = p47.add_run(f"{STUDENTS[0][1]} ({STUDENTS[0][0]}), {STUDENTS[1][1]} ({STUDENTS[1][0]}), and {STUDENTS[2][1]} ({STUDENTS[2][0]})")
    set_run_font(r47_cands, size_pt=12, bold=True)
    r47_3 = p47.add_run(
        ", School of Computer Science and Engineering, VIT, for the award of the degree of Bachelor of Technology in "
        "Computer Science and Engineering, is a record of bonafide work carried out by them under my supervision during "
        "Fall Semester 2024-2025, as per the VIT code of academic and research ethics."
    )
    set_run_font(r47_3, size_pt=12)

    # P58: Guide Signature block
    p58 = doc.paragraphs[58]
    p58.text = ""
    r58_1 = p58.add_run("Signature of the Guide:\n\n\n")
    set_run_font(r58_1, size_pt=12, bold=True)
    r58_2 = p58.add_run(f"{GUIDE_NAME}\n{GUIDE_DESIG}\n{GUIDE_DEPT}")
    set_run_font(r58_2, size_pt=11, bold=False)

    # P69: Hint -> Clear
    p69 = doc.paragraphs[69]
    p69.text = ""

    # ---------------------------------------------------------
    # 4. ACKNOWLEDGEMENTS (P75 to P92)
    # ---------------------------------------------------------
    print("Updating Acknowledgements...")
    p85 = doc.paragraphs[85]
    p85.text = ""
    p85.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p85.paragraph_format.line_spacing = 1.15
    r85_1 = p85.add_run("I am immensely thankful to my project guide, ")
    set_run_font(r85_1, size_pt=12)
    r85_guide = p85.add_run(GUIDE_NAME)
    set_run_font(r85_guide, size_pt=12, bold=True)
    r85_2 = p85.add_run(
        ", for his dedicated mentorship and invaluable feedback. His patience, knowledge, and encouragement have "
        "been pivotal in the successful completion of this project. My supervisor's willingness to share his expertise "
        "and provide thoughtful guidance has been instrumental in refining my ideas and methodologies. His support has "
        "not only contributed to the success of this project but has also enriched my overall academic experience."
    )
    set_run_font(r85_2, size_pt=12)

    p91 = doc.paragraphs[91]
    p91.text = ""
    r91_h = p91.add_run("Name of the Candidate(s):\n\n")
    set_run_font(r91_h, size_pt=12, bold=True)
    for reg, name in STUDENTS:
        r_c = p91.add_run(f"{name} ({reg})\n")
        set_run_font(r_c, size_pt=11, bold=False)

    # ---------------------------------------------------------
    # 5. TABLE OF CONTENTS (Table 2)
    # ---------------------------------------------------------
    print("Populating Table of Contents (Table 2)...")
    p94 = doc.paragraphs[94]
    p94.text = "" # Clear hint

    toc = doc.tables[2]
    # Remove all rows except header
    for row in list(toc.rows)[1:]:
        toc._tbl.remove(row._tr)

    toc_entries = [
        # (Sl.No, Contents, Page No., is_major)
        ("", "Abstract", "xiii", False),
        ("1.", "INTRODUCTION", "1", True),
        ("", "1.1 Background", "1", False),
        ("", "1.2 Motivation", "2", False),
        ("", "1.3 Scope of the Project", "2", False),
        ("2.", "PROJECT DESCRIPTION AND GOALS", "4", True),
        ("", "2.1 Literature Review", "4", False),
        ("", "2.2 Research Gap", "5", False),
        ("", "2.3 Objectives", "5", False),
        ("", "2.4 Problem Statement", "6", False),
        ("", "2.5 Project Plan", "6", False),
        ("3.", "TECHNICAL SPECIFICATION", "8", True),
        ("", "3.1 Requirements", "8", False),
        ("", "3.1.1 Functional Requirements", "8", False),
        ("", "3.1.2 Non-Functional Requirements", "8", False),
        ("", "3.2 Feasibility Study", "9", False),
        ("", "3.2.1 Technical Feasibility", "9", False),
        ("", "3.2.2 Economic Feasibility", "10", False),
        ("", "3.2.3 Social and Ethical Feasibility", "10", False),
        ("", "3.3 System Specification", "10", False),
        ("", "3.3.1 Hardware Specification", "10", False),
        ("", "3.3.2 Software Specification", "11", False),
        ("4.", "DESIGN APPROACH AND DETAILS", "12", True),
        ("", "4.1 System Architecture", "12", False),
        ("", "4.2 Design", "12", False),
        ("", "4.2.1 Data Flow Diagram", "13", False),
        ("", "4.2.2 Use Case Diagram", "14", False),
        ("", "4.2.3 Class Diagram", "15", False),
        ("", "4.2.4 Sequence Diagram", "15", False),
        ("5.", "IMPLEMENTATION AND EXPERIMENTAL METHODOLOGY", "17", True),
        ("", "5.1 Implementation Environment and Specifications", "17", False),
        ("", "5.2 Five-Stage Attack Taxonomy and Operational Scope", "17", False),
        ("", "5.3 Dataset Construction and In-House Testbed", "18", False),
        ("", "5.4 The 31 Causal Feature Engineering Framework", "21", False),
        ("", "5.5 Machine Learning Baseline Models", "24", False),
        ("", "5.6 Hidden Markov Model (HMM) Transition Dynamics", "25", False),
        ("", "5.7 Causal Ensemble Architecture and Decision Logic", "25", False),
        ("", "5.8 Evaluation Metrics", "26", False),
        ("", "5.9 Experimental Setup and Reproducibility", "27", False),
        ("6.", "RESULTS AND EVALUATION", "28", True),
        ("", "6.1 Benchmark Comparison on Held-Out Test Set", "28", False),
        ("", "6.2 Per-Class Performance and Confusion Matrix Analysis", "29", False),
        ("", "6.3 Transition Edge Accuracy and Sequential Consistency", "30", False),
        ("", "6.4 False-Positive Rate Reduction via Temporal Context", "31", False),
        ("", "6.5 Session-Level Attack Campaign Detection", "31", False),
        ("", "6.6 Early Detection Latency & Defensive Lead Time", "32", False),
        ("", "6.7 Next-Stage Attack Intent Forecasting", "33", False),
        ("", "6.8 Real-Time Streaming and Inference Latency", "34", False),
        ("7.", "DISCUSSION", "36", True),
        ("", "7.1 The Value of Context in Web Application Security", "36", False),
        ("", "7.2 Error Analysis: The Fuzzing-Injection Boundary", "36", False),
        ("", "7.3 Operational Feasibility in Security Operations Centers", "37", False),
        ("", "7.4 Latency vs. Accuracy Trade-Off", "37", False),
        ("", "7.5 Partitioning Protocol and Data Disjunction Analysis", "38", False),
        ("", "7.6 Threats to Validity and Limitations", "38", False),
        ("8.", "CONCLUSION AND FUTURE WORK", "40", True),
        ("", "8.1 Summary of Contributions", "40", False),
        ("", "8.2 Future Research Directions", "40", False),
        ("9.", "REFERENCES", "42", True),
    ]

    for sl_no, title, page_no, is_major in toc_entries:
        row = toc.add_row()
        format_cell(row.cells[0], sl_no, bold=is_major, size_pt=11, align=WD_ALIGN_PARAGRAPH.LEFT)
        format_cell(row.cells[1], title, bold=is_major, size_pt=11, align=WD_ALIGN_PARAGRAPH.LEFT)
        format_cell(row.cells[2], page_no, bold=is_major, size_pt=11, align=WD_ALIGN_PARAGRAPH.RIGHT)

    # ---------------------------------------------------------
    # 6. LIST OF FIGURES (Table 3)
    # ---------------------------------------------------------
    print("Populating List of Figures (Table 3)...")
    p105 = doc.paragraphs[105]
    p105.text = "" # Clear hint

    tbl_figs = doc.tables[3]
    for row in list(tbl_figs.rows)[1:]:
        tbl_figs._tbl.remove(row._tr)

    figures_data = [
        ("1", "Gantt Chart and Project Schedule", "7"),
        ("2", "High-Level Conceptual System Architecture of Multi-Stage Detector", "12"),
        ("3", "Level 0 Context Data Flow Diagram (DFD)", "13"),
        ("4", "Level 1 Detailed Functional Data Flow Diagram (DFD)", "14"),
        ("5", "Unified System Use Case Diagram", "15"),
        ("6", "Comprehensive System Class Diagram", "15"),
        ("7", "Sequential Transaction Processing Sequence Diagram", "16"),
        ("8", "Request Distribution Across Attack Stages (Train, Val, Test)", "21"),
        ("9", "5x5 Empirical Confusion Matrix Heatmap on Held-Out Test Set", "30"),
        ("10", "Cumulative Attack Campaign Detection Latency Distribution", "33"),
        ("11", "Real-Time Streaming Detection Run Console Output", "35"),
    ]

    for fig_no, title, page_no in figures_data:
        row = tbl_figs.add_row()
        format_cell(row.cells[0], fig_no, bold=False, size_pt=11, align=WD_ALIGN_PARAGRAPH.CENTER)
        format_cell(row.cells[1], title, bold=False, size_pt=11, align=WD_ALIGN_PARAGRAPH.LEFT)
        format_cell(row.cells[2], page_no, bold=False, size_pt=11, align=WD_ALIGN_PARAGRAPH.RIGHT)

    # ---------------------------------------------------------
    # 7. LIST OF TABLES
    # ---------------------------------------------------------
    print("Populating List of Tables...")
    # Clear P109 and P110
    doc.paragraphs[109].text = ""
    doc.paragraphs[110].text = ""

    # Insert a structured table for List of Tables right after P107
    p107 = doc.paragraphs[107]
    # We will create a table after P107 using oxml
    tbl_tables_xml = parse_xml(f'''
        <w:tbl {nsdecls("w")}>
            <w:tblPr>
                <w:tblStyle w:val="TableGrid"/>
                <w:tblW w:w="0" w:type="auto"/>
                <w:jc w:val="center"/>
            </w:tblPr>
            <w:tblGrid>
                <w:gridCol w:w="1200"/>
                <w:gridCol w:w="6000"/>
                <w:gridCol w:w="1400"/>
            </w:tblGrid>
            <w:tr>
                <w:tc><w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="{FONT_NAME}" w:hAnsi="{FONT_NAME}"/><w:b/><w:sz w:val="24"/></w:rPr><w:t>Table No.</w:t></w:r></w:p></w:tc>
                <w:tc><w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="{FONT_NAME}" w:hAnsi="{FONT_NAME}"/><w:b/><w:sz w:val="24"/></w:rPr><w:t>Title</w:t></w:r></w:p></w:tc>
                <w:tc><w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="{FONT_NAME}" w:hAnsi="{FONT_NAME}"/><w:b/><w:sz w:val="24"/></w:rPr><w:t>Page No.</w:t></w:r></w:p></w:tc>
            </w:tr>
        </w:tbl>
    ''')
    p107._p.addnext(tbl_tables_xml)
    tbl_tables = docx.table.Table(tbl_tables_xml, doc)

    tables_data = [
        ("1", "Experimental Testbed Specifications and Software Environment", "17"),
        ("2", "Operational Five-Stage Web Injection Attack Taxonomy", "18"),
        ("3", "Summary of In-House Multi-Stage Web Intrusion Dataset", "20"),
        ("4", "The 31 Causal Feature Set for Context-Aware Web Intrusion Detection", "22"),
        ("5", "Comprehensive Model Benchmark Comparison on 10,174 Held-Out Test Requests", "28"),
        ("6", "Class-Wise Performance Metrics of Deployed Causal Ensemble on Held-Out Test Set", "29"),
        ("7", "5x5 Empirical Confusion Matrix of Deployed Model on 10,174 Test Requests", "29"),
        ("8", "Session-Level Campaign Detection Rates and Benign Session False Alarm Rates", "31"),
        ("9", "Next-Distinct-Stage Intent Forecasting Accuracy at 754 Real Phase Transitions", "34"),
    ]

    for t_no, title, page_no in tables_data:
        row = tbl_tables.add_row()
        format_cell(row.cells[0], t_no, bold=False, size_pt=11, align=WD_ALIGN_PARAGRAPH.CENTER)
        format_cell(row.cells[1], title, bold=False, size_pt=11, align=WD_ALIGN_PARAGRAPH.LEFT)
        format_cell(row.cells[2], page_no, bold=False, size_pt=11, align=WD_ALIGN_PARAGRAPH.RIGHT)

    # ---------------------------------------------------------
    # 8. LIST OF ABBREVIATIONS
    # ---------------------------------------------------------
    print("Populating List of Abbreviations...")
    # Clear dummy abbreviation paragraphs from 114 to 128
    for idx in range(114, 129):
        doc.paragraphs[idx].text = ""

    abbreviations = [
        ("AI", "Artificial Intelligence"),
        ("ANN", "Artificial Neural Network"),
        ("API", "Application Programming Interface"),
        ("ATT&CK", "Adversarial Tactics, Techniques, and Common Knowledge"),
        ("AUC", "Area Under the Curve"),
        ("AVX2", "Advanced Vector Extensions 2"),
        ("CDF", "Cumulative Distribution Function"),
        ("CICIDS", "Canadian Institute for Cybersecurity Intrusion Detection System"),
        ("CPU", "Central Processing Unit"),
        ("CSV", "Comma-Separated Values"),
        ("DFD", "Data Flow Diagram"),
        ("DVWA", "Damn Vulnerable Web Application"),
        ("ECE", "Expected Calibration Error"),
        ("FAR", "False Alarm Rate"),
        ("FLOP", "Floating-Point Operations"),
        ("FPR", "False-Positive Rate"),
        ("GPU", "Graphics Processing Unit"),
        ("HMM", "Hidden Markov Model"),
        ("HTTP", "Hypertext Transfer Protocol"),
        ("HTTPS", "Hypertext Transfer Protocol Secure"),
        ("IDS", "Intrusion Detection System"),
        ("IP", "Internet Protocol"),
        ("JSON", "JavaScript Object Notation"),
        ("KDD", "Knowledge Discovery in Databases"),
        ("LLM", "Large Language Model"),
        ("LSTM", "Long Short-Term Memory"),
        ("ML", "Machine Learning"),
        ("NIDS", "Network Intrusion Detection System"),
        ("NVMe", "Non-Volatile Memory Express"),
        ("OWASP", "Open Worldwide Application Security Project"),
        ("RAM", "Random Access Memory"),
        ("REST", "Representational State Transfer"),
        ("RNN", "Recurrent Neural Network"),
        ("ROC", "Receiver Operating Characteristic"),
        ("SCADA", "Supervisory Control and Data Acquisition"),
        ("SOC", "Security Operations Center"),
        ("SQL", "Structured Query Language"),
        ("SQLi", "SQL Injection"),
        ("SSD", "Solid State Drive"),
        ("SVM", "Support Vector Machine"),
        ("TCP", "Transmission Control Protocol"),
        ("TLS", "Transport Layer Security"),
        ("TOC", "Table of Contents"),
        ("URI", "Uniform Resource Identifier"),
        ("URL", "Uniform Resource Locator"),
        ("Viterbi", "Viterbi Dynamic Programming Decoding Algorithm"),
        ("WAF", "Web Application Firewall"),
        ("XML", "Extensible Markup Language"),
        ("XSS", "Cross-Site Scripting"),
    ]

    p112 = doc.paragraphs[112] # Heading
    # Create clean 2-column table for abbreviations
    tbl_abbr_xml = parse_xml(f'''
        <w:tbl {nsdecls("w")}>
            <w:tblPr>
                <w:tblStyle w:val="TableGrid"/>
                <w:tblW w:w="0" w:type="auto"/>
                <w:jc w:val="center"/>
            </w:tblPr>
            <w:tblGrid>
                <w:gridCol w:w="2200"/>
                <w:gridCol w:w="6400"/>
            </w:tblGrid>
            <w:tr>
                <w:tc><w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="{FONT_NAME}" w:hAnsi="{FONT_NAME}"/><w:b/><w:sz w:val="22"/></w:rPr><w:t>Abbreviation</w:t></w:r></w:p></w:tc>
                <w:tc><w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="{FONT_NAME}" w:hAnsi="{FONT_NAME}"/><w:b/><w:sz w:val="22"/></w:rPr><w:t>Full Definition / Expansion</w:t></w:r></w:p></w:tc>
            </w:tr>
        </w:tbl>
    ''')
    p112._p.addnext(tbl_abbr_xml)
    tbl_abbr = docx.table.Table(tbl_abbr_xml, doc)

    for abbr, full_def in abbreviations:
        row = tbl_abbr.add_row()
        format_cell(row.cells[0], abbr, bold=True, size_pt=10.5, align=WD_ALIGN_PARAGRAPH.LEFT)
        format_cell(row.cells[1], full_def, bold=False, size_pt=10.5, align=WD_ALIGN_PARAGRAPH.LEFT)

    # ---------------------------------------------------------
    # 9. SYMBOLS AND NOTATIONS
    # ---------------------------------------------------------
    print("Populating Symbols and Notations...")
    # Clear dummy symbols in 132-140
    for idx in range(132, 145):
        doc.paragraphs[idx].text = ""

    symbols = [
        ("E", "Set of transition points (edges) across requests where state boundaries occur (|E| = 1,054)"),
        ("alpha_t(j)", "Causal forward joint probability variable at time t for latent attack stage j"),
        ("b_t(j)", "Normalized Bayesian belief state distribution over K = 5 attack stages at time t"),
        ("A_ij", "State transition probability from stage i to stage j: P(q_{t+1} = s_j | q_t = s_i)"),
        ("B", "Normalized off-diagonal transition matrix with self-loops removed: norm(A - diag(A))"),
        ("e_{t, j}", "Calibrated emission likelihood for stage j at time t emitted by neural-tree ensemble"),
        ("T", "Temperature scaling scalar parameter (T = 0.916) / sequence history window length"),
        ("lambda_s", "Additive Laplace transition smoothing hyperparameter (lambda_s = 0.20)"),
        ("L_det", "Early detection latency measured in number of requests elapsed in peak attack stage"),
        ("x_t", "31-dimensional causal feature vector extracted for incoming HTTP request at time t"),
        ("gamma", "Exponential moving average decay factor for attack pressure accumulation (gamma = 0.60)"),
        ("W", "Sliding window length for bounded local session context aggregation (W = 8 requests)"),
    ]

    p130 = doc.paragraphs[130] # Heading
    tbl_sym_xml = parse_xml(f'''
        <w:tbl {nsdecls("w")}>
            <w:tblPr>
                <w:tblStyle w:val="TableGrid"/>
                <w:tblW w:w="0" w:type="auto"/>
                <w:jc w:val="center"/>
            </w:tblPr>
            <w:tblGrid>
                <w:gridCol w:w="2200"/>
                <w:gridCol w:w="6400"/>
            </w:tblGrid>
            <w:tr>
                <w:tc><w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="{FONT_NAME}" w:hAnsi="{FONT_NAME}"/><w:b/><w:sz w:val="22"/></w:rPr><w:t>Symbol / Notation</w:t></w:r></w:p></w:tc>
                <w:tc><w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="{FONT_NAME}" w:hAnsi="{FONT_NAME}"/><w:b/><w:sz w:val="22"/></w:rPr><w:t>Mathematical Description / Definition</w:t></w:r></w:p></w:tc>
            </w:tr>
        </w:tbl>
    ''')
    p130._p.addnext(tbl_sym_xml)
    tbl_sym = docx.table.Table(tbl_sym_xml, doc)

    for sym, desc in symbols:
        row = tbl_sym.add_row()
        format_cell(row.cells[0], sym, bold=True, size_pt=10.5, align=WD_ALIGN_PARAGRAPH.LEFT)
        format_cell(row.cells[1], desc, bold=False, size_pt=10.5, align=WD_ALIGN_PARAGRAPH.LEFT)

    # ---------------------------------------------------------
    # 10. ABSTRACT
    # ---------------------------------------------------------
    print("Populating Abstract...")
    # Clear instruction paragraphs 186, 187, 188
    doc.paragraphs[186].text = ""
    doc.paragraphs[187].text = ""
    doc.paragraphs[188].text = ""

    # Insert the 3 abstract paragraphs into P187, P188, P189
    p_abs1 = doc.paragraphs[187]
    p_abs1.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p_abs1.paragraph_format.line_spacing = 1.15
    p_abs1.paragraph_format.space_after = Pt(6)
    r_abs1 = p_abs1.add_run(
        "Web application attacks often manifest as a sequence of orchestrated activities instead of isolated, "
        "single-use malicious requests. This operational reality necessitates intrusion detection systems to shift "
        "away from stateless, request-centric inspection toward causal, session-level sequential analysis. This "
        "work presents a context-aware artificial intelligence framework designed to detect, track, and forecast "
        "multi-stage web injection attacks across sequential HTTP transactions. The framework defines a comprehensive five-stage "
        "attack taxonomy consisting of Normal, Reconnaissance, Fuzzing, Injection, and Exploitation stages, enabling "
        "defenders to track individual HTTP transactions and establish their exact placement within an active attack campaign."
    )
    set_run_font(r_abs1, size_pt=12)

    p_abs2 = doc.paragraphs[188]
    p_abs2.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p_abs2.paragraph_format.line_spacing = 1.15
    p_abs2.paragraph_format.space_after = Pt(6)
    r_abs2 = p_abs2.add_run(
        "An empirical experimental dataset was constructed using a locally containerized, network-isolated deployment of the "
        "OWASP Juice Shop vulnerable web application, intercepted via mitmproxy and Burp Suite across 62 capture files "
        "(comprising 2,878 raw HTTP requests) alongside approximately 1,200 live-response requests in the training split. "
        "To evaluate non-trivial sequential dynamics without synthetic shortcuts, contiguous request blocks (3 to 16 requests) "
        "were composed into an extensive multi-stage corpus of 2,100 sessions containing 72,269 total request instances, "
        "partitioned using a file-disjoint protocol where source capture files and raw request blocks are strictly split-disjoint "
        "across training, validation, and testing partitions. To enforce strict operational causality without future lookahead bias, "
        "the system employs a 31-dimensional causal feature extraction framework incorporating request morphology, payload regex signatures, "
        "endpoint sensitivity classes, response status metrics, and decaying session-context indicators. Current-stage detection is "
        "executed via a responsive causal ensemble combining a per-request gradient boosted decision tree (XGBoost) and a seed-averaged "
        "Long Short-Term Memory (LSTM) recurrent neural network, fused via equal-weight probability blending (alpha = 0.50) and calibrated "
        "through temperature scaling (T = 0.916). A causal Hidden Markov Model (HMM) forward filter tracks Bayesian state belief, enabling "
        "proactive next-distinct-stage intent forecasting and providing an optional lower-false-positive operating mode."
    )
    set_run_font(r_abs2, size_pt=12)

    p_abs3 = doc.paragraphs[189]
    p_abs3.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p_abs3.paragraph_format.line_spacing = 1.15
    p_abs3.paragraph_format.space_after = Pt(6)
    r_abs3 = p_abs3.add_run(
        "The proposed system was empirically evaluated on a held-out, file-disjoint test corpus consisting of 300 sessions and 10,174 HTTP requests "
        "(derived from 12 held-out capture files). The deployed causal ensemble achieves an overall accuracy of 54.31% and a Macro-F1 score of 0.5060, "
        "outperforming parameter-free lookup heuristics by +24.36 percentage points. Transition edge accuracy reaches 0.4156, reflecting the operational "
        "trade-off between rapid boundary adaptation and temporal smoothing. Sequential recurrent modeling constrains the per-request benign false-positive "
        "rate to 14.00% (and 10.97% in HMM forward-filtering mode), achieving a 41.4% reduction in false alarms compared to standalone XGBoost (23.90%), "
        "though per-request false alarms remain an operational challenge in high-throughput environments. At the session campaign level, the detector catches "
        "86.09% of all attack sessions (74.29% to 91.45% across individual attack stages, identifying 91.45% of critical exploitation sessions) with a 35.29% "
        "false alarm rate on benign sessions (down from 52.94% for standalone XGBoost) and a median detection latency of 1 request. Furthermore, Bayesian "
        "next-distinct-stage intent forecasting achieves 33.69% Top-1 and 55.17% Top-2 accuracy at real phase transitions, providing early-warning "
        "indication while sustaining an end-to-end algorithmic inference latency averaging 0.18 ms per request."
    )
    set_run_font(r_abs3, size_pt=12)

    p_kw = doc.paragraphs[190]
    p_kw.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p_kw.paragraph_format.space_before = Pt(8)
    r_kw_h = p_kw.add_run("Keywords — ")
    set_run_font(r_kw_h, size_pt=11, bold=True, italic=True)
    r_kw = p_kw.add_run("Multi-Stage Web Attacks, Web Injection Detection, Context-Aware Intrusion Detection, Sequential HTTP Analysis, Causal Ensemble, Recurrent Neural Networks, Hidden Markov Models, Web Application Firewall.")
    set_run_font(r_kw, size_pt=11, italic=True)

    # ---------------------------------------------------------
    # 11. REMOVE DUMMY CHAPTERS & APPEND CHAPTERS 1 TO 9
    # ---------------------------------------------------------
    print("Replacing dummy chapters with full Chapters 1 to 9 from report...")
    body = doc._element.body

    # 1. Dynamically locate roman_p (paragraph holding lowerRoman sectPr closing Section 1)
    roman_p = None
    for child in body:
        if child.tag.endswith("p"):
            pPr = child.find(f"{{{nsdecls('w').split('=')[1].strip('\"')}}}pPr")
            if pPr is not None:
                sect = pPr.find(f"{{{nsdecls('w').split('=')[1].strip('\"')}}}sectPr")
                if sect is not None:
                    pg = sect.find(f"{{{nsdecls('w').split('=')[1].strip('\"')}}}pgNumType")
                    if pg is not None and pg.attrib.get(f"{{{nsdecls('w').split('=')[1].strip('\"')}}}fmt") == "lowerRoman":
                        roman_p = child
                        break

    if roman_p is None:
        raise ValueError("Could not locate roman_p paragraph with lowerRoman sectPr!")
    print("Found roman_p dynamically!")

    # 2. Collect all elements strictly between roman_p and the final body-level sectPr
    to_remove = []
    found_roman = False
    for child in body:
        if child == roman_p:
            found_roman = True
            continue
        if found_roman and not child.tag.endswith("sectPr"):
            to_remove.append(child)

    print(f"Removing {len(to_remove)} dummy template elements after roman_p...")
    for el in to_remove:
        body.remove(el)

    # 3. Insert report elements (Chapters 1 to 9) right after roman_p
    rep_body = doc_rep._element.body
    print(f"Copying {len(rep_body) - 1 - 42} elements from report docx after roman_p...")

    curr = roman_p
    for idx in range(42, len(rep_body) - 1): # exclude final sectPr
        src_elem = rep_body[idx]
        new_elem = copy.deepcopy(src_elem)

        # Remap image relationship IDs if present
        elem_xml = new_elem.xml
        for old_rId, (new_rId, target_img) in REMAP_RELS.items():
            if f'r:embed="{old_rId}"' in elem_xml:
                elem_xml = elem_xml.replace(f'r:embed="{old_rId}"', f'r:embed="{new_rId}"')
        
        updated_elem = parse_xml(elem_xml)
        curr.addnext(updated_elem)
        curr = updated_elem

    # 4. Ensure final body-level sectPr has start="1" in Arabic
    final_sectPr = body.xpath('./w:sectPr')[0]
    pgNum = final_sectPr.find(f"{{{nsdecls('w').split('=')[1].strip('\"')}}}pgNumType")
    if pgNum is None:
        final_sectPr.append(parse_xml(f'<w:pgNumType {nsdecls("w")} w:start="1"/>'))
    else:
        pgNum.set(f"{{{nsdecls('w').split('=')[1].strip('\"')}}}start", '1')

    print("All body elements transferred successfully after roman_p.")

    # Save to intermediate docx
    temp_docx = "temp_assembled.docx"
    doc.save(temp_docx)
    print(f"Intermediate docx saved: {temp_docx}")

    # ---------------------------------------------------------
    # 12. INJECT IMAGES AND RELATIONSHIPS INTO ZIP PACKAGE
    # ---------------------------------------------------------
    print("Injecting images and updating relationships in zip package...")
    
    # Read relationships and content types from temp_docx
    with zipfile.ZipFile(temp_docx, 'r') as zin:
        rels_xml = zin.read('word/_rels/document.xml.rels').decode('utf-8')
        content_types_xml = zin.read('[Content_Types].xml').decode('utf-8')

    # Add png content type if missing
    if 'Extension="png"' not in content_types_xml:
        insert_ct = content_types_xml.find('</Types>')
        content_types_xml = content_types_xml[:insert_ct] + '<Default Extension="png" ContentType="image/png"/>' + content_types_xml[insert_ct:]

    # Add new image relationships
    rel_entries = []
    for old_rId, (new_rId, target_img) in REMAP_RELS.items():
        if f'Id="{new_rId}"' not in rels_xml:
            rel_entries.append(f'<Relationship Id="{new_rId}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{target_img}"/>')

    if rel_entries:
        insert_pos = rels_xml.rfind('</Relationships>')
        rels_xml = rels_xml[:insert_pos] + "".join(rel_entries) + rels_xml[insert_pos:]

    # Write final zip package to OUT_PATH
    with zipfile.ZipFile(temp_docx, 'r') as zin, zipfile.ZipFile(OUT_PATH, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == 'word/_rels/document.xml.rels':
                zout.writestr(item, rels_xml.encode('utf-8'))
            elif item.filename == '[Content_Types].xml':
                zout.writestr(item, content_types_xml.encode('utf-8'))
            else:
                zout.writestr(item, zin.read(item.filename))

        # Add image files into word/media/
        for old_rId, (new_rId, target_img) in REMAP_RELS.items():
            img_filename = os.path.basename(target_img)
            img_disk_path = os.path.join(MEDIA_DIR, img_filename)
            zip_target = f"word/{target_img}"
            if os.path.exists(img_disk_path):
                with open(img_disk_path, 'rb') as f_img:
                    zout.writestr(zip_target, f_img.read())
                    print(f"Injected {zip_target} from {img_filename}")

    if os.path.exists(temp_docx):
        os.remove(temp_docx)

    print(f"[SUCCESS] Final template report created successfully at: {OUT_PATH}")

if __name__ == '__main__':
    main()
