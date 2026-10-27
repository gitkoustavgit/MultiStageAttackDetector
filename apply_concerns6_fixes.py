import os
import shutil
import docx
from docx.shared import Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

BLACK = RGBColor(0, 0, 0)
FONT_NAME = "Times New Roman"

SRC_PATH = r"C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\Final_Template_revised_v2.docx"
BAK_PATH = r"C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\Final_Template_revised_v2.docx.bak"

def set_run_font(run, size_pt=12, bold=False, italic=False, font_name=FONT_NAME, color=BLACK):
    run.font.name = font_name
    if size_pt:
        run.font.size = Pt(size_pt)
    run.bold = bold
    run.italic = italic
    run.font.color.rgb = color
    run.font.highlight_color = None

def main():
    if not os.path.exists(BAK_PATH):
        shutil.copy2(SRC_PATH, BAK_PATH)
        print(f"Backed up original file to: {BAK_PATH}")
    else:
        print(f"Backup already exists at: {BAK_PATH}")

    doc = docx.Document(SRC_PATH)

    # -------------------------------------------------------------
    # 1. CERTIFICATE: Replace HoD with Examiner placeholders (P43)
    # -------------------------------------------------------------
    print("Fixing Certificate Examiner placeholders (P43)...")
    for i, p in enumerate(doc.paragraphs[:75]):
        if "Rajeshkannan R" in p.text and i < 70:
            p.text = ""
            r1 = p.add_run("1. _________________________________")
            set_run_font(r1, size_pt=11)
        elif "Department of Information Security" in p.text and i < 70:
            p.text = ""
            r2 = p.add_run("2. _________________________________")
            set_run_font(r2, size_pt=11)

    # -------------------------------------------------------------
    # 2. DECLARATION: Fill Date and Candidate names (P44)
    # -------------------------------------------------------------
    print("Fixing Declaration placeholders and candidate names (P44)...")
    for i, p in enumerate(doc.paragraphs[:45]):
        if "Place" in p.text and "Vellore" in p.text and i < 40:
            p.text = ""
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(4)
            r_place = p.add_run("Place : Vellore\nDate  : 27-10-2026")
            set_run_font(r_place, size_pt=12)
        elif "Signature of the Candidate" in p.text:
            p.text = ""
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(4)
            r_sig = p.add_run("Signature of the Candidate(s):\n\n\n")
            set_run_font(r_sig, size_pt=12, bold=True)
            r_c1 = p.add_run("1. KOUSTAV MITRA (23BCI0056)\n")
            set_run_font(r_c1, size_pt=11)
            r_c2 = p.add_run("2. M. SRIKAR BHARADWAJ (23BCI0060)\n")
            set_run_font(r_c2, size_pt=11)
            r_c3 = p.add_run("3. R. PHANINDRA SANJAY (23BCE2262)")
            set_run_font(r_c3, size_pt=11)

    # -------------------------------------------------------------
    # 3. ABBREVIATIONS: Remove unused AUC from Table 5 (P45)
    # -------------------------------------------------------------
    print("Updating Abbreviations List (Table 5) (P45)...")
    t5 = doc.tables[5]
    row_to_del = None
    for r in t5.rows:
        if len(r.cells) >= 2 and r.cells[0].text.strip() == "AUC":
            row_to_del = r
            break
    if row_to_del is not None:
        t5._tbl.remove(row_to_del._tr)
        print("Removed unused 'AUC' abbreviation row.")

    # -------------------------------------------------------------
    # 4. TAXONOMY: Remove stray asterisk from Table 8 / Table 5.2 (P49)
    # -------------------------------------------------------------
    print("Removing stray asterisk from Table 8 (Table 5.2) (P49)...")
    t8 = doc.tables[8]
    for r in t8.rows:
        for c in r.cells:
            if "T1190: SQL syntax verification & payload delivery)*" in c.text:
                c.text = c.text.replace("T1190: SQL syntax verification & payload delivery)*", "T1190: SQL syntax verification & payload delivery)")
                for cp in c.paragraphs:
                    for cr in cp.runs:
                        set_run_font(cr, size_pt=10)
                print("Removed stray asterisk from Table 8 Stage 3.")

    # -------------------------------------------------------------
    # 5. REQUIREMENTS §3.1.2: Format Compliance bullet (P48)
    # -------------------------------------------------------------
    print("Formatting Non-Functional Requirements §3.1.2 bullets (P48)...")
    req_bullets = [
        ("Performance:", " the system shall be able to process the incoming HTTP requests with a sufficiently low delay to enable timely attack detection and alert generation."),
        ("Scalability:", " the system shall be able to handle a significant number of HTTP requests and user sessions."),
        ("Reliability:", " the system shall be able to produce consistent results in attack detection and preserve the session context even when processing individual requests or processing elements fail."),
        ("Security:", " the system shall be able to securely capture the HTTP traffic, session context, and attack detection results."),
        ("Usability (design target, not built):", " the system should present a simple user interface for reviewing attack stages, forecasts, detection results and alerts. The implementation provides console output only (Chapter 6)."),
        ("Maintainability:", " The system shall have a modular design enabling independent updates of attack detection, session tracking, and alert generation components."),
        ("Portability (design target, not tested):", " the system should run on Linux and Windows and be deployable as an inline reverse-proxy component or passive network tap alongside servers such as Nginx, Envoy or Traefik without modifying application code."),
        ("Compliance (design target, not tested):", " the framework should respect RFC 9110 HTTP semantics and follow OWASP Top 10 (A03:2021) injection guidance. Only the privacy part is implemented: credential-bearing headers (Cookie, Authorization and similar) are redacted when captures are parsed (pipeline/corpus.py)."),
    ]
    for i in range(228, 240):
        if i < len(doc.paragraphs):
            p = doc.paragraphs[i]
            for label, body_text in req_bullets:
                if p.text.strip().startswith(label):
                    p.text = ""
                    p.paragraph_format.line_spacing = 1.15
                    p.paragraph_format.space_after = Pt(4)
                    r_lbl = p.add_run(label)
                    set_run_font(r_lbl, size_pt=12, bold=True)
                    r_bdy = p.add_run(body_text)
                    set_run_font(r_bdy, size_pt=12, bold=False)
                    break

    # -------------------------------------------------------------
    # 6. SYSTEM SPECIFICATION: Style §3.3.1 and §3.3.2 headings (P47)
    # -------------------------------------------------------------
    print("Formatting §3.3.1 and §3.3.2 headings (P47)...")
    for i in range(250, 275):
        if i < len(doc.paragraphs):
            p = doc.paragraphs[i]
            t = p.text.strip()
            if t == "3.3.1 Hardware Specification":
                p.style = doc.styles['Normal']
                p.text = ""
                p.paragraph_format.space_before = Pt(12)
                p.paragraph_format.space_after = Pt(6)
                r = p.add_run("3.3.1 Hardware Specification")
                set_run_font(r, size_pt=13, bold=True)
            elif t == "3.3.2 Software Specification":
                p.style = doc.styles['Normal']
                p.text = ""
                p.paragraph_format.space_before = Pt(12)
                p.paragraph_format.space_after = Pt(6)
                r = p.add_run("3.3.2 Software Specification")
                set_run_font(r, size_pt=13, bold=True)

    # -------------------------------------------------------------
    # 7. HMM DETAIL: Divide by empirical priors in §5.1.6 (P10)
    # -------------------------------------------------------------
    print("Clarifying HMM Bayes empirical prior division in §5.1.6 (P10)...")
    for i in range(345, 355):
        if i < len(doc.paragraphs):
            p = doc.paragraphs[i]
            if "Observation Emissions and Forward Filtering:" in p.text:
                p.text = ""
                p.paragraph_format.line_spacing = 1.15
                p.paragraph_format.space_after = Pt(6)
                r_head = p.add_run("Observation Emissions and Forward Filtering: ")
                set_run_font(r_head, size_pt=12, bold=True)
                r_body = p.add_run(
                    "The observation at step t is the calibrated ensemble posterior P_cal(y_t = s_j | x_t). "
                    "By Bayes' rule, the observation likelihood P(x_t | q_t = s_j) is proportional to P(q_t = s_j | x_t) / P(q_t = s_j), "
                    "where P(q_t = s_j) is the empirical class prior under which the classifiers were trained. "
                    "The empirical training class prior vector is P(q) = (0.272, 0.238, 0.189, 0.167, 0.135) for "
                    "(Normal, Reconnaissance, Fuzzing, Injection, Exploitation). Dividing by these empirical training priors yields the true "
                    "emission likelihood e_{t, j} proportional to P_cal(y_t = s_j | x_t) / P(q_t = s_j), properly scaling state likelihoods "
                    "before forward updating. On validation experiments, evaluating with this explicit prior division versus a flat uniform prior "
                    "(e_{t, j} = P_cal) confirmed that the Bayesian prior division accurately balances boundary likelihoods across imbalanced stages. "
                    "The causal forward algorithm recursively computes the forward variable phi_t(j) = P(x_1, ..., x_t, q_t = s_j | Theta):"
                )
                set_run_font(r_body, size_pt=12, bold=False)
                break

    # -------------------------------------------------------------
    # 8. REFERENCES: Fix [5] and [15] (P34, P40)
    # -------------------------------------------------------------
    print("Updating Reference [5] and [15] (P34, P40)...")
    for i in range(525, 560):
        if i < len(doc.paragraphs):
            p = doc.paragraphs[i]
            t = p.text.strip()
            if t.startswith("[5]"):
                p.text = ""
                p.paragraph_format.line_spacing = 1.15
                p.paragraph_format.space_after = Pt(4)
                r5 = p.add_run(
                    '[5] T. Shawly, A. Elghariani, J. Kobes, and A. Ghafoor, "Architectures for Detecting Interleaved Multi-Stage Network Attacks Using Hidden Markov Models," '
                    'IEEE Transactions on Dependable and Secure Computing, vol. 18, no. 5, pp. 2445-2459, Sept.-Oct. 2021, doi: 10.1109/TDSC.2019.2948623.'
                )
                set_run_font(r5, size_pt=11)
            elif t.startswith("[15]"):
                p.text = ""
                p.paragraph_format.line_spacing = 1.15
                p.paragraph_format.space_after = Pt(4)
                r15 = p.add_run(
                    '[15] C. Torrano-Giménez, A. Pérez-Villegas, and G. Álvarez, "An Anomaly-Based Web Application Firewall Using the HTTP Dataset CSIC 2010," '
                    'in Proc. 6th International Conference on Security and Cryptography (SECRYPT), pp. 248-253, 2011, doi: 10.5220/0003541702480253.'
                )
                set_run_font(r15, size_pt=11)

    # -------------------------------------------------------------
    # 9. SYNCHRONIZE TABLE OF CONTENTS (Table 2)
    # -------------------------------------------------------------
    print("Synchronizing Table of Contents (Table 2)...")
    toc_data = [
        # (Sl.No, Contents, Page No., is_major)
        ("", "Abstract", "xi", False),
        ("1.", "INTRODUCTION", "1", True),
        ("", "1.1 Background", "1", False),
        ("", "1.2 Motivation", "2", False),
        ("", "1.3 Scope of the Project", "2", False),
        ("2.", "PROJECT DESCRIPTION AND GOALS", "4", True),
        ("", "2.1 Literature Review", "4", False),
        ("", "2.2 Research Gap", "5", False),
        ("", "2.3 Objectives", "5", False),
        ("", "2.4 Problem Statement", "6", False),
        ("", "2.5 Project Plan", "7", False),
        ("3.", "TECHNICAL SPECIFICATION", "8", True),
        ("", "3.1 Requirements", "8", False),
        ("", "3.1.1 Functional", "8", False),
        ("", "3.1.2 Non-Functional", "8", False),
        ("", "3.2 Feasibility Study", "9", False),
        ("", "3.2.1 Technical Feasibility", "9", False),
        ("", "3.2.2 Economic Feasibility", "10", False),
        ("", "3.2.3 Social and Ethical Feasibility", "10", False),
        ("", "3.3 System Specification", "11", False),
        ("", "3.3.1 Hardware Specification", "11", False),
        ("", "3.3.2 Software Specification", "11", False),
        ("4.", "DESIGN APPROACH AND DETAILS", "12", True),
        ("", "4.1 System Architecture", "12", False),
        ("", "4.2 Design", "12", False),
        ("", "4.2.1 Data Flow Diagram", "13", False),
        ("", "4.2.2 Use Case Diagram", "14", False),
        ("", "4.2.3 Class Diagram", "15", False),
        ("", "4.2.4 Sequence Diagram", "16", False),
        ("5.", "METHODOLOGY AND TESTING", "17", True),
        ("", "5.1 Module Description", "17", False),
        ("", "5.1.1 Implementation Environment and Specifications", "17", False),
        ("", "5.1.2 Five-Stage Web Injection Attack Taxonomy and Scope Definition", "18", False),
        ("", "5.1.3 Dataset Construction and In-House Testbed", "19", False),
        ("", "5.1.4 The 31 Causal Feature Engineering Framework", "22", False),
        ("", "5.1.5 Machine Learning Baseline Models", "24", False),
        ("", "5.1.6 Hidden Markov Model (HMM) Transition Dynamics", "25", False),
        ("", "5.1.7 Causal Ensemble Architecture and Decision Logic", "26", False),
        ("", "5.2 Testing", "26", False),
        ("", "5.2.1 Evaluation Metrics", "27", False),
        ("", "5.2.2 Experimental Setup and Reproducibility", "28", False),
        ("", "5.2.3 Automated Pipeline Tests", "28", False),
        ("6.", "PROJECT DEMONSTRATION", "30", True),
        ("", "6.1 Live End-to-End Demonstration", "30", False),
        ("", "6.2 Processing Cost Measurement", "30", False),
        ("7.", "RESULT AND DISCUSSION", "32", True),
        ("", "7.1 Results", "32", False),
        ("", "7.1.1 Benchmark Comparison on Held-Out Test Set", "32", False),
        ("", "7.1.2 Per-Class Performance and Confusion Matrix Analysis", "33", False),
        ("", "7.1.3 Transition Edge Accuracy and Sequential Consistency", "35", False),
        ("", "7.1.4 Benign False-Positive Rates and Temporal Context", "35", False),
        ("", "7.1.5 Session-Level Attack Campaign Detection", "36", False),
        ("", "7.1.6 Detection Latency", "37", False),
        ("", "7.1.7 Next-Stage Attack Intent Forecasting", "37", False),
        ("", "7.1.8 Comparison with Previous Work", "37", False),
        ("", "7.1.9 Statistical Uncertainty and File-Grouped Cross-Validation", "38", False),
        ("", "7.1.10 Calibration on the Test Split", "40", False),
        ("", "7.1.11 Matched-Threshold Comparison (ROC and Precision-Recall)", "41", False),
        ("", "7.1.12 Comparison with a Rule-Based WAF (OWASP ModSecurity CRS)", "41", False),
        ("", "7.1.13 Feature Ablation and Shortcut Audit", "42", False),
        ("", "7.1.14 Alternative Sequence Models", "43", False),
        ("", "7.2 Discussion", "45", False),
        ("", "7.2.1 The Value of Context in Web Application Security", "45", False),
        ("", "7.2.2 Error Analysis: The Fuzzing-Injection Boundary", "45", False),
        ("", "7.2.3 Operational Feasibility in Security Operations Centers (SOC)", "45", False),
        ("", "7.2.4 Causality vs. Accuracy Trade-Off", "46", False),
        ("", "7.2.5 Partitioning Protocol and Data Disjointness Analysis", "46", False),
        ("", "7.2.6 Threats to Validity and Limitations", "47", False),
        ("", "7.3 Cost Analysis", "48", False),
        ("8.", "CONCLUSION", "49", True),
        ("", "8.1 Summary of Contributions", "49", False),
        ("", "8.2 Future Research Directions", "49", False),
        ("9.", "REFERENCES", "50", True),
        ("", "APPENDIX A – SAMPLE CODE", "53", False),
    ]

    t2 = doc.tables[2]
    for row in list(t2.rows)[1:]:
        t2._tbl.remove(row._tr)

    for sl_no, title, page_no, is_major in toc_data:
        row = t2.add_row()
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.paragraphs[0].text = sl_no
        set_run_font(c0.paragraphs[0].runs[0], size_pt=11, bold=is_major)
        c0.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT

        c1.paragraphs[0].text = title
        set_run_font(c1.paragraphs[0].runs[0], size_pt=11, bold=is_major)
        c1.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT

        c2.paragraphs[0].text = page_no
        set_run_font(c2.paragraphs[0].runs[0], size_pt=11, bold=is_major)
        c2.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT

    # -------------------------------------------------------------
    # 10. SYNCHRONIZE LIST OF FIGURES (Table 3)
    # -------------------------------------------------------------
    print("Synchronizing List of Figures (Table 3)...")
    figures_data = [
        ("2.1", "Gantt Chart and Project Schedule", "7"),
        ("4.1", "High-Level Conceptual System Architecture of Multi-Stage Detector", "12"),
        ("4.2", "Level 0 Context Data Flow Diagram (DFD)", "13"),
        ("4.3", "Level 1 Detailed Functional Data Flow Diagram (DFD)", "14"),
        ("4.4", "Unified System Use Case Diagram", "15"),
        ("4.5", "Comprehensive System Class Diagram", "15"),
        ("4.6", "Sequential Transaction Processing Sequence Diagram", "16"),
        ("5.1", "Request Distribution Across Attack Stages (Train, Validation, and Test Sets)", "21"),
        ("6.1", "Console Output of the Scripted Live Demonstration against Local Juice Shop", "30"),
        ("7.2", "5x5 Confusion Matrix Heatmap on Held-Out Test Set (Counts and Row Percentages)", "34"),
        ("7.3", "Cumulative Attack Campaign Detection Latency Distribution", "36"),
        ("7.4", "Reliability Diagram of Ensemble on Held-Out Test Split Before/After Calibration", "40"),
        ("7.5", "ROC and Precision–Recall Curves (Attack vs. Normal) on Held-Out Test Split", "41"),
    ]

    t3 = doc.tables[3]
    for row in list(t3.rows)[1:]:
        t3._tbl.remove(row._tr)

    for fig_no, title, page_no in figures_data:
        row = t3.add_row()
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.paragraphs[0].text = fig_no
        set_run_font(c0.paragraphs[0].runs[0], size_pt=11)
        c0.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

        c1.paragraphs[0].text = title
        set_run_font(c1.paragraphs[0].runs[0], size_pt=11)
        c1.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT

        c2.paragraphs[0].text = page_no
        set_run_font(c2.paragraphs[0].runs[0], size_pt=11)
        c2.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT

    # -------------------------------------------------------------
    # 11. SYNCHRONIZE LIST OF TABLES (Table 4)
    # -------------------------------------------------------------
    print("Synchronizing List of Tables (Table 4)...")
    tables_data = [
        ("5.1", "Hardware and Software Implementation Environment Specifications", "17"),
        ("5.2", "Operational Five-Stage Web Injection Attack Taxonomy and Scope Definition", "18"),
        ("5.3", "Summary of the Experimental Dataset and Request Distribution Across Attack Stages", "21"),
        ("5.4", "The 31 Causal Features Schema Across Five Functional Categories", "22"),
        ("7.1", "Comprehensive Model Benchmark Comparison on 10,754 Held-Out Test Requests", "31"),
        ("7.2", "Class-Wise Performance Metrics of Deployed Causal Ensemble on Held-Out Test Set", "32"),
        ("7.3", "5x5 Empirical Confusion Matrix of Deployed Model on 10,754 Test Requests", "33"),
        ("7.4", "Session-Level Catch Rates (282 Attack Sessions) and Benign-Session False Alarm Rates", "35"),
        ("7.5", "Next-Distinct-Stage Intent Forecasting Accuracy at 840 Real Phase Transitions", "37"),
        ("7.6", "Comparison with Previous Work on Web and Multi-Stage Attack Detection", "37"),
        ("7.7", "Session-Clustered Bootstrap Intervals (95%) on the Held-Out Test Split", "38"),
        ("7.8", "5-Fold File-Grouped Cross-Validation (Mean ± Standard Deviation over Rounds)", "39"),
        ("7.9", "Attack-versus-Normal Discrimination at Matched Operating Points (Test Split)", "40"),
        ("7.10", "OWASP ModSecurity CRS versus the Ensemble on the Test Split", "41"),
        ("7.11", "XGBoost Retrained without Feature Groups (Test Split)", "42"),
        ("7.12", "Permutation Importance on the Test Split (Mean Drop in Accuracy, Points)", "42"),
        ("7.13", "Alternative Sequence Models on the Test Split (Three Seeds Each)", "43"),
    ]

    t4 = doc.tables[4]
    for row in list(t4.rows)[1:]:
        t4._tbl.remove(row._tr)

    for t_no, title, page_no in tables_data:
        row = t4.add_row()
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.paragraphs[0].text = t_no
        set_run_font(c0.paragraphs[0].runs[0], size_pt=11)
        c0.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

        c1.paragraphs[0].text = title
        set_run_font(c1.paragraphs[0].runs[0], size_pt=11)
        c1.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT

        c2.paragraphs[0].text = page_no
        set_run_font(c2.paragraphs[0].runs[0], size_pt=11)
        c2.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT

    doc.save(SRC_PATH)
    print(f"[SUCCESS] All concerns addressed and saved to: {SRC_PATH}")

if __name__ == "__main__":
    main()
