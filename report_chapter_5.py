"""
report_chapter_5.py

Generates Chapter 5: IMPLEMENTATION AND EXPERIMENTAL METHODOLOGY
for BCSE497J Project I Report.docx.
Addresses all reviewer concerns from Concerns.docx:
- Completely removes first-person language ("I have...", "my", "we").
- Details data generation tools (Burp Suite Intruder, SQLmap, synthetic e-commerce browsing scripts).
- Formally explains deterministic per-request labeling rules and the Fuzzing vs. Injection boundary.
- Acknowledges single-application limitation (OWASP Juice Shop) and cites multi-app testing (DVWA, WebGoat) as future work.
- Explicitly defines HMM hidden states (latent attack stages S_t in {0..4}) and continuous observations.
- Consecutive table numbering: Table 1 (Environment), Table 2 (Taxonomy), Table 3 (Dataset), Table 4 (31 Features).
- Renumbers figure to Fig. 8 (following Figs 1-7 in Chapters 2 & 4).
- Uses strictly black font (#000000) and Times New Roman.
"""

import os
import docx
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

BLACK = RGBColor(0, 0, 0)
FONT_NAME = "Times New Roman"

def set_run_font(run, size_pt=12, bold=False, italic=False):
    run.font.name = FONT_NAME
    run.font.size = Pt(size_pt)
    run.bold = bold
    run.italic = italic
    run.font.color.rgb = BLACK

def add_p(container, text="", size_pt=12, bold=False, italic=False, align=WD_ALIGN_PARAGRAPH.JUSTIFY, space_after=5, space_before=0, line_spacing=1.15):
    p = container.add_paragraph()
    p.alignment = align
    p.paragraph_format.line_spacing = line_spacing
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.space_before = Pt(space_before)
    if text:
        r = p.add_run(text)
        set_run_font(r, size_pt=size_pt, bold=bold, italic=italic)
    return p

def add_h1(container, text, page_break_before=False):
    p = add_p(container, text, size_pt=14, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_before=16, space_after=6)
    if page_break_before:
        p.paragraph_format.page_break_before = True
    return p

def add_h2(container, text):
    return add_p(container, text, size_pt=13, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_before=12, space_after=4)

def add_h3(container, text):
    return add_p(container, text, size_pt=12, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_before=8, space_after=3)

def add_caption(container, text):
    return add_p(container, text, size_pt=10.5, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_before=4, space_after=8)

def format_cell(cell, text="", bold=False, italic=False, size_pt=10, align=WD_ALIGN_PARAGRAPH.LEFT):
    p = cell.paragraphs[0]
    p.text = ""
    p.alignment = align
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(3)
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
                    
    # Repeat header row on continuation pages
    header_tr = table.rows[0]._tr.get_or_add_trPr()
    header_tr.append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))
    
    # Prevent rows from breaking across page breaks
    for row in table.rows:
        trPr = row._tr.get_or_add_trPr()
        trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))

def set_cell_bg(cell, hex_color="F2F2F2"):
    tcPr = cell._element.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tcPr.append(shd)

def add_callout_box(container, fig_num, title, description, capture_howto):
    tbl = container.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.style = 'Table Grid'
    cell = tbl.rows[0].cells[0]
    cell.width = Inches(6.5)
    set_cell_bg(cell, "FAFAFA")
    
    p0 = cell.paragraphs[0]
    p0.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p0.paragraph_format.space_before = Pt(6)
    p0.paragraph_format.space_after = Pt(3)
    r0 = p0.add_run(f"[{fig_num.upper()}: {title.upper()}]")
    set_run_font(r0, size_pt=11, bold=True)
    
    p1 = cell.add_paragraph()
    p1.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p1.paragraph_format.space_before = Pt(2)
    p1.paragraph_format.space_after = Pt(3)
    p1.paragraph_format.line_spacing = 1.10
    r1_b = p1.add_run("Scientific Description: ")
    set_run_font(r1_b, size_pt=10, bold=True)
    r1_t = p1.add_run(description)
    set_run_font(r1_t, size_pt=10, italic=False)
    
    p2 = cell.add_paragraph()
    p2.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p2.paragraph_format.space_before = Pt(2)
    p2.paragraph_format.space_after = Pt(6)
    p2.paragraph_format.line_spacing = 1.10
    r2_b = p2.add_run("Figure Capture / Reproduction Instructions: ")
    set_run_font(r2_b, size_pt=9.5, bold=True)
    r2_t = p2.add_run(capture_howto)
    set_run_font(r2_t, size_pt=9.5, italic=True)
    
    p_sp = container.add_paragraph()
    p_sp.paragraph_format.space_before = Pt(0)
    p_sp.paragraph_format.space_after = Pt(4)

def add_figure_or_callout(container, fig_num, title, img_filename, description, capture_howto, width_in=6.0):
    target_img = img_filename
    if not os.path.exists(target_img):
        proj_dir = os.path.dirname(os.path.abspath(__file__))
        cand = os.path.join(proj_dir, img_filename)
        if os.path.exists(cand):
            target_img = cand
            
    if os.path.exists(target_img):
        p_img = container.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_img.paragraph_format.space_before = Pt(8)
        p_img.paragraph_format.space_after = Pt(4)
        run = p_img.add_run()
        run.add_picture(target_img, width=Inches(width_in))
        add_caption(container, f"{fig_num}. {title}")
    else:
        add_callout_box(container, fig_num, title, description, capture_howto)

def append_chapter_5(doc):
    print("Appending Chapter 5: Implementation and Experimental Methodology...")
    
    add_h1(doc, "5. IMPLEMENTATION AND EXPERIMENTAL METHODOLOGY", page_break_before=True)
    
    # 5.1
    add_h2(doc, "5.1 Implementation Environment and Specifications")
    add_p(doc, 
        "To establish an authentic, leak-free, and reproducible experimental platform, the entire detection, feature "
        "extraction, model training, and sequential evaluation pipeline was deployed on dedicated laboratory hardware. "
        "Rather than relying on abstract mathematical simulations, real-world production-grade software frameworks, "
        "bidirectional network interception proxies, containerized web applications, and machine learning toolkits were "
        "fully integrated. The complete hardware architecture and software stack of the experimental implementation environment "
        "is documented in Table 1."
    )
    
    # Table 1: Implementation Environment
    add_caption(doc, "Table 1: Hardware and Software Implementation Environment Specifications")
    tbl1 = doc.add_table(rows=13, cols=3)
    style_table(tbl1, col_widths=[1.8, 2.4, 2.3])
    
    headers1 = ["Component", "Experimental Specification", "Functional Role in System"]
    for i, h in enumerate(headers1):
        format_cell(tbl1.rows[0].cells[i], h, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell_bg(tbl1.rows[0].cells[i], "E6E6E6")
        
    env_data = [
        ["Operating System", "Microsoft Windows 11 Enterprise (64-bit)", "Host execution runtime and container hypervisor"],
        ["Host Processor (CPU)", "Intel Core i7-12700H (14 cores, 20 threads @ 2.30 GHz)", "Model training, online feature extraction & real-time inference"],
        ["System Memory (RAM)", "16 GB DDR4 (3200 MHz)", "Session deque caching and batch corpus processing"],
        ["Storage Subsystem", "512 GB NVMe M.2 Solid State Drive", "Log persistence and model weight serialization"],
        ["GPU / Accelerator", "NVIDIA GeForce GTX 1650 (Exploratory prototyping only; all reported benchmark models, training routines, and streaming inference evaluations executed strictly on CPU for deployment portability and bit-stable reproducibility)", "Offline exploratory prototyping"],
        ["Programming Language", "Python 3.10.12 (64-bit virtualenv)", "End-to-end pipeline implementation and evaluation"],
        ["Tree Ensemble Framework", "XGBoost v2.0.3 (Hist gradient boosting)", "Per-request tabular stage classification"],
        ["Deep Learning Framework", "TensorFlow / Keras v2.15.0 (CPU execution)", "3-seed recurrent LSTM temporal sequence encoding"],
        ["Markov Modeling Library", "hmmlearn v0.3.2 / NumPy v1.26.4 / SciPy v1.11+", "Supervised Bayesian forward belief filtering"],
        ["Machine Learning Suite", "scikit-learn v1.4.0", "Feature scaling, probability calibration & metrics"],
        ["Interception Proxy", "mitmproxy v10.1.5 / Burp Suite Community", "Bidirectional HTTP/1.1 and HTTP/2 traffic interception"],
        ["Vulnerable Testbed", "OWASP Juice Shop v15.0.0 (Docker)", "Locally containerized, network-isolated web application target"],
    ]
    for r_idx, row_vals in enumerate(env_data):
        for c_idx, val in enumerate(row_vals):
            is_bold = (c_idx == 0)
            align = WD_ALIGN_PARAGRAPH.LEFT if c_idx < 2 else WD_ALIGN_PARAGRAPH.JUSTIFY
            format_cell(tbl1.rows[r_idx+1].cells[c_idx], val, bold=is_bold, align=align)
            if r_idx % 2 == 1:
                set_cell_bg(tbl1.rows[r_idx+1].cells[c_idx], "F9F9F9")

    # 5.2 Five-Stage Attack Taxonomy
    add_h2(doc, "5.2 Five-Stage Web Injection Attack Taxonomy and Scope Definition")
    add_p(doc, 
        "Enterprise web injection campaigns unfold through progressive operational phases. To provide granular situational awareness "
        "and avoid the blunt binary (malicious vs. benign) labeling of legacy intrusion detection systems, this research formalizes "
        "a five-stage operational attack taxonomy: Normal, Reconnaissance, Fuzzing, Injection, and Exploitation. While conceptually "
        "informed by established industry frameworks—specifically the Lockheed Martin Cyber Kill Chain and the MITRE ATT&CK Matrix "
        "for Enterprise—this taxonomy is designed as an operational engineering classification tailored specifically for application-layer "
        "HTTP session monitoring, rather than asserting a strict one-to-one mapping to high-level threat matrices. Each HTTP transaction "
        "within a session is mapped to one of the five stages detailed in Table 2."
    )
    
    # Table 2: Taxonomy
    add_caption(doc, "Table 2: Five-Stage Web Injection Attack Taxonomy and Operational Scope Definition")
    tbl2 = doc.add_table(rows=6, cols=5)
    style_table(tbl2, col_widths=[0.8, 1.2, 1.5, 1.8, 1.2])
    
    headers2 = ["Stage", "Phase Name", "MITRE ATT&CK Mapping", "Operational Objective & Scope", "Sample HTTP Transaction"]
    for i, h in enumerate(headers2):
        format_cell(tbl2.rows[0].cells[i], h, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell_bg(tbl2.rows[0].cells[i], "E6E6E6")
        
    tax_data = [
        ["Stage 0", "Normal", "Legitimate Interaction", "Authorized user browsing, product search, cart updates, and checkout", "GET /rest/products/search?q=apple"],
        ["Stage 1", "Reconnaissance", "Active Scanning (T1595 / T1595.003 Wordlist Scanning) / Endpoint Probing", "Endpoint discovery, hidden directory probing, schema fingerprinting", "GET /api/Challenges, /ftp, robots.txt"],
        ["Stage 2", "Fuzzing", "Active Scanning: Vulnerability Scanning (T1595.002) / Input Probing", "Input boundary testing, abnormal delimiters, parser exception induction", "GET /rest/products/search?q=-99999999 (Negative limit & boundary probe without SQL syntax)"],
        ["Stage 3", "Injection", "Exploit Public-Facing Application (T1190: SQL syntax verification & payload delivery)*", "Active SQL syntax verification, UNION queries, boolean-blind probes", "GET /rest/products/search?q=' UNION SELECT 1,id,email FROM Users--"],
        ["Stage 4", "Exploitation", "Credential Access (T1212) / Exfiltration (T1005)", "Authentication bypass, admin credential extraction, unauthorized data dump outcome", "POST /rest/user/login (admin'--) -> 200 OK + Admin JWT issued; unauthorized credential exfiltration"],
    ]
    for r_idx, row_vals in enumerate(tax_data):
        for c_idx, val in enumerate(row_vals):
            is_bold = (c_idx < 2)
            align = WD_ALIGN_PARAGRAPH.LEFT if c_idx != 0 else WD_ALIGN_PARAGRAPH.CENTER
            format_cell(tbl2.rows[r_idx+1].cells[c_idx], val, bold=is_bold, align=align)
            if r_idx % 2 == 1:
                set_cell_bg(tbl2.rows[r_idx+1].cells[c_idx], "F9F9F9")

    add_p(doc, 
        "*Note: MITRE ATT&CK associations are illustrative behavioral mappings for application-layer analysis rather than asserting strict one-to-one equivalence, as Stage 3 represents active SQL syntax verification and injection probing prior to confirmed unauthorized impact (Stage 4)."
    )

    # 5.3
    add_h2(doc, "5.3 Dataset Construction and In-House Testbed")
    add_p(doc, 
        "To evaluate multi-stage web injection attacks in a realistic, reproducible, and ethically sound "
        "setting, an in-house experimental testbed was deployed. Modern web injection campaigns rarely consist of isolated, "
        "out-of-context exploit payloads; instead, attackers systematically progress through reconnaissance, input space "
        "fuzzing, syntax verification, and finally exploit execution. Standard benchmark intrusion datasets such as KDD-99 "
        "or NSL-KDD lack application-layer HTTP semantics, whereas repositories like CICIDS-2017 collapse attack chains "
        "into independent packet samples without preserving session state. Consequently, a dedicated, session-aware "
        "experimental corpus was constructed using the OWASP Juice Shop (v15.0.0) vulnerable web application."
    )
    add_p(doc, 
        "The Juice Shop application was containerized using Docker and hosted on an isolated loopback network interface "
        "(127.0.0.1:9000). Traffic generation was partitioned into two distinct streams: (1) Benign traffic was produced "
        "using automated client browsing harnesses simulating legitimate e-commerce user behavior—including catalog navigation, "
        "product keyword search, user review perusal, basket updates, checkout flows, and user registration; (2) Malicious multi-stage "
        "traffic was generated using automated penetration testing harnesses (including Burp Suite Intruder, SQLmap, and custom Python "
        "requests scripts) coupled with manual vulnerability verification following the OWASP Web Security Testing Guide. "
        "Interception proxies, specifically mitmproxy and Burp Suite Community Edition, recorded all bidirectional HTTP/1.1 and HTTP/2 "
        "transactions, capturing full URI paths, request headers, query parameters, POST body payloads, HTTP response status codes, "
        "response byte sizes, and inter-arrival timestamps. The resulting raw capture pool comprises 62 distinct XML capture files containing "
        "2,878 unique captured HTTP requests across 5 HTTP methods, 13 status codes, and 653 unique URI endpoints."
    )
    add_p(doc, 
        "Dataset Provenance and Block-Level Session Composition: Because individual capture runs contain limited sequence lengths, multi-request "
        "sessions were assembled using a block-level kill-chain Markov process (implemented in pipeline/compose.py). Rather than generating synthetic "
        "text strings, the composition engine samples contiguous blocks of real, captured requests (block lengths ranging from 3 to 16 requests) "
        "from the capture pool. Across the entire corpus of 2,100 sessions totaling 72,269 request instances, the underlying 2,878 captured requests "
        "(alongside approximately 1,200 live-response requests added exclusively to the training split) are resampled approximately 17 times on average. "
        "The generative process transitions between attack rungs (Reconnaissance -> Fuzzing -> Injection -> Exploitation) while incorporating "
        "retreats, pauses, and skips, as well as an 18% proportion of erratic sessions with near-uniform stage transitions. This reduced the "
        "fraction of monotonically escalating sessions from 1.0 down to ~0.70, ensuring non-trivial temporal dynamics. It is acknowledged as a "
        "methodological characteristic that because session sequences are assembled via this Markov progression grammar, the Hidden Markov Model "
        "transition dynamics estimated during training partly reflect the generator's underlying transition rules."
    )
    add_p(doc, 
        "Deterministic Five-Stage Request Labeling Rules: To resolve syntactic ambiguities between operational phases, explicit labeling criteria "
        "were applied across all five stages:\n"
        "1. Stage 0 (Normal): Standard legitimate user navigation, product catalog queries with alphanumeric keywords, static asset retrievals "
        "(e.g., /assets/public/images), profile updates, and regular authentication attempts lacking metacharacters or anomalous headers.\n"
        "2. Stage 1 (Reconnaissance): Systematic application surface mapping and endpoint enumeration, including requests probing hidden routes "
        "(/admin, /api/Challenges, /rest/user/whoami), technology profiling, directory discovery, and parameter probing without active injection syntax.\n"
        "3. Stage 2 (Fuzzing): Deliberate parameter boundary and exception testing, including submitting boundary integers (-1, 0, 999999), single "
        "metacharacters (', \", <), malformed delimiters, and unexpected data types designed to elicit server error codes (4xx/5xx) or verbose database "
        "diagnostics without structured SQL or script execution.\n"
        "4. Stage 3 (Injection): Multi-token structured injection payloads targeting interpreter manipulation, including boolean SQL clauses "
        "(' OR '1'='1), UNION SELECT statements, inline SQL comments (--), XSS script tags (<script>alert(1)</script>), and attribute event handlers. "
        "The empirical recall on Injection is 25.8% (0.2583) because many subtle injection requests share structural tokens with fuzzing probes, "
        "leading the classifier to conservatively assign Fuzzing until multi-token syntax is established.\n"
        "5. Stage 4 (Exploitation): Payloads achieving verified security compromise, including authentication bypass yielding administrative JWT tokens "
        "(admin'--), unauthorized execution of administrative functions (/rest/admin/application-configuration), privilege escalation, or sensitive "
        "credential extraction (/api/Users/1)."
    )
    add_p(doc, 
        "File-Disjoint Partitioning Protocol: To prevent data leakage, the corpus enforces a strict file-disjoint partitioning protocol before session "
        "composition (pipeline/corpus.py: assign_file_splits). The 62 source XML capture files were partitioned into disjoint subsets: 40 files assigned "
        "to training, 10 files to validation, and 12 files to the held-out test split. Multi-stage sessions were composed by sampling request blocks "
        "exclusively from capture files assigned to that session's designated split; no source block or request sequence crosses a split boundary. "
        "While common application endpoints (e.g., /rest/user/login, /rest/products/search) and standardized scanner payload patterns (e.g., from "
        "Intruder or SQLmap wordlists) legitimately occur across partitions as in operational web traffic, source capture files and raw request blocks "
        "are strictly split-disjoint. The final corpus comprises 2,100 complete sessions totaling 72,269 HTTP request instances: 1,500 sessions "
        "(50,975 requests) in training, 300 sessions (11,120 requests) in validation, and 300 sessions (10,174 requests) in the held-out test split. "
        "In the held-out test split, 34 sessions are fully benign (835 requests) and 266 sessions contain attack sequences (9,339 requests). "
        "Results are reported on this held-out file-disjoint test partition; the limitation of evaluating on a single 300-session test split without "
        "multi-fold cross-validation confidence intervals is noted and discussed in Section 7.6."
    )
    
    # Table 3: Dataset Summary
    add_caption(doc, "Table 3: Summary of the Experimental Dataset and Request Distribution Across Attack Stages")
    tbl3 = doc.add_table(rows=12, cols=5)
    style_table(tbl3, col_widths=[2.0, 1.1, 1.1, 1.1, 1.1])
    
    headers3 = ["Dataset Metric / Attack Stage", "Training Set", "Validation Set", "Held-Out Test Set", "Total Corpus"]
    for i, h in enumerate(headers3):
        format_cell(tbl3.rows[0].cells[i], h, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell_bg(tbl3.rows[0].cells[i], "E6E6E6")
        
    data3 = [
        ["Source Capture Files", "40", "10", "12", "62"],
        ["Unique Raw Requests in Pool", "~1,700 + ~1,200 live", "~580", "~600", "~4,080"],
        ["Composed User Sessions", "1,500", "300", "300", "2,100"],
        ["Purely Benign Sessions (Peak = 0)", "168 (11.2%)", "32 (10.7%)", "34 (11.3%)", "234 (11.1%)"],
        ["Attack Sessions (Peak >= 1)", "1,332 (88.8%)", "268 (89.3%)", "266 (88.7%)", "1,866 (88.9%)"],
        ["Total Composed Request Instances", "50,975", "11,120", "10,174", "72,269"],
        ["Stage 0: Normal Requests", "14,373 (28.2%)", "3,067 (27.6%)", "2,900 (28.5%)", "20,340 (28.1%)"],
        ["Stage 1: Reconnaissance Requests", "11,993 (23.5%)", "2,806 (25.2%)", "2,400 (23.6%)", "17,199 (23.8%)"],
        ["Stage 2: Fuzzing Requests", "9,106 (17.9%)", "2,237 (20.1%)", "1,758 (17.3%)", "13,101 (18.1%)"],
        ["Stage 3: Injection Requests", "8,367 (16.4%)", "1,768 (15.9%)", "1,699 (16.7%)", "11,834 (16.4%)"],
        ["Stage 4: Exploitation Requests", "7,136 (14.0%)", "1,242 (11.2%)", "1,417 (13.9%)", "9,795 (13.6%)"],
    ]
    for r_idx, row_vals in enumerate(data3):
        for c_idx, val in enumerate(row_vals):
            is_bold = (r_idx < 3 or r_idx == 5)
            align = WD_ALIGN_PARAGRAPH.LEFT if c_idx == 0 else WD_ALIGN_PARAGRAPH.CENTER
            format_cell(tbl3.rows[r_idx+1].cells[c_idx], val, bold=is_bold, align=align)
            if r_idx % 2 == 1:
                set_cell_bg(tbl3.rows[r_idx+1].cells[c_idx], "F9F9F9")
                
    add_p(doc, 
        "As reported in Table 3 and illustrated in Fig. 8, the total request count across splits is 50,975 in training, 11,120 "
        "in validation, and 10,174 in the held-out test set (overall total: 72,269 request instances). The average session length is 34.0 requests "
        "in training, 37.1 requests in validation, and 33.9 requests in the test set. Class balance across all three partitions is "
        "consistent, with Normal traffic comprising ~28%, Reconnaissance ~24%, Fuzzing ~18%, Injection ~16%, and Exploitation ~14%. "
        "While evaluating on a single target application (Juice Shop) enables deep semantic modeling of full attack chains, it represents "
        "an acknowledged boundary condition; evaluating cross-application generalization against additional targets (e.g., DVWA, WebGoat) "
        "constitutes an important future research objective discussed in Section 7.6."
    )
    
    # Figure 8
    add_figure_or_callout(doc, "Fig. 8", "Request Distribution Across Attack Stages (Train, Validation, and Test Sets)",
        "fig8_class_distribution.png",
        "Grouped bar chart displaying the exact sample counts across the five attack stages (Normal, Reconnaissance, Fuzzing, "
        "Injection, Exploitation) partitioned across the Training (1,500 sessions / 50,975 requests), Validation (300 sessions / "
        "11,120 requests), and Held-Out Test (300 sessions / 10,174 requests) datasets. Visualizes class balance consistency and confirms "
        "proportional representation across all partitions.",
        "Execute 'python generate_report_figures.py' in the project directory to render 'fig8_class_distribution.png'.",
        width_in=6.0
    )
    
    # 5.4
    add_h2(doc, "5.4 The 31 Causal Feature Engineering Framework")
    add_p(doc, 
        "Feature engineering in intrusion detection systems must satisfy strict temporal causality. A feature vector extracted at "
        "time step t, denoted f_t, is strictly causal if and only if it is a mathematical function solely of the current request r_t "
        "and the historical sequence of prior requests within the same session: f_t = phi(r_1, r_2, ..., r_t). If a feature extraction "
        "routine computes statistics over the entire completed session (for instance, the total number of distinct endpoints visited across "
        "all requests 1 to T), the detector commits lookahead cheating: at request t=2, it uses knowledge of requests occurring at t=50. "
        "Such non-causal systems exhibit artificially inflated laboratory benchmark accuracy but fail completely when deployed in live, "
        "streaming proxy environments."
    )
    add_p(doc, 
        "To enforce absolute causality, the feature extraction engine (implemented in SessionFeatureExtractor) operates as an online state "
        "machine. It maintains a bounded sliding history window (window size W = 8) and an exponential decay context model (decay rate gamma = 0.6). "
        "Unbounded quantities, such as query string lengths, payload byte counts, and inter-arrival times, are stabilized using log1p compression "
        "(log(1 + x)) to prevent extreme outlier values from distorting neural gradient descent. A comprehensive schema of 31 causal features "
        "was engineered across five distinct operational categories, as detailed in Table 4."
    )
    
    # Table 4: 31 Causal Features Schema
    add_caption(doc, "Table 4: The 31 Causal Features Schema Across Five Functional Categories")
    tbl4 = doc.add_table(rows=32, cols=4)
    style_table(tbl4, col_widths=[0.6, 1.8, 1.3, 2.8])
    
    headers4 = ["#", "Feature Key", "Functional Category", "Mathematical Definition and Security Relevance"]
    for i, h in enumerate(headers4):
        format_cell(tbl4.rows[0].cells[i], h, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell_bg(tbl4.rows[0].cells[i], "E6E6E6")
        
    feat_data = [
        ["1", "is_get", "Request Morphology", "Binary indicator: 1 if HTTP method is GET, 0 otherwise."],
        ["2", "is_post", "Request Morphology", "Binary indicator: 1 if HTTP method is POST, 0 otherwise."],
        ["3", "is_write", "Request Morphology", "Binary indicator: 1 if method is PUT, PATCH, or DELETE (state mutation)."],
        ["4", "path_depth", "Request Morphology", "Integer count of URI path segments separated by slashes."],
        ["5", "has_query", "Request Morphology", "Binary indicator: 1 if query parameter string is non-empty."],
        ["6", "log_query_len", "Request Morphology", "Log1p compressed length of query parameter string: ln(1 + len(query))."],
        ["7", "log_body_len", "Request Morphology", "Log1p compressed length of POST/PUT body payload in bytes."],
        ["8", "query_param_count", "Request Morphology", "Total count of parsed query parameters."],
        ["9", "special_char_ratio", "Request Morphology", "Proportion of punctuation, quotes, and non-alphanumeric symbols in query and body."],
        ["10", "sqli_score", "Payload Regex Signatures", "Count of SQL injection keyword and syntax pattern matches (UNION, SELECT, WHERE, OR, comments --, #)."],
        ["11", "xss_score", "Payload Regex Signatures", "Count of XSS HTML tag and JavaScript event handler patterns (<script>, onerror=, onload=, alert)."],
        ["12", "numeric_query", "Payload Regex Signatures", "Binary indicator: 1 if query parameter values consist strictly of numeric digits."],
        ["13", "boundary_value", "Payload Regex Signatures", "Binary indicator: 1 if input values contain boundary probes (-1, 0, 999999, null, NaN)."],
        ["14", "admin_path", "Endpoint Sensitivity", "Binary indicator: 1 if URI contains administrative tokens (/admin, /administration, /metrics)."],
        ["15", "api_path", "Endpoint Sensitivity", "Binary indicator: 1 if URI targets REST API routes (/api/, /rest/)."],
        ["16", "auth_path", "Endpoint Sensitivity", "Binary indicator: 1 if URI targets authentication routes (/login, /auth, /oauth, /rest/user/login)."],
        ["17", "search_path", "Endpoint Sensitivity", "Binary indicator: 1 if URI targets product keyword search routes (/rest/products/search)."],
        ["18", "has_auth_header", "Endpoint Sensitivity", "Binary indicator: 1 if Authorization header (e.g., Bearer token) is present."],
        ["19", "has_identity_header", "Endpoint Sensitivity", "Binary indicator: 1 if user identity headers (X-User-Email, X-Forwarded-For) are present."],
        ["20", "status_2xx", "Response Diagnostics", "Binary indicator: 1 if HTTP response status code is in the 2xx range (Success)."],
        ["21", "status_3xx", "Response Diagnostics", "Binary indicator: 1 if HTTP response status code is in the 3xx range (Redirection)."],
        ["22", "status_4xx", "Response Diagnostics", "Binary indicator: 1 if HTTP response status is in the 4xx range (Client Error, e.g., 401, 404)."],
        ["23", "status_5xx", "Response Diagnostics", "Binary indicator: 1 if HTTP response status is in the 5xx range (Server Error, e.g., 500 unhandled exception)."],
        ["24", "log_resp_len", "Response Diagnostics", "Log1p compressed length of HTTP response payload in bytes: ln(1 + len(resp))."],
        ["25", "log_request_index", "Decaying Session Context", "Chronological index of request within the active user session: ln(1 + t)."],
        ["26", "log_inter_arrival", "Decaying Session Context", "Log1p compressed elapsed time in seconds since the previous request in session: ln(1 + Delta t)."],
        ["27", "endpoint_diversity_recent", "Decaying Session Context", "Number of distinct URI endpoints accessed across the sliding window (W = 8)."],
        ["28", "path_diversity_recent", "Decaying Session Context", "Number of distinct URI base paths accessed across the sliding window (W = 8)."],
        ["29", "error_rate_recent", "Decaying Session Context", "Fraction of requests in the sliding window (W = 8) that produced 4xx or 5xx response statuses."],
        ["30", "attack_pressure", "Decaying Session Context", "Exponential moving average of payload signature scores: C_t = gamma * C_{t-1} + (1 - gamma) * (sqli_score + xss_score) with gamma = 0.6."],
        ["31", "enum_pressure", "Decaying Session Context", "Rolling count of distinct parameterized probes in the window (W = 8), capturing systematic directory/parameter brute-forcing."],
    ]
    for r_idx, row_vals in enumerate(feat_data):
        for c_idx, val in enumerate(row_vals):
            is_bold = (c_idx == 0)
            align = WD_ALIGN_PARAGRAPH.CENTER if c_idx == 0 else (WD_ALIGN_PARAGRAPH.LEFT if c_idx < 3 else WD_ALIGN_PARAGRAPH.JUSTIFY)
            format_cell(tbl4.rows[r_idx+1].cells[c_idx], val, bold=is_bold, align=align)
            if r_idx % 2 == 1:
                set_cell_bg(tbl4.rows[r_idx+1].cells[c_idx], "F9F9F9")
                
    add_p(doc, 
        "The engineered feature space systematically decouples orthogonal signals: Features 1 to 9 capture request morphology and syntax density; "
        "Features 10 to 13 flag malicious payload signatures and boundary probes; Features 14 to 19 evaluate target endpoint criticality and privilege context; "
        "Features 20 to 24 capture application response diagnostics; and Features 25 to 31 maintain causal temporal session memory. "
        "Because context features use bounded sliding windows (W = 8) and exponential decay rather than infinite accumulators, a legitimate user "
        "who inadvertently triggers a 404 error is not permanently penalized for the remainder of their session."
    )
    
    # 5.5
    add_h2(doc, "5.5 Machine Learning Baseline Models")
    add_p(doc, 
        "To isolate the contribution of temporal sequence modeling, a progressive hierarchy of detection models was implemented "
        "and benchmarked, ranging from parameter-free heuristics to state-of-the-art non-linear classifiers:"
    )
    add_p(doc, 
        "1. Parameter-Free Baselines: The Majority Class baseline perpetually assigns the most frequent training label (Normal, Stage 0), "
        "providing a minimum floor for accuracy (28.50%). The Zero-Parameter Current-Request Lookup maps individual HTTP status codes and regex "
        "hits directly to stages using fixed rules. The Zero-Parameter Running-Max Lookup maintains the highest severity stage observed so far "
        "in the session, achieving 29.95% accuracy. These baselines represent conventional signature-matching firewalls."
    )
    add_p(doc, 
        "2. Gradient Boosted Decision Trees (XGBoost): A per-request non-linear tree ensemble trained using the XGBoost framework. "
        "The model operates on the 31-dimensional feature vector x_t. Although x_t incorporates rolling context features (Features 25 to 31, "
        "such as error_rate_recent and attack_pressure), the XGBoost classifier itself is non-recurrent and stateless; it evaluates each request "
        "vector independently without internal recurrent memory or hidden state propagation. Hyperparameters were tuned on the validation set: "
        "max_depth = 6, n_estimators = 100, learning_rate = 0.10, subsample = 0.8, colsample_bytree = 0.8, and multi:softprob objective function. "
        "XGBoost serves as a high-capacity single-request baseline."
    )
    add_p(doc, 
        "3. Long Short-Term Memory (LSTM) Recurrent Neural Network: A sequential deep neural network designed to capture temporal "
        "transitions across successive HTTP requests. The network architecture consists of an input layer accepting 31-dimensional feature vectors, "
        "two stacked causal LSTM layers with 64 hidden units each, a dropout layer (rate = 0.20) to mitigate overfitting, and a Dense linear layer "
        "with Softmax activation outputting posterior class probabilities over the five stages. The model is trained using the Adam optimizer "
        "(learning rate = 0.001) with categorical cross-entropy loss over 30 epochs on sliding history windows (T <= 10). To eliminate stochastic "
        "initialization variance, models were trained across three distinct random seeds (Seed 42, 43, 44), and the seed-averaged ensemble prediction "
        "is reported. On modern AVX2-enabled CPU hardware, evaluating this 3-seed ensemble across bounded sliding windows requires only 0.11 ms per request."
    )
    
    # 5.6
    add_h2(doc, "5.6 Hidden Markov Model (HMM) Transition Dynamics")
    add_p(doc, 
        "Web intrusion attacks follow an underlying stochastic process governed by attacker objectives and defensive feedback. "
        "Attack progression is formalized using a discrete-time Hidden Markov Model (HMM) defined by the 5-tuple lambda = (S, V, A, B, pi):"
    )
    add_p(doc, 
        "Hidden States: S = {s_0: Normal, s_1: Reconnaissance, s_2: Fuzzing, s_3: Injection, s_4: Exploitation}. At any time step t, "
        "the attacker or benign user occupies exactly one unobservable latent stage q_t in S representing their true operational phase."
    )
    add_p(doc, 
        "Transition Probability Matrix: A in R^{5 x 5}, where A_{ij} = P(q_{t+1} = s_j | q_t = s_i) represents the probability of transitioning "
        "from stage s_i to stage s_j. Transition probabilities are estimated directly from empirical state sequences in the training set with "
        "additive Laplace smoothing (smoothing parameter lambda_s = 0.20 selected via grid search on the validation set)."
    )
    add_p(doc, 
        "Observation Emissions and Forward Filtering: In classical discrete HMMs, emissions represent categorical tokens from a codebook. "
        "In this hybrid neural-HMM architecture, the continuous observation vector is the calibrated posterior probability distribution "
        "P_cal(y_t = s_j | x_t) emitted by the neural and tree classifiers. By Bayes' rule, the observation likelihood is proportional to "
        "P(x_t | q_t = s_j) proportional to P(q_t = s_j | x_t) / P(q_t = s_j). Under an uninformative uniform state prior (P(q_t = s_j) = 1/K), "
        "the emission likelihood is directly proportional to the calibrated posterior e_{t, j} = P_cal(y_t = s_j | x_t). "
        "The causal forward algorithm recursively computes the joint forward variable alpha_t(j) = P(x_1, ..., x_t, q_t = s_j | lambda):"
    )
    add_p(doc, 
        "alpha_t(j) = e_{t, j} * SUM_{i=0}^4 [ alpha_{t-1}(i) * A_{ij} ]"
    )
    add_p(doc, 
        "The causal belief distribution b_t in R^5 is obtained by normalizing the forward variables: b_t(j) = alpha_t(j) / SUM_{k=0}^4 alpha_t(k). "
        "Crucially, the forward filter is strictly causal: it requires only past observations x_1 to x_t and can be evaluated online with O(1) "
        "time complexity per request (0.02 ms). In contrast, the classic Viterbi algorithm computes the globally optimal state sequence using dynamic "
        "programming over the entire completed session 1 to T. While Viterbi provides a retrospective offline sequence decoding benchmark, "
        "it is inherently non-causal because decoding state q_t requires backward traceback from future observation x_T, making it unsuitable "
        "for real-time inline blocking."
    )
    
    # 5.7
    add_h2(doc, "5.7 Causal Ensemble Architecture and Decision Logic")
    add_p(doc, 
        "Neither standalone decision trees nor recurrent neural networks provide optimal detection across all operating regimes. XGBoost reacts "
        "instantaneously to acute payload anomalies (such as explicit SQL injection strings) but exhibits high false-positive rates on complex "
        "benign URLs. Conversely, LSTM excels at tracking smooth temporal trends but can suffer from transition inertia when an attacker "
        "abruptly pivots from reconnaissance to exploit delivery. To synthesize the strengths of both paradigms, a Causal Ensemble is implemented."
    )
    add_p(doc, 
        "The ensemble fuses the per-request class probabilities through linear probability blending:"
    )
    add_p(doc, 
        "P_ens(y_t = c) = alpha * P_LSTM(y_t = c) + (1 - alpha) * P_XGB(y_t = c)"
    )
    add_p(doc, 
        "Empirical validation across alpha in [0.0, 1.0] in increments of 0.10 confirmed that an equal blending weight (alpha = 0.50) yields "
        "the highest Macro-F1 score on validation data. To ensure that the blended probability distributions reflect true empirical probabilities, "
        "post-hoc Temperature Scaling [10] is applied to calibrate the blended logits:"
    )
    add_p(doc, 
        "P_cal(y_t = c) = exp(z_c / T) / SUM_{k=0}^4 exp(z_k / T)"
    )
    add_p(doc, 
        "where z is the unnormalized logit vector and T is the learned temperature scalar. Temperature scaling optimizes a single global parameter "
        "T > 0 to rescale logits without altering class ranking or argmax predictions, distinct from two-parameter sigmoid Platt scaling. "
        "Calibration optimization on the validation partition converged to T = 0.916 on the ensemble logits (and T = 1.3485 on raw LSTM outputs), "
        "reducing the Expected Calibration Error (ECE) from 15.68% down to 8.38%. The calibrated ensemble distribution P_cal provides the deployed "
        "current-stage prediction, while the HMM forward filter computes the causal belief state b_t dedicated to next-distinct-stage forecasting "
        "and providing an optional low-false-positive operating mode."
    )
    
    # 5.8
    add_h2(doc, "5.8 Evaluation Metrics")
    add_p(doc, 
        "To rigorously quantify performance across request-level classification, sequential transition fidelity, false alarm rates, "
        "and operational SOC utility, seven distinct mathematical metrics are evaluated on the held-out test set:"
    )
    add_p(doc, 
        "1. Overall Accuracy: The fraction of total requests whose predicted stage matches the ground-truth stage: "
        "Acc = (1 / N) * SUM_{t=1}^N I(hat{y}_t = y_t), where N = 10,174."
    )
    add_p(doc, 
        "2. Macro-Averaged F1-Score (Macro-F1): The unweighted arithmetic mean of F1-scores across all K = 5 classes: "
        "Macro-F1 = (1 / K) * SUM_{c=0}^{K-1} [ 2 * P_c * R_c / (P_c + R_c) ], where P_c and R_c represent class-specific precision and recall."
    )
    add_p(doc, 
        "3. Transition Edge Accuracy: Evaluates classification fidelity specifically at state change boundaries and sequence onsets. "
        "Let E = { t in {1, ..., T} | t = 1 or y_t != y_{t-1} } denote the set of transition points (|E| = 1,054 across the 300 test sessions). "
        "Transition Edge Accuracy is computed as: Edge_Acc = (1 / |E|) * SUM_{t in E} I(hat{y}_t = y_t), measuring how accurately the model "
        "captures dynamic phase shifts rather than relying on intra-block persistence."
    )
    add_p(doc, 
        "4. Benign False-Positive Rate (FPR) and Session False Alarm Rate: Request-level Benign FPR measures the proportion of legitimate "
        "(Stage 0: Normal) requests incorrectly classified as an attack: FPR = FP_Normal / (FP_Normal + TN_Normal). Complementing this, "
        "Session-Level False Alarm Rate (FAR) is evaluated strictly on the 34 pure-benign sessions in the test set: "
        "Session_FAR = (Benign Sessions with >= 1 False Alarm) / (Total Pure-Benign Sessions), quantifying how frequently legitimate user "
        "sessions trigger disruptive operational alerts."
    )
    add_p(doc, 
        "5. Session-Level Campaign Detection Rate: Measures the operational probability that an attacking session is detected before completion. "
        "For all 266 test sessions whose true peak stage reaches an attack stage (s >= 1), evaluation assesses whether the running predicted stage "
        "ever reaches or exceeds that peak stage: Catch_Rate(s) = Caught_Sessions(s) / Total_Sessions(s)."
    )
    add_p(doc, 
        "6. Early Detection Latency & Lead Time: For each caught attack session, detection latency L_det is the number of requests of the peak "
        "attack stage processed before the detector raises an alert: L_det = t_alert - t_peak_onset. The operational lead-time metric measures "
        "the number of requests elapsed between the initial alarm and the final exploitation payload delivery, providing defenders with tactical response margin."
    )
    add_p(doc, 
        "7. Next-Distinct-Stage Intent Forecasting Accuracy: Evaluated strictly at real phase transitions (points where true stage y_{t+1} != y_t, "
        "n = 754 in the test corpus). Because raw adjacent-request pairs exhibit 92.36% persistence due to block structure, predicting y_{t+1} = y_t "
        "is trivial during steady-state runs. Meaningful intent forecasting requires predicting the next distinct stage when a transition occurs. "
        "Using the transition matrix with self-loops removed, B = norm(A - diag(A)), the model forecasts the next distinct stage via "
        "v_next = b_t * B. Top-1 and Top-2 accuracy are compared against naive advance and global empirical prior baselines."
    )
    
    # 5.9
    add_h2(doc, "5.9 Experimental Setup and Reproducibility")
    add_p(doc, 
        "All experiments were conducted on an Intel Core i7-12700H workstation (14 cores, 20 threads @ 2.30 GHz), equipped with 16 GB DDR4 RAM "
        "and a 512 GB NVMe SSD running 64-bit Windows 11. The software environment utilized Python 3.10.12 (64-bit virtualenv), TensorFlow/Keras 2.15.0 "
        "(CPU execution mode), XGBoost 2.0.3, scikit-learn 1.4.0, and hmmlearn 0.3.2, in strict accordance with the specifications in Table 1. "
        "Offline training was executed with CUDA_VISIBLE_DEVICES=-1 to ensure bit-reproducible model weights without cuDNN kernel stochasticity. "
        "Online inference latency was benchmarked strictly on single-thread Intel Core i7-12700H CPU execution, ensuring that live proxy deployments "
        "require no dedicated GPU acceleration. Deterministic execution was guaranteed by fixing random seeds across NumPy (seed = 42), "
        "Python random (seed = 42), and TensorFlow (tf.random.set_seed(42))."
    )
    add_p(doc, 
        "The entire experimental corpus is packaged as dataset_v2.npz, containing 2,100 pre-tokenized request feature sequences, session labels, "
        "and split masks. Benchmark evaluation is fully automated via pipeline/evaluate.py, ensuring that every result reported in Chapter 6 "
        "can be reproduced deterministically with zero stochastic discrepancy. While the current protocol enforces strict file-disjoint partitioning, "
        "evaluations are based on a fixed train/val/test split of Juice Shop traffic; future extensions will evaluate multi-fold cross-validation "
        "and cross-application transferability across additional target environments."
    )
    
    print("Chapter 5 appended successfully.")
