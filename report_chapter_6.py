"""
report_chapter_6.py

Generates Chapter 6: RESULTS AND EVALUATION
for BCSE497J Project I Report.docx.
Addresses all reviewer concerns from Concerns.docx:
- Renumbers figures to Figs 9, 10, 11 (following Figs 1-7 in Ch 2 & 4, and Fig 8 in Ch 5).
- Completely removes first-person language.
- Explicitly discusses the lead-time metric in Section 6.6.
- Explains the raw persistence baseline (~0.49) in Section 6.7.
- Retains 100% genuine empirical metrics from benchmark_v2.json.
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

def append_chapter_6(doc):
    print("Appending Chapter 6: Results and Evaluation...")
    
    add_h1(doc, "6. RESULTS AND EVALUATION", page_break_before=True)
    
    # 6.1
    add_h2(doc, "6.1 Benchmark Comparison on Held-Out Test Set")
    add_p(doc, 
        "The empirical evaluation was executed on the held-out test split of 300 unseen sessions comprising 10,174 HTTP requests. "
        "To establish rigorous comparative baselines, nine model architectures spanning parameter-free heuristics, standalone "
        "classifiers, sequential neural networks, and hybrid ensembles were evaluated under identical experimental conditions. "
        "Table 5 presents the complete benchmark results, reporting causality compliance, overall request accuracy, Macro-F1 score, "
        "transition edge accuracy, benign false-positive rate (FPR), and per-request inference latency."
    )
    
    # Table 5: Comprehensive Benchmark
    add_caption(doc, "Table 5: Comprehensive Model Benchmark Comparison on 10,174 Held-Out Test Requests")
    tbl5 = doc.add_table(rows=10, cols=7)
    style_table(tbl5, col_widths=[2.3, 0.7, 0.7, 0.8, 0.8, 0.7, 0.8])
    
    headers5 = ["Evaluated Model Architecture", "Causal", "Accuracy", "Macro-F1", "Edge Acc", "Benign FP", "Latency"]
    for i, h in enumerate(headers5):
        format_cell(tbl5.rows[0].cells[i], h, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell_bg(tbl5.rows[0].cells[i], "E6E6E6")
        
    bench_data = [
        ["Zero-Param: Current-Request Lookup", "Yes", "28.60%", "0.0917", "0.2951*", "0.07%", "-"],
        ["Zero-Param: Running-Max Lookup", "Yes", "29.95%", "0.1346", "0.3008", "2.00%", "-"],
        ["Majority Class Baseline (Normal)", "Yes", "28.50%", "0.0887", "0.2865", "0.00%", "-"],
        ["LSTM (Seed-Averaged x3)", "Yes", "53.56%", "0.5011", "0.3691", "14.69%", "0.17 ms"],
        ["XGBoost (Per-Step Tree Model)", "Yes", "52.49%", "0.4726", "0.4896", "23.90%", "0.03 ms"],
        ["Causal Ensemble (alpha=0.50) [DEPLOYED]", "Yes", "54.31%", "0.5060", "0.4156", "14.00%", "0.18 ms"],
        ["Ensemble + HMM Forward Filter", "Yes", "52.83%", "0.4900", "0.2951*", "10.97%", "0.20 ms"],
        ["Ensemble + HMM Online Viterbi", "Yes", "50.33%", "0.4595", "0.2903", "9.86%", "0.22 ms"],
        ["Ensemble + HMM Offline Viterbi (Benchmark)", "NO", "57.20%", "0.5364", "0.4497", "7.86%", "-"],
    ]
    for r_idx, row_vals in enumerate(bench_data):
        is_deployed = ("DEPLOYED" in row_vals[0])
        for c_idx, val in enumerate(row_vals):
            is_bold = is_deployed or (c_idx == 0 and "Offline" in val)
            align = WD_ALIGN_PARAGRAPH.LEFT if c_idx == 0 else WD_ALIGN_PARAGRAPH.CENTER
            format_cell(tbl5.rows[r_idx+1].cells[c_idx], val, bold=is_bold, align=align)
            if is_deployed:
                set_cell_bg(tbl5.rows[r_idx+1].cells[c_idx], "FFF2CC")
            elif r_idx % 2 == 1:
                set_cell_bg(tbl5.rows[r_idx+1].cells[c_idx], "F9F9F9")
                
    add_p(doc, 
        "*Note on Edge Accuracy: The identical Edge Accuracy of 0.2951 for Zero-Param Lookup and Ensemble + HMM Forward Filter represents "
        "an exact empirical coincidence: both models correctly classified exactly 311 out of 1,054 transition edge points (311 / 1,054 = 0.295066). "
        "Zero-Param Lookup captures acute regex hits, whereas the HMM forward filter imposes heavy temporal smoothing that dampens immediate boundary response."
    )
    add_p(doc, 
        "The experimental results establish several pivotal findings. First, the deployed Causal Ensemble (alpha = 0.50) achieves "
        "an overall accuracy of 54.31% and a Macro-F1 score of 0.5060 on the held-out test corpus. Compared to the best parameter-free "
        "heuristic (Running-Max Lookup at 29.95%), the deployed ensemble achieves an empirical margin of +24.36 percentage "
        "points, demonstrating genuine learning of multi-stage sequential patterns over static lookup heuristics. "
        "At the same time, this accuracy reflects the realistic difficulty of fine-grained request-level discrimination in web traffic: while early reconnaissance "
        "and late exploitation are detected reliably, intermediate probing stages exhibit significant syntactic overlap, as detailed in Section 6.2."
    )
    add_p(doc, 
        "Second, comparing standalone XGBoost against the deployed ensemble reveals the indispensable value of temporal sequence integration. "
        "While per-step XGBoost attains 52.49% accuracy, it suffers from an unacceptably high benign false-positive rate of 23.90% (flagging nearly "
        "one out of every four benign requests as malicious). In contrast, the Causal Ensemble cuts the benign FPR to 14.00%—a 41.4% relative "
        "reduction in false alarms. When configured with the HMM Forward Filter (low-FP operating mode), benign FPR is suppressed further to "
        "10.97% while maintaining 52.83% accuracy, demonstrating controllable trade-offs between sensitivity and alert fatigue."
    )
    add_p(doc, 
        "Finally, the non-causal Offline Viterbi decoder achieves 57.20% accuracy and 0.5364 Macro-F1. However, as established in Section 5.6, "
        "Offline Viterbi uses retrospective backward dynamic programming over future requests (t+1 to T) and cannot be deployed in live proxies. "
        "The 2.89 percentage point gap between the online causal ensemble (54.31%) and the retrospective offline benchmark (57.20%) represents "
        "the modest performance cost of strict operational causality."
    )
    
    # 6.2
    add_h2(doc, "6.2 Per-Class Performance and Confusion Matrix Analysis")
    add_p(doc, 
        "To evaluate detection efficacy across individual rungs of the attack chain, class-specific Precision, Recall, and F1-scores "
        "were computed on the 10,174 held-out test requests, as summarized in Table 6. The complete 5x5 empirical confusion matrix "
        "is detailed in Table 7 and visualized as a heatmap in Fig. 9."
    )
    
    # Table 6: Class-wise Performance
    add_caption(doc, "Table 6: Class-Wise Performance Metrics of Deployed Causal Ensemble on Held-Out Test Set")
    tbl6 = doc.add_table(rows=7, cols=5)
    style_table(tbl6, col_widths=[2.2, 1.2, 1.2, 1.2, 1.0])
    
    headers6 = ["Stage Class", "Precision", "Recall", "F1-Score", "Test Support"]
    for i, h in enumerate(headers6):
        format_cell(tbl6.rows[0].cells[i], h, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell_bg(tbl6.rows[0].cells[i], "E6E6E6")
        
    class_metrics = [
        ["Stage 0: Normal", "64.11%", "86.00%", "0.7348", "2,900 requests"],
        ["Stage 1: Reconnaissance", "51.05%", "48.46%", "0.4972", "2,400 requests"],
        ["Stage 2: Fuzzing", "32.30%", "30.15%", "0.3118", "1,758 requests"],
        ["Stage 3: Injection", "39.32%", "25.78%", "0.3114", "1,699 requests"],
        ["Stage 4: Exploitation", "71.94%", "63.51%", "0.6747", "1,417 requests"],
        ["Macro Average", "51.74%", "50.78%", "0.5060", "10,174 requests"],
    ]
    for r_idx, row_vals in enumerate(class_metrics):
        is_avg = (r_idx == 5)
        for c_idx, val in enumerate(row_vals):
            align = WD_ALIGN_PARAGRAPH.LEFT if c_idx == 0 else WD_ALIGN_PARAGRAPH.CENTER
            format_cell(tbl6.rows[r_idx+1].cells[c_idx], val, bold=is_avg, align=align)
            if is_avg:
                set_cell_bg(tbl6.rows[r_idx+1].cells[c_idx], "EAEAEA")
            elif r_idx % 2 == 1:
                set_cell_bg(tbl6.rows[r_idx+1].cells[c_idx], "F9F9F9")
                
    # Table 7: 5x5 Confusion Matrix
    add_caption(doc, "Table 7: 5x5 Empirical Confusion Matrix of Deployed Model on 10,174 Test Requests")
    tbl7 = doc.add_table(rows=6, cols=6)
    style_table(tbl7, col_widths=[1.8, 1.0, 1.0, 1.0, 1.0, 1.0])
    
    headers7 = ["True \\ Predicted", "Pred: Normal", "Pred: Recon", "Pred: Fuzzing", "Pred: Injection", "Pred: Exploit"]
    for i, h in enumerate(headers7):
        format_cell(tbl7.rows[0].cells[i], h, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell_bg(tbl7.rows[0].cells[i], "E6E6E6")
        
    cm_data = [
        ["True: Normal (2,900)", "2,494", "184", "121", "77", "24"],
        ["True: Recon (2,400)", "932", "1,163", "80", "86", "139"],
        ["True: Fuzzing (1,758)", "137", "493", "530", "496", "102"],
        ["True: Injection (1,699)", "175", "206", "794", "438", "86"],
        ["True: Exploit (1,417)", "152", "232", "116", "17", "900"],
    ]
    for r_idx, row_vals in enumerate(cm_data):
        for c_idx, val in enumerate(row_vals):
            align = WD_ALIGN_PARAGRAPH.LEFT if c_idx == 0 else WD_ALIGN_PARAGRAPH.CENTER
            is_diag = (c_idx == r_idx + 1)
            format_cell(tbl7.rows[r_idx+1].cells[c_idx], val, bold=is_diag, align=align)
            if is_diag:
                set_cell_bg(tbl7.rows[r_idx+1].cells[c_idx], "D9EAD3")
            elif r_idx % 2 == 1:
                set_cell_bg(tbl7.rows[r_idx+1].cells[c_idx], "F9F9F9")
                
    add_p(doc, 
        "Inspection of Table 6 and Table 7 highlights sharp performance differences between the early/late stages and the intermediate rungs. "
        "Stage 0 (Normal) achieves high recall (86.00%), with 2,494 of 2,900 benign requests correctly classified. Crucially, Stage 4 (Exploitation) "
        "demonstrates high precision (71.94%) and recall (63.51%), with 900 of 1,417 exploitation requests correctly detected and only 24 benign "
        "requests ever misclassified as exploitation (a benign false-positive rate for critical exploits of under 0.83%)."
    )
    add_p(doc, 
        "Conversely, Table 6 and Table 7 reveal significant cross-stage boundary leakage between Stage 2 (Fuzzing) and Stage 3 (Injection). "
        "Stage 3 achieves a recall of 25.78% (438 of 1,699 requests correctly identified). Out of 1,699 true injection requests, 794 (46.7%) "
        "were classified as Fuzzing, while 496 of 1,758 true fuzzing requests (28.2%) were classified as Injection. "
        "This boundary confusion is technically well-founded: input space fuzzing probes frequently inject single quotes, SQL comment sequences, "
        "and boundary integers to probe backend database parsers, sharing near-identical lexical token distributions and HTTP 500/400 response "
        "signatures with early SQL injection syntax verification. The model therefore adopts a conservative posture on early SQL verification probes "
        "until overt exploitation signals emerge. The architectural implications of this inter-stage overlap are explored in Section 7.2."
    )
    
    # Figure 9
    add_figure_or_callout(doc, "Fig. 9", "5x5 Confusion Matrix Heatmap on Held-Out Test Set",
        "fig9_confusion_matrix.png",
        "Heatmap visualization of the 5x5 confusion matrix from Table 7, plotting ground-truth attack stages against model predictions "
        "across the 10,174 held-out test requests. Dark green diagonal cells indicate high true positive accuracy (notably 2,494 Normal and "
        "900 Exploitation requests), while shaded off-diagonal cells illustrate the syntactic boundary confusion between Fuzzing and Injection.",
        "Generate 'fig9_confusion_matrix.png' using 'python generate_report_figures.py'.",
        width_in=5.4
    )
    
    # 6.3
    add_h2(doc, "6.3 Transition Edge Accuracy and Sequential Consistency")
    add_p(doc, 
        "A critical vulnerability of stateless intrusion detectors is output flicker: classifying request t as an exploit, request t+1 as normal, "
        "and request t+2 as reconnaissance, generating contradictory, disorienting alerts for security operations centers. To quantify sequential "
        "path stability, Transition Edge Accuracy evaluates classification accuracy specifically at state transition boundaries and sequence "
        "onsets (the set E = { t in {1, ..., T} | t = 1 or y_t != y_{t-1} }, containing |E| = 1,054 edge points in the test split)."
    )
    add_p(doc, 
        "As documented in Table 5, standalone XGBoost achieves an Edge Accuracy of 0.4896, compared to 0.4156 for the deployed Causal Ensemble, "
        "0.3691 for LSTM, and 0.2951 for HMM Forward Filtering. This comparison illustrates a fundamental engineering trade-off: XGBoost operates "
        "without temporal memory or state inertia, allowing it to react instantaneously to acute single-request payload spikes at the exact moment "
        "of a phase shift. However, this lack of inertia comes at the severe expense of a 23.90% benign false-positive rate and high session flicker. "
        "In contrast, the LSTM hidden state and HMM transition smoothing impose temporal continuity: while this state inertia dampens immediate "
        "reaction on the single transition request (yielding 0.4156 Edge Accuracy), it slashes benign FPR from 23.90% down to 14.00% (and 10.97% with HMM), "
        "eliminating erratic false-alarm oscillation across multi-request sessions."
    )
    
    # 6.4
    add_h2(doc, "6.4 False-Positive Rate Reduction via Temporal Context")
    add_p(doc, 
        "In enterprise environments, alert fatigue is the single primary cause of security monitoring failure. If an intrusion detection system "
        "triggers thousands of spurious alerts on benign traffic, operators inevitably disable or ignore its telemetry. A core contribution of this "
        "research is demonstrating that temporal sequence modeling dramatically suppresses false-positive rates."
    )
    add_p(doc, 
        "As established in Table 5, standalone XGBoost yields a benign FPR of 23.90%. Although XGBoost consumes the engineered context features "
        "(Features 25 to 31, including attack_pressure, error_rate_recent, and endpoint_diversity_recent), the tree classifier itself evaluates "
        "each request in isolation without internal recurrent state propagation. Consequently, complex legitimate HTTP requests containing nested "
        "JSON strings, URL-encoded search filters, or base64 tokens exhibit high special_char_ratio and query_param_count values, triggering false alarms. "
        "In contrast, the recurrent LSTM network maintains continuous hidden state across successive requests (achieving 14.69% FPR alone). "
        "When blended into the Causal Ensemble, benign FPR drops to 14.00%—and further to 10.97% under HMM forward filtering. This constitutes "
        "an absolute reduction of 9.90 to 12.93 percentage points in false alarms, driven primarily by temporal sequence memory."
    )
    
    # 6.5
    add_h2(doc, "6.5 Session-Level Attack Campaign Detection")
    add_p(doc, 
        "Evaluating intrusion detection systems exclusively on per-request accuracy substantially understates their real-world defensive efficacy. "
        "From an operational perspective, a security operations center does not require an intrusion detection system to correctly classify every "
        "single ancillary probe in an attack chain; rather, the system must reliably catch the attacking session and alert operators before exploit "
        "completion. To evaluate this operational capability, session-level campaign catch rates were analyzed across all test sessions whose true peak "
        "stage reached an attack phase (s >= 1). The empirical results are detailed in Table 8."
    )
    
    # Table 8: Session Detection
    add_caption(doc, "Table 8: Session-Level Campaign Detection Rates (266 Attack Sessions) and Benign Session False Alarm Rates (34 Benign Sessions)")
    tbl8 = doc.add_table(rows=8, cols=4)
    style_table(tbl8, col_widths=[2.4, 1.3, 1.3, 1.5])
    
    headers8 = ["Evaluation Category / Peak Stage", "Total Sessions", "Caught / Flagged", "Session Rate"]
    for i, h in enumerate(headers8):
        format_cell(tbl8.rows[0].cells[i], h, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell_bg(tbl8.rows[0].cells[i], "E6E6E6")
        
    sess_data = [
        ["Peak Stage 1: Reconnaissance (Ensemble)", "44 sessions", "40 sessions", "90.91% Catch"],
        ["Peak Stage 2: Fuzzing (Ensemble)", "35 sessions", "30 sessions", "85.71% Catch"],
        ["Peak Stage 3: Injection (Ensemble)", "70 sessions", "52 sessions", "74.29% Catch"],
        ["Peak Stage 4: Exploitation (Ensemble)", "117 sessions", "107 sessions", "91.45% Catch"],
        ["Overall Attack Campaigns (Causal Ensemble)", "266 sessions", "229 sessions", "86.09% Catch"],
        ["Overall Attack Campaigns (Standalone XGBoost)", "266 sessions", "247 sessions", "92.86% Catch*"],
        ["Benign Session False Alarms (Causal Ensemble vs XGB)", "34 pure-benign", "12 vs 18 sessions", "35.29% vs 52.94% FAR"],
    ]
    for r_idx, row_vals in enumerate(sess_data):
        is_total = (r_idx == 4)
        is_highlight = (r_idx >= 4)
        for c_idx, val in enumerate(row_vals):
            align = WD_ALIGN_PARAGRAPH.LEFT if c_idx == 0 else WD_ALIGN_PARAGRAPH.CENTER
            format_cell(tbl8.rows[r_idx+1].cells[c_idx], val, bold=is_total or (c_idx == 3 and is_highlight), align=align)
            if is_total:
                set_cell_bg(tbl8.rows[r_idx+1].cells[c_idx], "EAEAEA")
            elif r_idx == 6:
                set_cell_bg(tbl8.rows[r_idx+1].cells[c_idx], "FFF2CC")
            elif r_idx % 2 == 1:
                set_cell_bg(tbl8.rows[r_idx+1].cells[c_idx], "F9F9F9")
                
    add_p(doc, 
        "As shown in Table 8, the deployed Causal Ensemble achieves high campaign catch rates across individual attack stages: 90.91% of reconnaissance "
        "campaigns (40 of 44 sessions), 85.71% of fuzzing campaigns (30 of 35 sessions), 74.29% of injection campaigns (52 of 70 sessions), "
        "and 91.45% of critical exploitation campaigns (107 of 117 sessions). Across all 266 attacking sessions in the test corpus, the ensemble "
        "successfully raised alarms on 229 sessions, yielding an aggregate campaign catch rate of 86.09%."
    )
    add_p(doc, 
        "Critically, Table 8 illuminates why standalone XGBoost appears to achieve a higher raw catch rate (92.86%, 247 of 266 sessions): "
        "XGBoost's aggressive single-request sensitivity comes at the prohibitive cost of triggering false alarms on 52.94% (18 of 34) of purely "
        "benign sessions in the test partition. In contrast, the Causal Ensemble reduces benign session false alarms to 35.29% (12 of 34 sessions, "
        "corresponding to an 8.98% per-request FPR across benign sessions). This demonstrates that the ensemble achieves robust multi-stage campaign "
        "detection while significantly mitigating disruptive benign false alarms."
    )
    
    # 6.6
    add_h2(doc, "6.6 Early Detection Latency & Defensive Lead Time")
    add_p(doc, 
        "Catching an attack is operationally useless if detection occurs only after the session has terminated and data exfiltration has completed. "
        "Detection latency—measured as the exact number of requests processed within the peak attack stage before the alarm is triggered—was "
        "computed for all 229 caught attack campaigns, as plotted in Fig. 10."
    )
    add_p(doc, 
        "The empirical detection latency distribution exhibits a median detection latency of exactly 1 request into the active attack stage. "
        "The mean detection latency is 3.3 requests, and exactly 69.00% of all attack campaigns are successfully detected within <= 3 requests of onset. "
        "Crucially, evaluating the operational lead-time metric—the interval between the first attack alert and the final exploitation request—reveals "
        "that security operations centers receive a median defensive lead time of 7 requests prior to database compromise. This rapid response provides "
        "defenders with an actionable window of intervention to terminate active TCP connections, invalidate compromised session tokens, "
        "or apply targeted rate limiting before exfiltration succeeds."
    )
    
    # Figure 10
    add_figure_or_callout(doc, "Fig. 10", "Cumulative Attack Campaign Detection Latency Distribution",
        "fig10_detection_latency.png",
        "Cumulative distribution function (CDF) and latency histogram illustrating the number of requests elapsed within the peak attack stage "
        "before initial detection. Highlights that 50% of attacks are caught on the very first malicious request (median latency = 1 req), "
        "and 69.00% are caught within <= 3 requests, validating early warning responsiveness.",
        "Generate 'fig10_detection_latency.png' using 'python generate_report_figures.py'.",
        width_in=6.0
    )
    
    # 6.7
    add_h2(doc, "6.7 Next-Stage Attack Intent Forecasting")
    add_p(doc, 
        "Traditional intrusion detection systems are purely reactive: they report what an attacker has already done. In contrast, the proposed "
        "framework implements proactive intent forecasting. In sequential web attack analysis, next-stage prediction must be carefully formulated to avoid "
        "trivial baseline dominance. Two distinct forecasting tasks arise in this setting:"
    )
    add_p(doc, 
        "1. Task A (Continuous Next-Request Prediction): Predicting y_{t+1} from observations 1..t across every transaction in the continuous request stream. "
        "Because user sessions and attack campaigns naturally progress in contiguous multi-request blocks, consecutive requests share identical "
        "labels across 9,120 of the 9,874 adjacent request pairs in the test set—a persistence baseline of 92.36%. Consequently, a trivial 'same-stage "
        "persistence' heuristic (hat{y}_{t+1} = y_t) scores 92.36% accuracy simply by anticipating that the active block continues. However, predicting "
        "that an adversary will merely repeat their current activity provides zero forewarning of tactical escalation or stage transitions."
    )
    add_p(doc, 
        "2. Task B (Next-Distinct-Stage Intent Forecasting): The primary operational challenge for proactive defense is anticipating which distinct "
        "stage an adversary will pivot to when a phase transition occurs (y_{t+1} != y_t). To rigorously evaluate this capability, next-distinct-stage "
        "intent forecasting was benchmarked across all 754 ground-truth phase transitions in the held-out test set. At these transition boundaries, "
        "the same-stage persistence baseline is definitionally 0.00% because the stage has shifted by definition. Using the normalized transition matrix "
        "with self-loops removed, B = norm(A - diag(A)), the model projects the current Bayesian belief vector b_t one phase ahead: v_next = b_t * B. "
        "Performance was benchmarked against relevant baseline heuristics: (1) Uniform Random Guess across the 4 candidate alternative stages (25.00% Top-1, "
        "50.00% Top-2), (2) Global most-common next distinct stage from training data (27.06% Top-1), (3) Naive linear advance ('always guess min(y_t + 1, 4)', "
        "27.85% Top-1), and (4) Transition Matrix Empirical Prior (choosing argmax_j B_{y_t, j}, 30.64% Top-1). The results are detailed in Table 9."
    )
    
    # Table 9: Next-Stage Intent Forecasting
    add_caption(doc, "Table 9: Next-Distinct-Stage Intent Forecasting Accuracy at 754 Real Phase Transitions")
    tbl9 = doc.add_table(rows=6, cols=3)
    style_table(tbl9, col_widths=[3.5, 1.5, 1.5])
    
    headers9 = ["Forecasting Architecture / Baseline (Task B)", "Top-1 Accuracy", "Top-2 Accuracy"]
    for i, h in enumerate(headers9):
        format_cell(tbl9.rows[0].cells[i], h, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell_bg(tbl9.rows[0].cells[i], "E6E6E6")
        
    forecast_data = [
        ["Baseline 1: Uniform Random Guess (1 in 4 distinct)", "25.00%", "50.00%"],
        ["Baseline 2: Global Most-Common Next Distinct Stage", "27.06%", "-"],
        ["Baseline 3: Naive Linear Advance (min(s+1, 4))", "27.85%", "-"],
        ["Baseline 4: Transition Matrix Empirical Prior (argmax B)", "30.64%", "-"],
        ["Proposed Model: Bayesian Belief @ Transition Matrix", "33.69%", "55.17%"],
    ]
    for r_idx, row_vals in enumerate(forecast_data):
        is_model = (r_idx == 4)
        for c_idx, val in enumerate(row_vals):
            align = WD_ALIGN_PARAGRAPH.LEFT if c_idx == 0 else WD_ALIGN_PARAGRAPH.CENTER
            format_cell(tbl9.rows[r_idx+1].cells[c_idx], val, bold=is_model, align=align)
            if is_model:
                set_cell_bg(tbl9.rows[r_idx+1].cells[c_idx], "D9EAD3")
            elif r_idx % 2 == 1:
                set_cell_bg(tbl9.rows[r_idx+1].cells[c_idx], "F9F9F9")
                
    add_p(doc, 
        "*Note: Table 9 evaluates Task B (forecasting the next distinct stage when y_{t+1} != y_t across 754 phase transitions). In contrast, on the unconstrained "
        "continuous stream (Task A), consecutive requests share identical labels in 92.36% of instances (9,120 / 9,874 pairs); at true phase transitions, however, "
        "same-stage persistence is definitionally 0.00%."
    )
    add_p(doc, 
        "As documented in Table 9, the Bayesian intent forecasting engine achieves 33.69% Top-1 accuracy and 55.17% Top-2 accuracy at real phase "
        "transitions, outperforming random chance (25.00%), the global frequency baseline (27.06%), the naive linear advance baseline (27.85%), "
        "and the empirical transition prior baseline (30.64%). In over half of all phase transitions (55.17%), the adversary's subsequent objective "
        "is captured within the top two forecasted candidates, though this Top-2 score is 5.17 percentage points above random 2-of-4 selection (50.00%). "
        "This predictive intelligence provides security operations centers with a preliminary heuristic early warning to pre-emptively tighten defensive controls—such as "
        "dynamically activating parameterized query verification or tightening WAF inspection rules—before exploitation payloads arrive."
    )
    
    # 6.8
    add_h2(doc, "6.8 Real-Time Streaming and Inference Latency")
    add_p(doc, 
        "To validate deployment viability in live enterprise proxy environments, computational execution latency was profiled across the full "
        "inference pipeline on 10,174 test requests. The per-request execution latency decomposes into four discrete processing stages: "
        "(1) 31-dimensional causal feature extraction: 0.03 ms; "
        "(2) XGBoost decision tree inference: 0.03 ms; "
        "(3) 3-seed causal LSTM forward pass: 0.11 ms; and "
        "(4) Calibration and probability blending: 0.01 ms."
    )
    add_p(doc, 
        "The total algorithmic processing latency of the deployed Causal Ensemble sums to exactly 0.18 ms per request (0.03 + 0.03 + 0.11 + 0.01 = 0.18 ms), "
        "consistently below 0.20 ms on single-thread CPU execution without GPU acceleration. When the optional HMM forward belief state update is enabled, "
        "an additional 0.02 ms is required, bringing total latency to 0.20 ms per request (and 0.22 ms if online causal Viterbi decoding is invoked). "
        "The 3-seed LSTM forward pass executes in 0.11 ms on CPU because TensorFlow oneDNN and AVX2 vector optimizations execute matrix multiplications "
        "across bounded history windows (T <= 10) in batch size 1 with minimal FLOP requirements. This latency measurement strictly reflects the computational "
        "cost of feature extraction, model inference, and belief state updating; it deliberately excludes network transmission delay and reverse-proxy socket I/O, "
        "which vary by network environment. Based on this computational profile, a single CPU core possesses an algorithmic processing capacity exceeding "
        "5,000 HTTP requests per second, demonstrating that the context-aware detection pipeline imposes negligible overhead when integrated into high-throughput web proxy infrastructure. "
        "A live console execution run is illustrated in Fig. 11."
    )
    
    # Figure 11
    add_figure_or_callout(doc, "Fig. 11", "Real-Time Streaming Detection Run Console Output",
        "fig11_streaming_console.png",
        "Real-time console output from pipeline/live_demo.py executing against streaming HTTP traffic from OWASP Juice Shop. "
        "Illustrates per-request transaction monitoring, session tracking, real-time stage classification, calibrated confidence scores, "
        "posterior state beliefs, next-stage forecasts, and instantaneous alert generation under 0.20 ms latency.",
        "Launch 'python -m pipeline.live_demo' in a terminal with Juice Shop running on localhost:9000.",
        width_in=6.2
    )
    
    print("Chapter 6 appended successfully.")
