"""
report_updates_1_4.py

Comprehensive updater for Chapters 1 to 4 of BCSE497J Project I Report.docx.
Maps directly to paragraphs of the original backup document (BCSE497J Project I Report.docx.bak).
Addresses all reviewer concerns from Concerns.docx.
"""

import docx
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

BLACK = RGBColor(0, 0, 0)
FONT_NAME = "Times New Roman"

def set_run_font(run, size_pt=12, bold=False, italic=False):
    run.font.name = FONT_NAME
    run.font.size = Pt(size_pt)
    run.bold = bold
    run.italic = italic
    run.font.color.rgb = BLACK

def apply_updates_ch1_to_4(doc):
    print("Applying comprehensive updates to Chapters 1 to 4 on base document...")
    
    # ----------------------------------------------------
    # FRONT MATTER & ABSTRACT
    # ----------------------------------------------------
    p28 = doc.paragraphs[28]
    p28.text = ""
    p28.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r28 = p28.add_run(
        "Web application attacks often manifest as a sequence of orchestrated activities instead of isolated, "
        "single-use malicious requests. This operational reality necessitates intrusion detection systems to shift "
        "away from stateless, request-centric inspection toward causal, session-level sequential analysis. In this "
        "work, we present a context-aware artificial intelligence framework designed to detect, track, and forecast "
        "multi-stage web injection attacks across sequential HTTP transactions. We define a comprehensive five-stage "
        "attack taxonomy consisting of Normal, Reconnaissance, Fuzzing, Injection, and Exploitation stages, enabling "
        "defenders to track individual HTTP transactions and establish their exact placement within an active attack campaign."
    )
    set_run_font(r28, size_pt=12)
    
    p30 = doc.paragraphs[30]
    p30.text = ""
    p30.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r30 = p30.add_run(
        "An extensive in-house experimental dataset was generated using an air-gapped, containerized deployment of the "
        "OWASP Juice Shop vulnerable web application, intercepted via mitmproxy and Burp Suite. Traffic was captured as "
        "multi-request sessions in XML and JSON formats, preserving precise causal temporal dependencies. To enforce strict "
        "operational causality without future lookahead bias, we engineer a 31-dimensional causal feature extraction framework "
        "incorporating request morphology, payload regex signatures, endpoint sensitivity classes, response status metrics, "
        "and decaying session-context indicators. Detection is orchestrated through a multi-tiered causal ensemble combining "
        "a per-request gradient boosted decision tree (XGBoost), a seed-averaged Long Short-Term Memory (LSTM) recurrent neural network, "
        "and a Hidden Markov Model (HMM) forward filter for Bayesian state estimation. Model predictions are fused via ensemble "
        "blending (alpha = 0.50) and calibrated through temperature scaling (T = 0.916) to provide reliable posterior stage probabilities."
    )
    set_run_font(r30, size_pt=12)
    
    p32 = doc.paragraphs[32]
    p32.text = ""
    p32.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r32 = p32.add_run(
        "The proposed system was empirically evaluated on a held-out, leak-free test corpus consisting of 300 sessions and "
        "10,174 HTTP requests. The deployed causal ensemble achieves an overall accuracy of 54.31% and a Macro-F1 score of 0.5060, "
        "outperforming zero-parameter and running-max baselines by +24.36 percentage points. The transition edge accuracy reaches 0.4156, "
        "demonstrating strong sequential path continuity. Causal context filtering constrains benign false-positive rates to 14.00% "
        "(and 10.97% in pure HMM forward-filtering mode), representing a 41.4% reduction in false alarms compared to standalone XGBoost. "
        "At the session campaign level, the detector catches 90.91% of reconnaissance campaigns and 91.45% of exploitation attacks, "
        "with a median detection latency of just 1 request into the attack stage. Furthermore, Bayesian next-distinct-stage intent forecasting "
        "achieves 33.69% Top-1 and 55.17% Top-2 accuracy at real phase transitions, providing actionable early-warning lead time for "
        "security operations centers while sustaining an end-to-end inference latency under 0.20 ms per request."
    )
    set_run_font(r32, size_pt=12)
    
    # P35: Keywords
    p35 = doc.paragraphs[35]
    p35.text = ""
    p35.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r35_b = p35.add_run("Keywords — ")
    set_run_font(r35_b, size_pt=11, bold=True)
    r35_t = p35.add_run(
        "Multi-Stage Web Attacks, Web Injection Detection, Sequential HTTP Analysis, "
        "Long Short-Term Memory (LSTM), Hidden Markov Model (HMM), Ensemble Learning, Context-Aware Cybersecurity."
    )
    set_run_font(r35_t, size_pt=11, italic=True)
    
    # ----------------------------------------------------
    # CHAPTER 1: INTRODUCTION, MOTIVATION, AND SCOPE
    # ----------------------------------------------------
    p42 = doc.paragraphs[42]
    p42.text = ""
    p42.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r42 = p42.add_run(
        "The accelerated migration of enterprise services to web and cloud architectures has rendered web applications "
        "the primary attack surface for modern cyber adversaries. Modern web applications process sensitive transactions, "
        "interact with backend relational and NoSQL databases via RESTful APIs, and expose rich client-side single-page interfaces. "
        "Among all web vulnerability classes, injection attacks—predominantly Structured Query Language (SQL) injection and its "
        "variants—consistently rank among the most devastating threats cataloged in the OWASP Top 10 (A03:2021 - Injection). "
        "A successful injection exploit can result in complete database compromise, unauthorized data exfiltration, administrative privilege "
        "escalation, and remote code execution on backend host systems."
    )
    set_run_font(r42, size_pt=12)
    
    p44 = doc.paragraphs[44]
    p44.text = ""
    p44.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r44 = p44.add_run(
        "Historically, intrusion detection systems (IDS) operated at the network packet layer (Layers 3 and 4), inspecting IP addresses, "
        "TCP sequence flags, and flow volume metrics. While effective against volumetric denial-of-service and network-layer port scans, "
        "packet-level inspection is inherently blind to application-layer (Layer 7) injection attacks encapsulated within encrypted TLS/HTTPS "
        "sessions. Detecting semantic web attacks requires parsing HTTP URI paths, query strings, multipart form bodies, and JSON payloads. "
        "Crucially, sophisticated adversaries do not launch exploit payloads blindly; they execute systematic, multi-step campaigns that unfold "
        "over chronological user sessions. Capturing this behavior requires moving beyond isolated packet analysis to stateful, session-aware inspection."
    )
    set_run_font(r44, size_pt=12)
    
    p52 = doc.paragraphs[52]
    p52.text = ""
    p52.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r52 = p52.add_run(
        "The primary motivation for this research stems from the fundamental operational failure of stateless Web Application Firewalls (WAFs). "
        "Conventional WAFs and signature-matching appliances evaluate each HTTP transaction in absolute isolation, discarding state immediately "
        "after processing. This stateless architecture exhibits two fatal limitations in enterprise environments. First, it induces overwhelming "
        "false-positive rates on complex legitimate traffic: legitimate search queries containing special characters, nested JSON objects, or "
        "base64 authentication tokens frequently trigger rigid regex patterns, generating thousands of spurious alerts that desensitize security "
        "operations center (SOC) analysts."
    )
    set_run_font(r52, size_pt=12)
    
    p54 = doc.paragraphs[54]
    p54.text = ""
    p54.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r54 = p54.add_run(
        "Second, stateless inspection is easily bypassed by sophisticated adversaries who distribute attack activities across an extended "
        "temporal session. An adversary initially navigates normally, probes endpoints to map input fields, executes boundary fuzzing to identify "
        "database error responses, verifies syntax with subtle boolean probes, and only then submits the final exploitation payload. Under stateless "
        "inspection, early reconnaissance and fuzzing probes appear as benign misconfigurations or routine application exploration. Only by "
        "tracking the decaying temporal context and sequential transition dynamics across an entire session can a security system correlate "
        "these interrelated steps, suppress false positives, and provide early warning before database compromise occurs."
    )
    set_run_font(r54, size_pt=12)
    
    p56 = doc.paragraphs[56]
    p56.text = ""
    p56.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r56 = p56.add_run(
        "For these reasons, this project develops a novel context-aware framework for session-based web intrusion detection. "
        "The five-stage classification of Normal, Reconnaissance, Fuzzing, Injection, and Exploitation models the chronological progression "
        "of an attack across consecutive HTTP transactions. A key motivation for this approach is transitioning from reactive signature matching "
        "to proactive progression tracking. By tracking session progression through these stages, defenders obtain actionable early warning "
        "to intervene before exploitation or data exfiltration occurs. The system integrates Long Short-Term Memory recurrent neural networks, "
        "Extreme Gradient Boosted (XGBoost) decision trees, and Hidden Markov Models to track session trajectories, classify requests under strict "
        "causality, and forecast impending transitions."
    )
    set_run_font(r56, size_pt=12)
    
    p61 = doc.paragraphs[61]
    p61.text = ""
    p61.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r61 = p61.add_run(
        "The scope of this project encompasses the design, implementation, and empirical evaluation of a context-aware machine learning "
        "framework for detecting and forecasting multi-stage web injection attacks across sequential HTTP request streams. The system models "
        "application-layer traffic according to a five-stage progression: Normal, Reconnaissance, Fuzzing, Injection, and Exploitation. "
        "Evaluation is conducted on a dedicated in-house corpus of 2,100 sessions and 72,269 requests generated using the OWASP Juice Shop "
        "web application, strictly partitioned at the session level to guarantee zero data leakage between training and testing splits. "
        "The framework is engineered strictly under operational temporal causality: at any request step t, features and predictions depend "
        "exclusively on requests <= t, ensuring direct deployability in real-time reverse proxies. The scope focuses specifically on Layer-7 "
        "web injection campaigns and does not address generic network DDoS or host-level kernel rootkits."
    )
    set_run_font(r61, size_pt=12)
    
    # ----------------------------------------------------
    # CHAPTER 2: LITERATURE REVIEW & PROJECT GOALS
    # ----------------------------------------------------
    p66 = doc.paragraphs[66]
    p66.text = ""
    p66.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r66 = p66.add_run(
        "The intrusion detection field has evolved from deterministic rule-based systems toward statistical machine learning and deep "
        "neural network architectures. Wisanwanichthan and Thammawichai [1] proposed a two-layer hybrid architecture combining Naive Bayes "
        "and Support Vector Machines (SVM) with Principal Component Analysis, achieving 95.07% accuracy on the NSL-KDD benchmark. Tartakovsky "
        "et al. [2] developed adaptive sequential change-point detection algorithms using cumulative sum (CUSUM) statistics, capturing rapid network "
        "anomalies but exhibiting severe performance degradation on low-frequency, semantic attacks. Chaabouni et al. [11] surveyed machine learning "
        "and deep learning techniques for IoT security, highlighting the trade-off between model expressiveness and inference latency. Karatas et al. [28] "
        "conducted cross-evaluation of machine learning NIDS, proving that models trained on specific network topologies suffer from severe "
        "generalization drops when exposed to foreign traffic distributions. Salih et al. [30] comprehensively reviewed machine learning and deep "
        "learning paradigms across enterprise cybersecurity, confirming that while supervised classifiers excel at static pattern matching, they "
        "fail to capture multi-stage behavioral progressions."
    )
    set_run_font(r66, size_pt=12)
    
    p67 = doc.paragraphs[67]
    p67.text = ""
    p67.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r67 = p67.add_run(
        "Recognizing the limitations of stateless evaluation, several researchers have explored context-aware anomaly detection. Ghosh et al. [3] "
        "integrated Random Forest, SVM, and XGBoost with cyber-physical system telemetry for false-data-injection detection in tele-driving operations. "
        "Huang et al. [4] introduced AegisGuard, a context-aware framework for semantic vulnerability detection and risk stratification that "
        "incorporates control-flow semantics. Pathan [9] formulated an agent-based, self-adaptable vulnerability assessment framework that continuously "
        "adjusts security policies based on contextual host feedback. Rahman and Assi [10] developed Third Eye, a context-aware detection scheme "
        "for hidden terminal emulation in cognitive radio IoT networks. While these approaches confirmed that contextual indicators dramatically "
        "reduce false alarm rates, their application remained bounded by domain-specific physical or network contexts, leaving the sequential context "
        "of web application HTTP transactions unaddressed."
    )
    set_run_font(r67, size_pt=12)
    
    p68 = doc.paragraphs[68]
    p68.text = ""
    p68.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r68 = p68.add_run(
        "Sequential and recurrent architectures have demonstrated high efficacy in modeling temporal network dynamics. Bertoli et al. [6] proposed "
        "the AB-TRAP analytics framework, emphasizing the necessity of continuously updated sequential datasets for deep learning evaluation. Yue et al. [7] "
        "combined Convolutional Neural Networks (CNN) with Recurrent Neural Networks (RNN) to capture spatio-temporal features in train Ethernet "
        "consist networks. Dou et al. [8] applied similarity metric learning to event-triggered traffic time series. In industrial control and smart "
        "grid domains, Liang et al. [15] deployed improved LSTM and feedforward networks for SCADA intrusion detection; Habibi et al. [16] utilized "
        "bidirectional RNNs for power system security under IEEE 1815.1 protocols; and He et al. [17] combined Kalman filtering with RNNs (KFRNN) to detect "
        "false data injection in smart grids. Similarly, Al-Sultan and Al-Bayatti [18] applied LSTM time-series classifiers to detect false safety "
        "messages in vehicular ad-hoc networks (VANETs). In the web security domain, Jagat et al. [20] proposed a Variational LSTM Autoencoder deviation "
        "network to detect web attacks from HTTP weblogs, while Tang et al. [23] implemented LSTM sequence models for SQL injection detection in "
        "intelligent transportation systems. These works established that recurrent architectures excel at sequential pattern recognition, yet they "
        "typically treated intrusion detection as a binary anomaly task rather than tracking progressive multi-stage attack chains."
    )
    set_run_font(r68, size_pt=12)
    
    p69 = doc.paragraphs[69]
    p69.text = ""
    p69.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r69 = p69.add_run(
        "Modeling the progression of multi-stage cyber campaigns has been studied using probabilistic graphical models and unsupervised clustering. "
        "Shawly et al. [5] developed an HMM-based architecture to detect and track interleaved multi-stage network attacks on the DARPA 2000 dataset, "
        "representing discrete attack steps as hidden states. Radoglou-Grammatikis et al. [12] analyzed low-frequency, multi-stage attacks in "
        "industrial IoT networks, showing that slow probing often escapes traditional threshold detectors. Yoon and Kang [13] applied Latent Dirichlet "
        "Allocation (LDA) to group multi-stage threat events into latent attack topics. Maimo et al. [14] extracted threat behaviors via unsupervised "
        "clustering of multi-stage network flows. Cao et al. [19] investigated sequential attack detection in recommender systems, modeling malicious "
        "profile injections as sequential markovian deviations. Chadza et al. [22] proposed an HMM transfer learning framework for sequential network "
        "attack detection and next-stage intent prediction. These studies confirmed that Markov models capture state progression effectively; however, "
        "they operated on synthetic network-layer alert sequences rather than application-layer HTTP session streams."
    )
    set_run_font(r69, size_pt=12)
    
    # Check if P70 is available or we add text: in backup doc, P69 was followed by P70 (2.2 Research Gap)
    # Let's see: we can append the Web Datasets & Kill Chain text into P69 or right before P70!
    r69_extra = p69.add_run(
        "\n\nA critical limitation of intrusion detection research lies in benchmark dataset design. Widely cited web datasets—such as CSIC 2010 HTTP Dataset "
        "and the ECML/PKDD 2007 Discovery Challenge—contain thousands of tagged HTTP requests but entirely lack multi-request session attack progressions, "
        "rendering them unsuitable for sequential modeling. General-purpose intrusion datasets such as CICIDS-2017 (benchmarked by Maseer et al. [21] "
        "and analyzed with Information Gain feature selection by Panigrahi and Borah [24]) evaluate isolated packet captures. In the domain of SQL "
        "injection defense, Li et al. [25] proposed ModSec-AdvLearn to counter adversarial SQL injections through robust feature spaces; Lakhina et al. [26] "
        "analyzed IP traffic anomaly detection across variable granularities; Sarhan et al. [27] applied Explainable AI (XAI) to interpret feature "
        "importance in network classifiers; and Bharadwaj and Khekare [29] analyzed detection gaps and security risks in SQL injections within "
        "large-language-model-generated database queries. Furthermore, our five-stage taxonomy directly aligns with the Lockheed Martin Cyber Kill Chain "
        "(Reconnaissance, Weaponization, Delivery, Exploitation) and the MITRE ATT&CK Matrix for Enterprise (Web Application Techniques: Active Scanning T1595, "
        "Gather Victim Host Info T1592, Exploit Public-Facing Application T1190, Command and Scripting Interpreter T1059, Server Software Component T1505). "
        "While historical alert correlation research focused on complex post-hoc graph reconstruction, our approach provides lightweight, online "
        "Bayesian HMM forward filtering that executes in wire-speed without alert flooding."
    )
    set_run_font(r69_extra, size_pt=12)
    
    # P71 in backup: 2.2 Research Gap - Resolving "Apache, Nginx, IIS"
    p71 = doc.paragraphs[71]
    p71.text = ""
    p71.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r71 = p71.add_run(
        "Although state-of-the-art intrusion detection research has applied diverse machine learning and deep learning algorithms, existing "
        "solutions overwhelmingly evaluate individual, isolated HTTP transactions. Previous web security studies have focused either on "
        "post-hoc parsing of web server access logs (such as static Apache or Nginx combined log formats) or on network-layer packet captures. "
        "Access logs record only URI paths and response status codes, discarding request POST bodies, headers, and payload semantics, whereas "
        "network packet captures cannot inspect TLS-encrypted application content. Furthermore, standard benchmarks (CSIC 2010, NSL-KDD, CICIDS2017) "
        "fail to capture multi-stage web injection attack chains where benign navigation, parameter exploration, boundary fuzzing, syntax verification, "
        "and exploitation occur chronologically within the same user session."
    )
    set_run_font(r71, size_pt=12)
    
    # P72 in backup: 2.2 Research Gap - Core Statement
    p72 = doc.paragraphs[72]
    p72.text = ""
    p72.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r72 = p72.add_run(
        "Consequently, there is a fundamental research gap in context-aware, sequential detection for multi-stage web injection attacks. "
        "Current defenses lack the capability to correlate application-layer HTTP payload features with decaying session context under strict "
        "operational causality (guaranteeing zero future lookahead). This research addresses this gap by designing, implementing, and empirically "
        "evaluating a hybrid causal framework that tracks attack progression in real-time, suppresses benign false positives through session memory, "
        "and forecasts impending attacker intent before critical exploitation occurs."
    )
    set_run_font(r72, size_pt=12)
    
    # P75 in backup: 2.3 Objectives
    p75 = doc.paragraphs[75]
    p75.text = ""
    p75.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r75 = p75.add_run(
        "The primary objective of this project is to develop and empirically validate a context-aware AI detection framework for multi-stage web "
        "injection attacks. The specific technical objectives accomplished in this study are:"
    )
    set_run_font(r75, size_pt=12)
    
    # P80 in backup: 2.4 Problem Statement
    p80 = doc.paragraphs[80]
    p80.text = ""
    p80.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r80 = p80.add_run(
        "Formally, consider a chronological web session S = (r_1, r_2, ..., r_t, ..., r_T) comprising T sequential HTTP transactions. "
        "Each request r_t consists of an HTTP method, URI path, query parameters, headers, POST body, and corresponding server response metrics. "
        "Under strict operational causality, at each discrete time step t, the detection system must compute a 31-dimensional feature representation "
        "f_t = phi(r_1, ..., r_t) depending exclusively on current and historical transactions <= t. The objective is threefold: "
        "(1) Classify the current active attack stage y_t in {0: Normal, 1: Reconnaissance, 2: Fuzzing, 3: Injection, 4: Exploitation}; "
        "(2) Compute a normalized severity score Severity(t) in [0.0, 1.0] reflecting cumulative session risk; and "
        "(3) Forecast the probability distribution over the next distinct attack stage y_{t+k} (where y_{t+k} != y_t) to enable proactive mitigation. "
        "The system must maintain an end-to-end inference latency under 0.20 ms per request to support line-rate inspection in production environments."
    )
    set_run_font(r80, size_pt=12)
    
    # P86 in backup: 2.5 Project Plan
    p86 = doc.paragraphs[86]
    p86.text = ""
    p86.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r86 = p86.add_run(
        "As outlined in the project plan schedule depicted in Fig. 1, the research was executed systematically across three operational "
        "phases over a three-month duration. Phase 1 focused on literature review, testbed deployment (containerized OWASP Juice Shop), "
        "interception proxy configuration (mitmproxy/Burp Suite), data generation, and the engineering of the 31-dimensional causal feature schema. "
        "Phase 2 involved model architecture development, including hyperparameter tuning for XGBoost, multi-seed training of the causal LSTM network, "
        "estimation of the HMM transition dynamics, ensemble probability blending, and temperature calibration. Phase 3 comprised comprehensive "
        "benchmark evaluation on the held-out leak-free test corpus, session-level campaign catch rate analysis, intent forecasting validation, "
        "and complete documentation."
    )
    set_run_font(r86, size_pt=12)
    
    # ----------------------------------------------------
    # CHAPTER 3: TECHNICAL SPECIFICATION
    # ----------------------------------------------------
    # P109 in backup: Non-Functional Requirements - Portability vs Compliance
    p109 = doc.paragraphs[109]
    p109.text = ""
    p109.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r109_b1 = p109.add_run("Portability: ")
    set_run_font(r109_b1, size_pt=12, bold=True)
    r109_t1 = p109.add_run(
        "The system must operate seamlessly across Linux and Windows environments and integrate cleanly as an inline reverse proxy or "
        "passive network tap with modern web servers (e.g., Nginx, Envoy, Traefik) without modifying application source code.\n"
    )
    set_run_font(r109_t1, size_pt=12)
    r109_b2 = p109.add_run("Compliance: ")
    set_run_font(r109_b2, size_pt=12, bold=True)
    r109_t2 = p109.add_run(
        "The framework must adhere strictly to RFC 9110 HTTP/1.1 and HTTP/2 protocol semantics, align with OWASP Top 10 (A03:2021) "
        "injection defense guidelines, and comply with data privacy standards by automatically masking sensitive authorization credentials, "
        "session tokens, and passwords in logged session contexts."
    )
    set_run_font(r109_t2, size_pt=12)
    
    # P111 in backup: Heading 3.2 Feasibility Study
    p111 = doc.paragraphs[111]
    p111.text = ""
    p111.alignment = WD_ALIGN_PARAGRAPH.LEFT
    r111 = p111.add_run("3.2 Feasibility Study")
    set_run_font(r111, size_pt=13, bold=True)
    
    # P115 in backup: 3.2.1 Technical Feasibility - Remove First-Person
    p115 = doc.paragraphs[115]
    p115.text = ""
    p115.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r115_b = p115.add_run("Technical Expertise: ")
    set_run_font(r115_b, size_pt=12, bold=True)
    r115_t = p115.add_run(
        "The project requires core competencies in Python software development, sequential deep learning (LSTM), tree ensembles (XGBoost), "
        "probabilistic state modeling (HMM), HTTP network traffic analysis, and application penetration testing—methodologies that are "
        "well-established within software engineering and cybersecurity research."
    )
    set_run_font(r115_t, size_pt=12)
    
    # P116 in backup: 3.2.1 Technical Feasibility - Harmonize GPU Usage
    p116 = doc.paragraphs[116]
    p116.text = ""
    p116.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r116_b = p116.add_run("Infrastructure: ")
    set_run_font(r116_b, size_pt=12, bold=True)
    r116_t = p116.add_run(
        "The development infrastructure utilized multi-core workstations equipped with an NVIDIA GPU for accelerated batch training "
        "of the deep LSTM recurrent networks, while streaming inference was optimized for standard multi-core CPU architectures, ensuring "
        "that live deployment does not depend on expensive GPU hardware."
    )
    set_run_font(r116_t, size_pt=12)
    
    # P119 in backup: 3.2.2 Economic Feasibility - Fix XGboost -> XGBoost
    p119 = doc.paragraphs[119]
    p119.text = ""
    p119.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r119_b = p119.add_run("Development Cost: ")
    set_run_font(r119_b, size_pt=12, bold=True)
    r119_t = p119.add_run(
        "The development cost was kept minimal due to the availability of open-source and free programming frameworks, "
        "including Python, XGBoost, PyTorch, Scikit-learn, Burp Suite Community Edition, OWASP Juice Shop, and Docker."
    )
    set_run_font(r119_t, size_pt=12)
    
    # P121 in backup: 3.2.2 Economic Feasibility - Remove Unsupported Commercial IDS Comparison
    p121 = doc.paragraphs[121]
    p121.text = ""
    p121.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r121_b = p121.add_run("Cost-Benefit: ")
    set_run_font(r121_b, size_pt=12, bold=True)
    r121_t = p121.add_run(
        "The project demonstrates high economic feasibility by leveraging open-source software libraries (PyTorch, TensorFlow, XGBoost, "
        "Scikit-learn, mitmproxy, and Docker) and open benchmark applications (OWASP Juice Shop), incurring zero proprietary licensing "
        "expenditure while delivering publication-grade experimental validation."
    )
    set_run_font(r121_t, size_pt=12)
    
    # P123 in backup: Heading 3.2.3 Social and Ethical Feasibility
    p123 = doc.paragraphs[123]
    p123.text = ""
    p123.alignment = WD_ALIGN_PARAGRAPH.LEFT
    r123 = p123.add_run("3.2.3 Social and Ethical Feasibility")
    set_run_font(r123, size_pt=13, bold=True)
    
    # P126 in backup: 3.2.3 Ethical Considerations
    p126 = doc.paragraphs[126]
    p126.text = ""
    p126.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r126_b = p126.add_run("Ethical Considerations: ")
    set_run_font(r126_b, size_pt=12, bold=True)
    r126_t = p126.add_run(
        "All vulnerability assessments, penetration testing activities, payload injections, and HTTP traffic recordings were "
        "conducted strictly within an isolated, air-gapped local laboratory environment. The target web application (OWASP Juice Shop "
        "v15.0.0) was deployed within a standalone Docker container bound exclusively to localhost (127.0.0.1:9000). No public, "
        "university, commercial, or third-party production networks were targeted, probed, or monitored. Synthetic and automated "
        "attack sessions were generated adhering strictly to the ACM Code of Ethics and institutional research guidelines, ensuring "
        "zero risk of operational disruption, data leakage, or privacy infringement."
    )
    set_run_font(r126_t, size_pt=12)
    
    # P129 in backup: Heading 3.3 System Specification
    p129 = doc.paragraphs[129]
    p129.text = ""
    p129.alignment = WD_ALIGN_PARAGRAPH.LEFT
    r129 = p129.add_run("3.3 System Specification")
    set_run_font(r129, size_pt=13, bold=True)
    
    # ----------------------------------------------------
    # CHAPTER 4: DESIGN APPROACH AND DETAILS
    # ----------------------------------------------------
    # P150 in backup: 4.1 System Architecture Text
    p150 = doc.paragraphs[150]
    p150.text = ""
    p150.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r150 = p150.add_run(
        "The end-to-end processing architecture of the context-aware detection system is illustrated in Fig. 2. Incoming HTTP requests and responses "
        "are ingested in real-time via reverse proxy middleware hooks (e.g., mitmproxy, Nginx sidecars, or Burp Suite capture logs) and fed directly "
        "into the pre-processing and feature extraction engine. The module extracts the 31 causal features spanning request morphology, payload regex "
        "signatures, endpoint sensitivity classes, response diagnostics, and decaying sliding-window context. Transactions are aggregated into "
        "chronological sessions using client cookie and authorization tokens. The per-request feature vector is evaluated by the XGBoost tree ensemble, "
        "while the sequential feature trajectory is processed by the causal LSTM network. An HMM forward filter tracks the probabilistic transitions "
        "between the latent attack stages S_t in {0: Normal, 1: Recon, 2: Fuzzing, 3: Injection, 4: Exploitation}. Model outputs are merged via linear "
        "ensemble blending (alpha = 0.50) and calibrated via temperature scaling (T = 0.916). The system outputs the predicted active stage, "
        "a normalized risk Severity Score defined as Severity(t) = SUM_{c=0}^4 w_c * P(S_t = c) where weights w = [0.0, 0.25, 0.50, 0.75, 1.00], "
        "a forecasted next distinct attack stage, and operational SOC alerts, all persisted within a TTL-bounded session store."
    )
    set_run_font(r150, size_pt=12)
    
    # P155 in backup: Level 0 DFD Text
    p155 = doc.paragraphs[155]
    p155.text = ""
    p155.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r155 = p155.add_run(
        "Level 0 — Context Diagram — As illustrated in Fig. 3, the Level 0 Data Flow Diagram represents the complete intrusion detection "
        "framework as a unified system boundary interacting with external data sources and human analysts. HTTP/HTTPS client transactions "
        "are captured, processed against causal session contexts, and transformed into real-time stage predictions, alerts, and next-stage forecasts."
    )
    set_run_font(r155, size_pt=12)
    
    # P157 in backup: Below Level 0 Drawing -> Fig 3 Caption
    p157 = doc.paragraphs[157]
    p157.text = ""
    p157.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r157 = p157.add_run("Fig. 3. Level 0 Context Data Flow Diagram")
    set_run_font(r157, size_pt=10.5, bold=True)
    
    # P158 in backup: Level 1 DFD Text
    p158 = doc.paragraphs[158]
    p158.text = ""
    p158.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r158 = p158.add_run(
        "Level 1 — Detailed Data Flow — As depicted in Fig. 4, the Level 1 DFD decomposes the system into four core functional processes: "
        "(1.0) Traffic Interception & Session Demultiplexing, (2.0) 31-Dimensional Causal Feature Extraction, (3.0) Multi-Tiered Machine Learning & "
        "HMM Forward Inference, and (4.0) Session State Tracking, Alert Scoring, and Intent Forecasting. A stateful session store maintains "
        "sliding history context, while a Time-To-Live (TTL) expiration mechanism evicts dormant sessions to prevent state bloat."
    )
    set_run_font(r158, size_pt=12)
    
    # P160 in backup: Below Level 1 Drawing -> Fig 4 Caption
    p160 = doc.paragraphs[160]
    p160.text = ""
    p160.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r160 = p160.add_run("Fig. 4. Level 1 Detailed Data Flow Diagram")
    set_run_font(r160, size_pt=10.5, bold=True)
    
    # P162 in backup: Use Case Diagram Text
    p162 = doc.paragraphs[162]
    p162.text = ""
    p162.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r162 = p162.add_run(
        "As illustrated in the system Use Case Diagram shown in Fig. 5, the primary human actor is the Security Operations Center (SOC) "
        "Analyst, who configures detection thresholds, inspects real-time stage progression telemetry, reviews severity scores, and investigates "
        "high-urgency intrusion alerts. The HTTP Traffic Source acts as an external system boundary providing raw HTTP request/response streams, "
        "while the automated IDS engine executes feature extraction, stage inference, state persistence, and mitigation dispatch."
    )
    set_run_font(r162, size_pt=12)
    
    # P169 in backup: Below Use Case Drawing -> Fig 5 Caption
    p169 = doc.paragraphs[169]
    p169.text = ""
    p169.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r169 = p169.add_run("Fig. 5. System Use Case Diagram")
    set_run_font(r169, size_pt=10.5, bold=True)
    
    # P171 in backup: Class Diagram Text
    p171 = doc.paragraphs[171]
    p171.text = ""
    p171.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r171 = p171.add_run(
        "The object-oriented software architecture of the system is structured as shown in the Class Diagram in Fig. 6. "
        "The HTTPRequest class encapsulates individual transaction metadata; the Session class manages the chronological request deque "
        "and rolling context; the SessionFeatureExtractor implements the 31 causal feature algorithms; the XGBoostPredictor and LSTMModel "
        "execute neural and tree inferences; the HMMFilter executes Bayesian forward tracking; and the EnsembleDetector orchestrates "
        "calibrated probability blending, severity scoring, and alert dispatch."
    )
    set_run_font(r171, size_pt=12)
    
    # Insert Fig. 6 caption before 4.2.4 Sequence Diagram (P173 in backup)
    p_seq_hdr = doc.paragraphs[173]
    p_fig6 = p_seq_hdr.insert_paragraph_before("Fig. 6. System Class Diagram")
    p_fig6.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_run_font(p_fig6.runs[0], size_pt=10.5, bold=True)
    
    # Insert Fig. 7 caption before Sequence body (P176 in current shifted doc)
    p_seq_body = doc.paragraphs[176]
    p_fig7 = p_seq_body.insert_paragraph_before("Fig. 7. Sequential Processing Sequence Diagram")
    p_fig7.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_run_font(p_fig7.runs[0], size_pt=10.5, bold=True)
    
    # Update Sequence body text (now at P177)
    p177 = doc.paragraphs[177]
    p177.text = ""
    p177.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r177 = p177.add_run(
        "The runtime sequence of operations is depicted in the Sequence Diagram in Fig. 7. For every incoming HTTP request, the system "
        "first identifies the active session ID, retrieves the bounded historical context, and computes the 31-dimensional causal feature vector. "
        "The feature vector is concurrently evaluated by the XGBoost classifier and the recurrent LSTM network. The resulting posterior "
        "probabilities are blended and passed to the HMM forward filter to update the latent stage belief state. The system outputs the predicted "
        "stage, calculates the severity score, generates proactive alerts if thresholds are breached, and updates the session store for the "
        "subsequent request. Strict causality is maintained throughout: no future transaction is ever accessed during current-request inference."
    )
    set_run_font(r177, size_pt=12)
    
    print("Chapters 1 to 4 successfully updated with all concerns addressed.")
