import sqlite3
import time
import requests
from app.settings import Settings

# Configuration
BASE_URL = f"http://{Settings.APP_HOST}:{Settings.APP_PORT}"
DB_PATH = Settings.DB_USERS_ROOT

def setup_test_settings():
    print("Setting up test rate limits...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Set limit to 5 requests per 10 seconds
    settings = [
        ("global_rate_limit_enabled", "true"),
        ("global_rate_limit", "5"),
        ("global_rate_limit_window", "10")
    ]
    
    for key, value in settings:
        cursor.execute("SELECT setting_id FROM site_settings WHERE setting_key = ?", (key,))
        if cursor.fetchone():
            cursor.execute("UPDATE site_settings SET setting_value = ? WHERE setting_key = ?", (value, key))
        else:
            cursor.execute("INSERT INTO site_settings(setting_key, setting_value, updated_at) VALUES(?, ?, ?)", (key, value, int(time.time())))
            
    conn.commit()
    conn.close()
    print("Test settings applied.")

def test_rate_limit():
    print(f"Testing rate limit against {BASE_URL}...")
    
    # Wait a bit to ensure clean slate (or we could clear the table)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM request_logs")
    conn.commit()
    conn.close()
    
    for i in range(1, 8):
        try:
            response = requests.get(f"{BASE_URL}/")
            print(f"Request {i}: Status {response.status_code}")
            
            if i <= 5:
                if response.status_code != 200:
                    print(f"FAIL: Request {i} should have succeeded but got {response.status_code}")
            else:
                if response.status_code == 429:
                    print(f"SUCCESS: Request {i} was rate limited (429)")
                else:
                    print(f"FAIL: Request {i} should have been rate limited but got {response.status_code}")
                    
        except requests.exceptions.ConnectionError:
            print("FAIL: Could not connect to the server. Is it running?")
            return

def verify_audit_log():
    print("Verifying audit log...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM security_audit_log WHERE event_type = 'rate_limit_triggered' ORDER BY id DESC LIMIT 1")
    log = cursor.fetchone()
    
    if log:
        print(f"SUCCESS: Found audit log entry: {log}")
    else:
        print("FAIL: No audit log entry found for rate limit.")
        
    conn.close()

if __name__ == "__main__":
    setup_test_settings()
    test_rate_limit()
    verify_audit_log()
