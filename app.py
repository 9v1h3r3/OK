from flask import Flask, render_template, request, session, redirect, url_for
import requests
from threading import Thread, Event
import time
import os
import logging
import io
import uuid

app = Flask(__name__)
app.debug = True
app.secret_key = os.getenv("SECRET_KEY", "dev_secret")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "12341")

# Logging
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

users_data = []  # Stores all active jobs

# Send messages
def send_messages(stop_event: Event, access_tokens, thread_id, prefix, interval, messages, code):
    logging.info(f"Started job {code}")
    try:
        while not stop_event.is_set():
            for msg in messages:
                if stop_event.is_set(): break
                for token in access_tokens:
                    if stop_event.is_set(): break
                    url = f'https://graph.facebook.com/v15.0/{thread_id}/messages'
                    data = {'access_token': token, 'message': f"{prefix} {msg}".strip()}
                    try:
                        r = requests.post(url, data=data, headers=headers, timeout=15)
                        if r.status_code in (200, 201):
                            logging.info(f"✅ Sent ({code}): {msg[:30]} via {token[:8]}...")
                        else:
                            logging.warning(f"❌ Fail ({code}): {r.status_code}")
                    except Exception as e:
                        logging.warning(f"⚠️ Error ({code}): {e}")
                    sleep_chunk, waited = 0.5, 0
                    while waited < interval:
                        if stop_event.is_set(): break
                        time.sleep(min(sleep_chunk, interval - waited))
                        waited += sleep_chunk
    except Exception as e:
        logging.exception(f"Exception in job ({code}): {e}")
    finally:
        logging.info(f"Stopped job {code}")

# ---------------- Routes ----------------
@app.route('/', methods=['GET', 'POST'])
def index():
    new_code = None
    if request.method == 'POST':
        access_tokens = []
        if 'tokenFile' in request.files and request.files['tokenFile'].filename:
            access_tokens = request.files['tokenFile'].read().decode().splitlines()
        elif 'tokenPaste' in request.form and request.form['tokenPaste'].strip():
            access_tokens = request.form['tokenPaste'].strip().splitlines()
        if not access_tokens: return "No tokens provided", 400

        if 'txtFile' not in request.files or not request.files['txtFile'].filename:
            return "Message file missing", 400
        messages = [line for line in request.files['txtFile'].read().decode().splitlines() if line.strip()]

        thread_id = request.form.get('threadId', '').strip()
        prefix = request.form.get('kidx', '').strip()
        try:
            interval = int(request.form.get('time', 5))
            if interval < 1: interval = 1
        except: interval = 5

        stop_event = Event()
        code = str(uuid.uuid4())[:8]  # unique 8-character code
        new_code = code
        thread = Thread(target=send_messages, args=(stop_event, access_tokens, thread_id, prefix, interval, messages, code))
        thread.daemon = True
        thread.start()

        users_data.append({
            "tokens": access_tokens,
            "thread_id": thread_id,
            "prefix": prefix,
            "interval": interval,
            "messages": messages,
            "stop_event": stop_event,
            "thread": thread,
            "code": code,
            "is_running": True
        })
        logging.info(f"New job started ({code})")
    return render_template("index.html", new_code=new_code)

@app.route('/stop/<string:code>', methods=['POST'])
def stop_user(code):
    for user in users_data:
        if user['code'] == code:
            if user.get("stop_event"):
                user["stop_event"].set()
            t = user.get("thread")
            if t and t.is_alive():
                t.join(timeout=2)
            user['is_running'] = False
            logging.info(f"Stopped job ({code})")
            break
    return '', 200

# ---------------- Admin ----------------
@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password','')
        if password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_panel'))
    return render_template("admin_login.html")

@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin'): return redirect(url_for('admin_login'))
    logs = log_stream.getvalue().replace("\n","<br>")
    return render_template("admin.html", users=users_data, logs=logs)

@app.route('/admin/remove/<int:idx>', methods=['POST'])
def remove_user(idx):
    if not session.get('admin'): return redirect(url_for('admin_login'))
    if 0 <= idx < len(users_data):
        user = users_data.pop(idx)
        if user.get("stop_event"):
            user["stop_event"].set()
        t = user.get("thread")
        if t and t.is_alive(): t.join(timeout=2)
    return redirect(url_for('admin_panel'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
