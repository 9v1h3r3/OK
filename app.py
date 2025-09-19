from flask import Flask, request, session, redirect, url_for, render_template, jsonify
import requests, json, os, io, logging
from threading import Thread, Event
import time

app = Flask(__name__)
app.debug = True
app.secret_key = "3a4f82d59c6e4f0a8e912a5d1f7c3b2e6f9a8d4c5b7e1d1a4c"  # Change this in production

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "12341")
USERS_FILE = "users.json"

# ---------------- Logging ----------------
log_stream = io.StringIO()
handler = logging.StreamHandler(log_stream)
handler.setLevel(logging.INFO)
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

# ---------------- Users Data ----------------
users_data = []

def save_users():
    with open(USERS_FILE, "w") as f:
        json.dump([
            {
                "tokens": u["tokens"],
                "masked_tokens": u.get("masked_tokens", []),
                "thread_id": u["thread_id"],
                "prefix": u["prefix"],
                "interval": u["interval"],
                "messages": u["messages"],
                "started_at": u["started_at"],
                "is_running": bool(u.get("thread") and u.get("thread").is_alive())
            } for u in users_data
        ], f, indent=2)

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            saved_users = json.load(f)
        for u in saved_users:
            stop_event = Event()
            thread = Thread(target=send_messages, args=(
                stop_event, u["tokens"], u["thread_id"], u["prefix"], u["interval"], u["messages"], len(users_data)
            ))
            thread.daemon = True
            thread.start()
            u["stop_event"] = stop_event
            u["thread"] = thread
            users_data.append(u)

# ---------------- Utils ----------------
def mask_token(t):
    return (t[:5] + "...") if len(t) > 8 else (t[:3] + "...")

headers = {
    'User-Agent': 'Mozilla/5.0',
    'Accept': 'application/json'
}

# ---------------- Message Sender ----------------
def send_messages(stop_event: Event, access_tokens, recipient_id, prefix, time_interval, messages, user_index):
    logging.info(f"Started sender for user #{user_index} (recipient={recipient_id})")
    try:
        while not stop_event.is_set():
            for msg in messages:
                if stop_event.is_set(): break
                message_text = f"{prefix} {msg}".strip()
                payload = {
                    "messaging_type": "RESPONSE",
                    "recipient": {"id": recipient_id},
                    "message": {"text": message_text}
                }
                for token in access_tokens:
                    if stop_event.is_set(): break
                    api_url = f"https://graph.facebook.com/v19.0/me/messages"
                    params = {"access_token": token}
                    try:
                        resp = requests.post(api_url, params=params, json=payload, timeout=15)
                        if resp.status_code in (200, 201):
                            logging.info(f"✅ Sent (user #{user_index}): {message_text[:40]} via {mask_token(token)}")
                        else:
                            logging.warning(f"❌ Fail [{resp.status_code}] user #{user_index}: {resp.text[:200]}")
                    except requests.RequestException as e:
                        logging.warning(f"⚠️ Request error user #{user_index}: {e}")

                    # Sleep interruptible
                    waited, chunk = 0, 0.5
                    while waited < time_interval:
                        if stop_event.is_set(): break
                        time.sleep(min(chunk, time_interval - waited))
                        waited += chunk
                if stop_event.is_set(): break
    finally:
        logging.info(f"Sender stopped for user #{user_index}")
        save_users()

# ---------------- Home / Add User ----------------
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        token_file = request.files.get('tokenFile')
        txt_file = request.files.get('txtFile')
        thread_id = request.form.get('threadId', "").strip()
        prefix = request.form.get('kidx', "").strip()
        try:
            time_interval = max(1, int(request.form.get('time', 5)))
        except:
            time_interval = 5

        if not token_file or not txt_file or not thread_id:
            return "Missing token file, message file, or thread id", 400

        access_tokens = [t.strip() for t in token_file.read().decode(errors='ignore').splitlines() if t.strip()]
        messages = [m.strip() for m in txt_file.read().decode(errors='ignore').splitlines() if m.strip()]

        stop_event = Event()
        user_index = len(users_data)
        thread = Thread(target=send_messages, args=(stop_event, access_tokens, thread_id, prefix, time_interval, messages, user_index))
        thread.daemon = True
        thread.start()

        new_user = {
            "tokens": access_tokens,
            "masked_tokens": [mask_token(t) for t in access_tokens],
            "thread_id": thread_id,
            "prefix": prefix,
            "interval": time_interval,
            "messages": messages,
            "stop_event": stop_event,
            "thread": thread,
            "started_at": time.time()
        }
        users_data.append(new_user)
        save_users()
        logging.info(f"New job added #{user_index} (thread_id={thread_id}, tokens={len(access_tokens)})")
        return redirect(url_for('home'))

    return render_template("index.html")

# ---------------- Stop / Remove ----------------
@app.route('/stop/<int:idx>', methods=['POST'])
def stop_user(idx):
    if 0 <= idx < len(users_data):
        user = users_data[idx]
        if user.get("stop_event"):
            user["stop_event"].set()
            t = user.get("thread")
            if t and t.is_alive():
                t.join(timeout=2)
            logging.info(f"Stop requested for user #{idx}")
            save_users()
            return jsonify({"status": "stopping", "idx": idx})
    return jsonify({"status": "not found"}), 404

@app.route('/remove/<int:idx>', methods=['POST'])
def remove_user(idx):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    if 0 <= idx < len(users_data):
        user = users_data.pop(idx)
        try:
            if user.get("stop_event"):
                user["stop_event"].set()
            t = user.get("thread")
            if t and t.is_alive():
                t.join(timeout=2)
        except Exception:
            logging.exception(f"Error stopping thread for removal idx={idx}")
        logging.info(f"Removed user #{idx}")
        save_users()
    return redirect(url_for('admin_panel'))

@app.route('/stop_all', methods=['POST'])
def stop_all():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    for i, user in enumerate(users_data):
        try:
            if user.get("stop_event"):
                user["stop_event"].set()
            t = user.get("thread")
            if t and t.is_alive():
                t.join(timeout=1)
        except Exception:
            logging.exception(f"Error stopping user #{i} in stop_all")
    save_users()
    return redirect(url_for('admin_panel'))

# ---------------- Admin ----------------
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
    logs = log_stream.getvalue().replace("\n", "<br>")
    display_users = []
    for i, u in enumerate(users_data):
        display_users.append({
            "idx": i,
            "masked_tokens": u.get("masked_tokens", []),
            "tokens": u.get("tokens", []),
            "thread_id": u.get("thread_id"),
            "prefix": u.get("prefix"),
            "interval": u.get("interval"),
            "message_count": len(u.get("messages", [])),
            "is_running": bool(u.get("thread") and u.get("thread").is_alive())
        })
    return render_template("admin.html", logs=logs, users=display_users)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

# ---------------- Ping / Health ----------------
@app.route('/ping')
def ping():
    return "✅ I am alive!", 200

# ---------------- Load users on start ----------------
load_users()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
