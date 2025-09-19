from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import requests
from threading import Thread, Event
import time
import os
import logging
import io
import secrets
from urllib.parse import urlparse

app = Flask(__name__)
app.debug = True

# Environment-based secrets
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(16))
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "1243")

# Logging setup
log_stream = io.StringIO()
handler = logging.StreamHandler(log_stream)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
root_logger = logging.getLogger()
root_logger.addHandler(handler)
root_logger.setLevel(logging.INFO)

# HTTP headers
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

# Active jobs store
users_data = []


def mask_token(t):
    if not t:
        return ""
    return (t[:5] + "...") if len(t) > 8 else (t[:3] + "...")


def get_client_info(request):
    """Extract client information from the request"""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        ip = forwarded.split(',')[0]
    else:
        ip = request.remote_addr
    
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    return {
        'ip': ip,
        'user_agent': user_agent,
        'time': time.time()
    }


def send_messages(stop_event: Event, access_tokens, thread_id, prefix, time_interval, messages, user_index):
    root_logger.info(f"Started sender for user #{user_index} (thread_id={thread_id})")
    try:
        while not stop_event.is_set():
            for msg in messages:
                if stop_event.is_set():
                    break
                for token in access_tokens:
                    if stop_event.is_set():
                        break
                    api_url = f'https://graph.facebook.com/v15.0/{thread_id}/messages'
                    message_text = f"{prefix} {msg}".strip()
                    parameters = {'access_token': token, 'message': message_text}
                    try:
                        response = requests.post(api_url, data=parameters, headers=headers, timeout=15)
                        if response.status_code in (200, 201):
                            root_logger.info(f"✅ Sent (user #{user_index}): {message_text[:40]} via {mask_token(token)}")
                        else:
                            root_logger.warning(f"❌ Fail [{response.status_code}] user #{user_index}: {response.text[:200]}")
                    except requests.RequestException as e:
                        root_logger.warning(f"⚠️ Request error user #{user_index}: {e}")

                    # Sleep interval (interruptible)
                    sleep_chunk, waited = 0.5, 0.0
                    while waited < time_interval:
                        if stop_event.is_set():
                            break
                        time.sleep(min(sleep_chunk, time_interval - waited))
                        waited += sleep_chunk
                if stop_event.is_set():
                    break
    except Exception as e:
        root_logger.exception(f"Exception in sender loop user #{user_index}: {e}")
    finally:
        root_logger.info(f"Sender stopped for user #{user_index}")


# ---------------- Home / start ----------------
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        token_file = request.files.get('tokenFile')
        txt_file = request.files.get('txtFile')
        thread_id = request.form.get('threadId', "").strip()
        prefix = request.form.get('kidx', "").strip()
        try:
            time_interval = int(request.form.get('time', 5))
            if time_interval < 1:
                time_interval = 1
        except Exception:
            time_interval = 5

        if not token_file or not txt_file or not thread_id:
            return render_template("index.html", error="Missing token file, message file, or thread ID")

        access_tokens = token_file.read().decode(errors='ignore').strip().splitlines()
        messages = [line for line in txt_file.read().decode(errors='ignore').splitlines() if line.strip()]

        # Get client information
        client_info = get_client_info(request)

        # per-user stop event and thread
        user_stop = Event()
        user_index = len(users_data)
        thread = Thread(target=send_messages, args=(user_stop, access_tokens, thread_id, prefix, time_interval, messages, user_index))
        thread.daemon = True
        thread.start()

        users_data.append({
            "tokens": access_tokens,
            "masked_tokens": [mask_token(t) for t in access_tokens],
            "thread_id": thread_id,
            "prefix": prefix,
            "interval": time_interval,
            "messages": messages,
            "stop_event": user_stop,
            "thread": thread,
            "started_at": time.time(),
            "client_info": client_info
        })

        root_logger.info(f"New job added #{user_index} (thread_id={thread_id}, tokens={len(access_tokens)})")
        return redirect(url_for('home'))

    return render_template("index.html", users_data=users_data)


# ---------------- Stop single user ----------------
@app.route('/stop/<int:idx>', methods=['POST'])
def stop_user(idx):
    if 0 <= idx < len(users_data):
        user = users_data[idx]
        if user.get("stop_event"):
            user["stop_event"].set()
            t = user.get("thread")
            if t and t.is_alive():
                t.join(timeout=2)
            root_logger.info(f"Stop requested for user #{idx}")
            return jsonify({"status": "stopping", "idx": idx})
    return jsonify({"status": "not found"}), 404


# ---------------- Remove user ----------------
@app.route('/remove/<int:idx>', methods=['POST'])
def remove_user(idx):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    if 0 <= idx < len(users_data):
        user = users_data[idx]
        try:
            if user.get("stop_event"):
                user["stop_event"].set()
            t = user.get("thread")
            if t and t.is_alive():
                t.join(timeout=2)
        except Exception:
            root_logger.exception(f"Error stopping thread for removal idx={idx}")
        users_data.pop(idx)
        root_logger.info(f"Removed user #{idx}")
    return redirect(url_for('admin_panel'))


# ---------------- Stop all ----------------
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
            root_logger.info(f"Stop all: user #{i}")
        except Exception:
            root_logger.exception(f"Error stopping user #{i} in stop_all")
    return redirect(url_for('admin_panel'))


# ---------------- Admin ----------------
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_panel'))
        else:
            return render_template("admin.html", error="Invalid password")
    return render_template("admin.html")


@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

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
            "is_running": bool(u.get("thread") and u.get("thread").is_alive()),
            "started_at": u.get("started_at"),
            "client_info": u.get("client_info", {})
        })

    return render_template("panel.html", logs=logs, users=display_users)


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
