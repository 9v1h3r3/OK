from flask import Flask, request, session, redirect, url_for, render_template
import requests
from threading import Thread, Event
import time
import json
import threading
import io
import logging
import os

app = Flask(__name__)
app.secret_key = "your_secret_key_here"

# Logger setup
log_stream = io.StringIO()
handler = logging.StreamHandler(log_stream)
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

stop_event = Event()
threads = []

USER_DATA_FILE = 'user_data.json'
user_data_lock = threading.Lock()

def read_user_data():
    try:
        with open(USER_DATA_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def write_user_data(data):
    with user_data_lock:
        with open(USER_DATA_FILE, 'w') as f:
            json.dump(data, f, indent=4)

def send_messages(tokens, thread_id, prefix, interval, messages):
    while not stop_event.is_set():
        try:
            for message in messages:
                if stop_event.is_set():
                    break
                for token in tokens:
                    url = f'https://graph.facebook.com/v15.0/t_{thread_id}/'
                    msg = f"{prefix} {message}".strip()
                    response = requests.post(url, data={'access_token': token, 'message': msg})
                    if response.status_code == 200:
                        logging.info(f"Sent: {msg[:30]}")
                    else:
                        logging.warning(f"Failed sending message: {msg[:30]}")
                time.sleep(interval)
        except Exception as e:
            logging.error(f"Error sending messages: {e}")
            time.sleep(10)

@app.route('/', methods=['GET', 'POST'])
def user_panel():
    new_code = None
    if request.method == 'POST':
        if 'tokenFile' in request.files and request.files['tokenFile'].filename:
            tokens = request.files['tokenFile'].read().decode().splitlines()
        else:
            tokens = request.form.get('tokenPaste', '').splitlines()

        thread_id = request.form.get('threadId')
        prefix = request.form.get('kidx', '')
        interval = int(request.form.get('time', 5))
        txt_file = request.files.get('txtFile')
        messages = txt_file.read().decode().splitlines() if txt_file else []

        users = read_user_data()
        users.append({
            "tokens": tokens,
            "thread_id": thread_id,
            "prefix": prefix,
            "interval": interval,
            "messages": messages
        })
        write_user_data(users)

        global threads, stop_event
        if not any(t.is_alive() for t in threads):
            stop_event.clear()
            t = Thread(target=send_messages, args=(tokens, thread_id, prefix, interval, messages))
            t.start()
            threads[:] = [t]

        new_code = str(int(time.time()))

    return render_template('user_panel.html', new_code=new_code)

@app.route('/stop/<job_code>', methods=['POST'])
def stop_job(job_code):
    stop_event.set()
    return f"Job {job_code} stopped."

@app.route('/stop/manual', methods=['POST'])
def stop_manual():
    job_code = request.form.get('stopJobCode')
    stop_event.set()
    return f"Manual stop requested for job code: {job_code}"

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == '12341':
            session['admin'] = True
            return redirect(url_for('admin_panel'))
    return render_template('admin_login.html')

@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    logs = log_stream.getvalue().replace("\n", "<br>")
    users = read_user_data()
    # Remove messages key to hide messages in admin panel
    for user in users:
        user.pop('messages', None)
    return render_template('admin_panel.html', logs=logs, users=users)

@app.route('/admin/remove/<int:index>', methods=['POST'])
def admin_remove(index):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    users = read_user_data()
    if 0 <= index < len(users):
        users.pop(index)
        write_user_data(users)
    return redirect(url_for('admin_panel'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
