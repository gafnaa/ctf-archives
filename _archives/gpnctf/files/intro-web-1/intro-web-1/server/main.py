import base64
import hashlib
import os
import pickle
import random
import re
from functools import wraps
from uuid import uuid4
import requests
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, session, flash, g, abort


BOT_SERVICE_URL = os.environ.get('BOT_SERVICE_URL', 'http://localhost:3000')
CHALLENGE_SERVICE_URL = os.environ.get('CHALLENGE_SERVICE_URL', 'http://localhost:9222')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH')

FLAG_STAGE_1 = os.environ.get("FLAG_STAGE_1")
FLAG_STAGE_4 = os.environ.get("FLAG_STAGE_4")
FLAG_STAGE_5 = os.environ.get("FLAG_STAGE_5")

load_dotenv()


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_APP_SECRET_KEY")

app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
SHOW_DEVELOPMENT_ROUTES = False

notes = {}
reported_notes = {}


def read_file(path):
    # Prevent reading files outside the allowed directory (.img/).
    if not re.search(r'^\.\w+.*$', str(os.path.relpath(path))):
        return ""

    try:
        with open(path, 'rb') as f:
            content = f.read()
            base64_content = base64.b64encode(content).decode('utf-8')
            return base64_content
    except Exception:
        return ""


app.jinja_env.filters['read_file'] = read_file


def is_mod():
    return g.user.get('role') in ['admin', 'moderator']


@app.context_processor
def inject_user():
    return dict(current_user=session.get('user', {}).get('username'))


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.endpoint))
        else:
            g.user = session['user']
        return f(*args, **kwargs)

    return decorated

def moderator_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_mod():
            return 'Unauthorized - You must be a moderator or admin to access this page', 403
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # I only trust my self to know the admin password :)
        if not hashlib.sha512(request.cookies.get('ADMIN_PASSWORD').encode()).hexdigest() == ADMIN_PASSWORD_HASH:
            return 'Unauthorized - You must be a admin to access this page', 403
        return f(*args, **kwargs)

    return decorated


def development_routes_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not SHOW_DEVELOPMENT_ROUTES:
            return 'Development routes are not enabled', 403
        return f(*args, **kwargs)

    return decorated


@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username:
            flash('Please provide a username', 'danger')
            return render_template('login.html')

        session['user'] = {
            'username': username,
            'role': 'admin' if hashlib.sha512(password.encode()).hexdigest() == ADMIN_PASSWORD_HASH else 'user'
        }

        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    if is_mod():
        return redirect(url_for('moderator'))

    user_notes = [(nid, notes[nid]['title'], notes[nid]['content']) for nid in notes if notes[nid]['owner'] == g.user]
    return render_template('dashboard.html', user_notes=user_notes)


@app.route('/moderator')
@login_required
@moderator_required
def moderator():
    user_notes = [(nid, notes[nid]['title'], notes[nid]['content']) for nid in notes]
    return render_template('dashboard.html', user_notes=user_notes)


@app.route('/note/new', methods=['GET', 'POST'])
@login_required
def new_note():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        image_path = request.form['image_path']

        note_id = str(uuid4())
        notes[note_id] = {'owner': g.user, 'title': title, 'content': content, 'image_path': image_path}

        flash('Note created', 'success')
        return redirect(url_for('view_note', note_id=note_id))

    return render_template('note_form.html',
                           image_path=random.choice(['.img/1.png', '.img/2.png', '.img/3.png']),)


@app.route('/note/<note_id>')
@login_required
def view_note(note_id):
    if note_id not in notes:
        abort(404)

    user_notes = [(nid, notes[nid]['title']) for nid in notes if notes[nid]['owner'] == g.user]
    return render_template('view_note.html', note=notes[note_id], note_id=note_id, user_notes=user_notes, is_mod=(is_mod()))


@app.route('/report/<note_id>', methods=['GET', 'POST'])
@login_required
@moderator_required
def report_note(note_id):
    if note_id not in notes:
        abort(404)

    if request.method == 'POST':
        reason = request.form['reason']
        reported_notes[note_id] = {'reason': reason, 'reported_by': g.user.get('username'), **notes.get(note_id, {})}

        try:
            response = requests.post(f'{BOT_SERVICE_URL}/bot',
                                     json={'url': CHALLENGE_SERVICE_URL + url_for('report_note', note_id=note_id)})
            return response.text, response.status_code
        except requests.exceptions.RequestException as e:
            return f'Error contacting admin: {e}', 500

    if note_id not in reported_notes:
        redirect(url_for('view_note', note_id=note_id))

    return render_template('report_note.html', note=reported_notes[note_id])


@app.route('/settings', methods=['POST'])
@login_required
@admin_required
def settings():
    show_dev_routes = request.json.get('show_development_routes', False)

    global SHOW_DEVELOPMENT_ROUTES
    SHOW_DEVELOPMENT_ROUTES = show_dev_routes

    flash('Settings updated', 'success')
    return "Settings updated", 200

@app.route('/development', methods=['GET'])
@login_required
@moderator_required
@development_routes_required
def development():
    return FLAG_STAGE_4, 200


@app.route('/development/cookie-sign', methods=['POST'])
@login_required
@moderator_required
@development_routes_required
def sign_cookie():
    """
    Development route to learn how signing cookies works.
    """
    value = request.data.decode('utf-8')
    secret_key = app.secret_key.encode()
    signature = hashlib.sha256((value + secret_key.decode()).encode()).hexdigest()

    data = pickle.dumps({
        'value': value,
        'signature': signature,
    }, 0)

    return {'cookie': f"{base64.b64encode(data).decode("utf-8")}"}, 200


@app.route('/development/cookie-verify', methods=['POST'])
@login_required
@moderator_required
@development_routes_required
def verify_cookie():
    """
    Development route to validat the signature of the cookie is valid.
    """
    data = request.json.get('cookie')
    try:
        data = pickle.loads(base64.b64decode(data))
    except Exception as e:
        return "Invalid data :/", 400

    value = data.get('value')
    signature = data.get('signature')

    if not value or not signature:
        return "Missing signature or value", 400

    secret_key = app.secret_key.encode()
    expected_signature = hashlib.sha256((value + secret_key.decode()).encode()).hexdigest()

    if expected_signature != signature:
        return "Invalid signature", 400

    return "Valid Cookie!", 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9222)
