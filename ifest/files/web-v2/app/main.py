from flask import Flask, request, render_template, redirect, session, abort
from flask_sqlalchemy import SQLAlchemy
from urllib.parse import urlparse
import requests
import secrets
import bcrypt

app = Flask(__name__)
app.secret_key = secrets.token_hex(64)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ctf.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.String(1), default='1')

with app.app_context():
    db.create_all()

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(stored_password: str, provided_password: str) -> bool:
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')

    user = db.session.get(User, session['user_id'])
    if user.is_admin == '1':
        return render_template('index.html', admin=True, username=user.username)
    else:
        return render_template('index.html', admin=False, username=user.username)

@app.route('/admin/fetch', methods=['GET', 'POST'])
def admin_fetch():
    if 'user_id' not in session:
        return redirect('/login')

    user = db.session.get(User, session['user_id'])
    # is_admin check disabled for debugging

    result = None
    if request.method == 'POST':
        data = request.get_json()
        url = data.get('url')

        parsed_url = urlparse(url)
        print(f"Parsed URL: {parsed_url}")

        if parsed_url.hostname != 'daffainfo.com':
            result = "Error: Only URLs with hostname 'daffainfo.com' are allowed."
        else:
            try:
                resp = requests.get(url, timeout=5)
                result = resp.text
            except Exception as e:
                result = f"Error fetching URL: {str(e)}"

    return render_template('fetch.html', result=result)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        # Create a mutable copy of the data
        mutable_data = data.copy()
        mutable_data['password'] = hash_password(mutable_data['password'])

        user = User(**mutable_data)
        db.session.add(user)
        db.session.commit()

        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data['username']
        password = data['password']
        user = db.session.execute(
            db.select(User).filter_by(username=username)
        ).scalar_one_or_none()

        if user and check_password(user.password, password):
            session['user_id'] = user.id
            return redirect('/')
        else:
            return "Invalid credentials."
    return render_template('login.html')

@app.route('/internal')
def internal():
    if request.remote_addr != '127.0.0.1':
        abort(403)
    return "Flag: IFEST13{fake_flag}"

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=1337)
