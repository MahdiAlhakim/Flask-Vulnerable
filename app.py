from flask import Flask, request, render_template, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cme_offshore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def add_admin_user():
    with app.app_context():
        db.create_all()
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', email='admin@example.com')
            admin_user.set_password("password123")
            db.session.add(admin_user)
            db.session.commit()

add_admin_user()

@app.route('/')
def index():
    return render_template('index.html')

stored_password_hash = "pbkdf2:sha256:600000$DdJnw28tsMUOK8ju$44a1baa1fcdee90f557f5bf60eacb715a339a112cf3bf524c48a16d2f871a4e5"  # Replace with your generated hash


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and check_password_hash(stored_password_hash, password):
            session['logged_in'] = True
            session['username'] = 'admin'
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/privacy')
def privacy():
    return "You have found the secret page!"

@app.route('/user/<username>')
def user_profile(username):
    # Vulnerable SQL query for demonstration
    query = text(f"SELECT * FROM user WHERE username = '{username}'")
    with db.engine.connect() as connection:
        user = connection.execute(query).fetchone()
    return render_template('profile.html', user=user)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = []
    return render_template('search.html', query=query, results=results)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            try:
                result = subprocess.run(
                    ['python', file_path], 
                    capture_output=True,
                    text=True,
                    timeout=5 
                )
                output = result.stdout
                if result.returncode != 0:
                    output += f"\nError: {result.stderr}"
            except subprocess.TimeoutExpired:
                output = "Execution timed out."
            except Exception as e:
                output = f"Error: {str(e)}"

            return f"File uploaded and executed. Output:\n{output}"
    return render_template('upload.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return f"File {filename} uploaded successfully!"

@app.route('/comments', methods=['GET', 'POST'])
def comments():
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            comment = Comment(content=content)
            db.session.add(comment)
            db.session.commit()
    comments = Comment.query.all()
    return render_template('comments.html', comments=comments)

@app.route('/backup')
def backup():
    return send_from_directory(app.config['UPLOAD_FOLDER'], 'backup.sql')

@app.route('/admin')
def admin_panel():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    return render_template('admin.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
