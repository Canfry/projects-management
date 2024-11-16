from flask import Flask, render_template, request, redirect, flash, session
from datetime import datetime
from flask_session import Session
import validators
import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash
from utils import login_required

from dotenv import load_dotenv

from config import config

# Initialize the Flask application
app = Flask(__name__)
config(app)

Session(app)


# Set up database
connection = sqlite3.connect("projects.db", check_same_thread=False)
cursor = connection.cursor()

# Set up variables
now = datetime.now()
year = now.year

load_dotenv()


# Create tables
cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, username TEXT NOT NULL, email TEXT NOT NULL, hash TEXT NOT NULL, is_admin TEXT NOT NULL, comment_id INTEGER, post_id INTEGER, project_id INTEGER, FOREIGN KEY(comment_id) REFERENCES comments(id), FOREIGN KEY(post_id) REFERENCES posts(id), FOREIGN KEY(project_id) REFERENCES projects(id))")

cursor.execute("CREATE TABLE IF NOT EXISTS projects (id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, user_id INTEGER, comment_id INTEGER, post_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(comment_id) REFERENCES comments(id), FOREIGN KEY(post_id) REFERENCES posts(id))")

cursor.execute("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, text TEXT, user_id INTEGER, project_id INTEGER, post_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(project_id) REFERENCES projects(id), FOREIGN KEY(post_id) REFERENCES posts(id))")

cursor.execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, body TEXT, user_id INTEGER, project_id INTEGER, comment_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(project_id) REFERENCES projects(id), FOREIGN KEY(comment_id) REFERENCES comments(id))")


# Context processors
@app.context_processor
def inject_year():
    return {'year': year}


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not validators.email(request.form.get('email')):
            flash('Please enter a valid email address')
            return redirect('/login')
        elif len(request.form.get('password')) < 6:
            flash('Password must be at least 6 characters')
            return redirect('/login')

        # Query the database
        email = request.form.get('email')
        password = request.form.get('password')
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if user is None or not check_password_hash(user[4], password):
            flash('Invalid email and/or password')
            return redirect('/login')

        session['user_id'] = user[0]
        session['username'] = user[2]
        session['admin'] = user[5]

        return redirect('/dashboard')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not validators.email(request.form.get('email')):
            flash('Please enter a valid email address')
            return redirect('/register')
        elif len(request.form.get('password')) < 6:
            flash('Password must be at least 6 characters')
            return redirect('/register')

        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        admin = request.form.get('admin')

        cursor.execute("INSERT INTO users (name, username, email, hash, is_admin) VALUES (?, ?, ?, ?, ?)",
                       (name, username, email, hashed_password, admin))
        connection.commit()

        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        session['user_id'] = user[0]
        session['username'] = user[2]
        session['admin'] = user[5]

        flash('Account created successfully')

        return redirect('/dashboard')

    return render_template('register.html')


@app.route('/dashboard')
@login_required
def dashboard():
    cursor.execute(
        "SELECT users.name, users.is_admin, projects.name, projects.id FROM users JOIN projects ON users.id = projects.user_id")
    admin_projects = cursor.fetchall()
    print(admin_projects)

    cursor.execute(
        "SELECT users.name, users.is_admin, projects.name, projects.id FROM users JOIN projects ON users.id = projects.user_id WHERE users.id = ?", (session['user_id'],))
    user_projects = cursor.fetchall()
    print(user_projects)

    cursor.execute("SELECT is_admin FROM users WHERE id = ?",
                   (session['user_id'],))
    admin = cursor.fetchone()
    print(admin)

    return render_template('dashboard.html', admin_projects=admin_projects, user_projects=user_projects, admin=admin)


@app.route('/create_project', methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        name = request.form.get('title')
        description = request.form.get('description')

        user_id = request.form.get('user_id')
        # cursor.execute("SELECT id FROM users WHERE name = ?", (user,))
        # user_id = cursor.fetchone()
        # print(user_id)

        cursor.execute("INSERT INTO projects (name, description, user_id) VALUES (?, ?, ?)",
                       (name, description, user_id))
        connection.commit()

        flash('Project created successfully')
        return redirect('/dashboard')

    cursor.execute("SELECT name, id, is_admin FROM users")
    users = cursor.fetchall()
    print(users)
    return render_template('create_project.html', users=users)


@app.route('/delete_project/<int:project_id>')
@login_required
def delete_project(project_id):
    cursor.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    connection.commit()

    flash('Project deleted successfully')
    return redirect('/dashboard')


@app.route('/project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def project(project_id):
    if request.method == 'POST':
        post = request.form.get('post')
        user_id = session['user_id']

        cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
        project = cursor.fetchone()
        print(project)

        cursor.execute("INSERT INTO posts (body, user_id, project_id) VALUES (?, ?, ?)",
                       (post, user_id, project_id))
        connection.commit()
        return redirect(f'/project/{project_id}')

    admin = session['admin']
    print(admin)

    cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project = cursor.fetchone()
    print(project)

    cursor.execute(
        "SELECT * FROM comments WHERE project_id = ?", (project_id,))
    comments = cursor.fetchall()
    print(comments)

    cursor.execute("SELECT * FROM posts WHERE project_id = ?", (project_id,))
    posts = cursor.fetchall()
    print(posts)

    return render_template('project.html', project=project, posts=posts, admin=admin, comments=comments)


@app.route('/comment', methods=['POST'])
@login_required
def comment():
    text = request.form.get('comment')
    user_id = session['user_id']
    project_id = request.form.get('project_id')
    print(project_id)

    cursor.execute("INSERT INTO comments (text, user_id, project_id) VALUES (?, ?, ?)",
                   (text, user_id, project_id))
    connection.commit()

    return redirect(f'/project/{project_id}')


if __name__ == '__main__':
    app.run()
