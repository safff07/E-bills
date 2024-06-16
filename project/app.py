from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
import mysql.connector

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Database configurations
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # Default password for XAMPP is empty
    'database': 'mydatabase'  # Name of your database
}

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        flash(f"Database connection failed: {err}", "error")
        return None

app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phoneno = request.form['phoneno']
        password = request.form['password']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        if conn is None:
            return render_template('signup.html')
        
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (name, email, phoneno, password) VALUES (%s, %s, %s, %s)", 
                           (name, email, phoneno, hashed_password))
            conn.commit()
            flash('You have successfully signed up! Please log in.', 'success')
        except mysql.connector.Error as err:
            flash(f'Error: {err}', 'error')
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        if conn is None:
            return render_template('login.html')
        
        cursor = conn.cursor()
        cursor.execute("SELECT name, email, phoneno, password FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.fetchall()  # Clear the unread results
        cursor.close()

        if user and bcrypt.check_password_hash(user[3], password):
            session['user_name'] = user[0]
            session['user_email'] = user[1]
            return redirect(url_for('dashboard'))  # Redirect to user dashboard
        else:
            flash('Invalid email or password', 'error')

        conn.close()

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_name' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))
    return render_template('dashboard.html', user_name=session['user_name'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
