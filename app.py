from flask import Flask,jsonify, render_template, request, redirect, url_for, session
import pyrebase
import re
import requests
import urllib.parse
from functools import wraps
import firebase_admin
from firebase_admin import credentials,db

app = Flask(__name__)
app.secret_key = "YourSecretKey"

# Initialize Firebase
firebaseConfig = {
  "apiKey": "AIzaSyDFJxeQnDGv7jS9zrwslQ3h2vvNbEB-5bI",
  "authDomain": "activityplus-b900e.firebaseapp.com",
  "databaseURL": "https://activityplus-b900e-default-rtdb.firebaseio.com",
  "projectId": "activityplus-b900e",
  "storageBucket": "activityplus-b900e.appspot.com",
  "messagingSenderId": "974798997443",
  "appId": "1:974798997443:web:51bb2a2d85b0e294d31f76",
  "measurementId": "G-L3WGTS278B",
  "databaseURL":"https://activityplus-b900e-default-rtdb.firebaseio.com/"
}
firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
database = firebase.database()

cred = credentials.Certificate("firebase_Key.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://userdb-172001-default-rtdb.firebaseio.com/'
})

# Email validation function
def is_valid_email(email):
    # Use regular expression to validate email format
    return re.match(r"[^@]+@srmist\.edu\.in", email)

# Admin check decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        user = session['user']
        email = user['email']
        admins = ['bs1329@srmist.edu.in']  # List of admin emails
        if email not in admins:
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_users():
    return render_template('admin.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if not is_valid_email(email):
            return "Please use your SRMIST email for sign Up"
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            # session['user'] = {
            #     'idToken': user['idToken'],
            #     'email': email
            # }
            admins = ['bs1329@srmist.edu.in']
            ref = db.reference('users/' + user.uid)
            user_data = ref.get()
            if user_data['email_id'] == email and user_data['password'] == password:
                if email in admins:
                    return render_template('admin.html')
                return redirect(url_for('dashboard', uid=user.uid))
            else:
                return jsonify({"error": "Invalid email or password"}), 401
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return render_template('login.html')

@app.route('/dashboard')
def dashboard(uid):
    if 'user' in session:
        user = session['user']
        return render_template('dashboard.html', user=user)
    else:
        return redirect(url_for('login'))

@app.route('/logout', methods=["POST", "GET"])
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
