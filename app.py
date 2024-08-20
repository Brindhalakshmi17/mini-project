from flask import Flask,jsonify, render_template, request, redirect, url_for, session
import pyrebase
import re
import urllib
from functools import wraps
import firebase_admin
from firebase_admin import credentials,db

app = Flask(__name__)
app.secret_key = "YourSecretKey"

# Initialize Firebase
firebaseConfig = {
  #paste here 1
}
firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
database = firebase.database()

cred = credentials.Certificate("firebase_Key.json")
firebase_admin.initialize_app(cred, {
    #paste here 2
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

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        register_number = request.form['register_number']
        phone_number = request.form['phone_number']
        
        
        if not is_valid_email(email):
            return "Please use your SRMIST email for sign Up"
        
        try:
            encoded = urllib.parse.quote(email, safe="")
            
            users = database.child('users').get()
            if users.each():
                for user in users.each():
                    user_data = user.val()
                    if user_data.get('email') == email:
                        return "This email is already signed up. Please go back to the login page."
            
        except Exception as e:
            return str(e)      
        
        try:
            user = auth.create_user_with_email_and_password(email, password)
            uid = user['localId']

            user_data = {
                'name': name,
                'register_number': register_number,
                'phone_number': phone_number,
                'email': email,
            }
            database.child('users').child(uid).set(user_data)

            return redirect(url_for('login'))
        except Exception as e:
            return render_template('signup.html', error=str(e))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            user = auth.sign_in_with_email_and_password(email, password)
            session['user'] = {
                'idToken': user['idToken'],
                'email': email
            }
            admins = ['bs1329@srmist.edu.in']
            if email in admins:
                return render_template('admin.html')
            else:
                return redirect(url_for('dashboard'))
        except Exception as e:
            return render_template('login.html', error=str(e))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
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
