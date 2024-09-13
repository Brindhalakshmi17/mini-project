from flask import Flask, render_template, request, redirect, url_for, session,flash
import pyrebase
import re
import urllib
from functools import wraps
import firebase_admin
from firebase_admin import credentials, db

app = Flask(__name__)
app.secret_key = "YourSecretKey"

# Initialize Firebase
firebaseConfig = {
    # Paste credentials
}
firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
database = firebase.database()

cred = credentials.Certificate("firebase_Key.json")
firebase_admin.initialize_app(cred, {
    # Paste credentials
})

# Email validation function
def is_valid_email(email):
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
        # Retrieve form data
        email = request.form['email']
        password = request.form['password']
        retype_password = request.form['retype_password']
        name = request.form['name']
        register_number = request.form['register_number']
        phone_number = request.form['phone_number']
        department = request.form['department']
        batch = request.form['batch']
        year_start = request.form['year_start']
        year_end = request.form['year_end']
        
        # Email validation
        if not is_valid_email(email):
            flash("Please use your SRMIST email for sign up.", "danger")
            return render_template('signup.html')

        # Password confirmation validation
        if password != retype_password:
            flash("Passwords do not match. Please try again.", "danger")
            return render_template('signup.html')

        # Year validation: ensure year_end is greater than year_start
        if int(year_end) < int(year_start):
            flash("Year of end must be greater than or equal to year of start.", "danger")
            return render_template('signup.html')

        try:
            # Check if the email is already registered in the Firebase Realtime Database
            encoded = urllib.parse.quote(email, safe="")
            users = database.child('users').get()
            if users.each():
                for user in users.each():
                    user_data = user.val()
                    if user_data.get('email') == email:
                        flash("This email is already signed up. Please go back to the login page.", "danger")
                        return render_template('signup.html')

        except Exception as e:
            return str(e)      

        try:
            # Create a new user in Firebase Authentication
            user = auth.create_user_with_email_and_password(email, password)
            uid = user['localId']

            # Prepare the user data to save in Firebase Realtime Database
            user_data = {
                'name': name,
                'register_number': register_number,
                'phone_number': phone_number,
                'email': email,
                'department': department,
                'batch': batch,
                'year_start': year_start,
                'year_end': year_end,
                'joined': '2024-01-01'  # Example joined date
            }

            # Save the user data in Firebase Realtime Database under the user's UID
            database.child('users').child(uid).set(user_data)

            # Redirect to login page upon successful signup
            flash("Signup successful! Please login.", "success")
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
                'localId': user['localId'],
                'email': email
            }
            admins = ['bs1329@srmist.edu.in']
            if email in admins:
                return redirect(url_for('admin_users'))
            else:
                return redirect(url_for('user_dashboard'))
        except Exception as e:
            return render_template('login.html', error=str(e))

    return render_template('login.html')

def get_user_data(user_id):
    ref = db.reference(f'users/{user_id}')
    user_snapshot = ref.get()
    if user_snapshot:
        return user_snapshot
    return None

@app.route('/dashboard', methods=['GET'])
def user_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user']['localId']
    user_data = get_user_data(user_id)
    if user_data:
        return render_template('dashboard.html', user=user_data)
    return "User not found", 404

@app.route('/logout', methods=["POST", "GET"])
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
