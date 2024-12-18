from flask import Flask, render_template, request, redirect, url_for, session,flash
import pyrebase
import re
import urllib
from functools import wraps
import firebase_admin
from firebase_admin import credentials, db, storage
import os
import uuid
from werkzeug.utils import secure_filename
from dash import Dash, html, dcc
from dash.dependencies import Input, Output
import firebase_admin
from firebase_admin import credentials, db
import pandas as pd
import plotly.express as px
from sklearn.cluster import KMeans

app = Flask(__name__)
app.secret_key = "YourSecretKey"


# Initialize Firebase
firebaseConfig = {
   #paste 1
}
firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
database = firebase.database()

cred = credentials.Certificate("firebase_key.json")
firebase_admin.initialize_app(cred, {
  #paste 2
})
tutor_ref = db.reference('tutors')
@app.route('/tutor_dashboard')
def tutor_dashboard():
    # Check if the tutor is logged in
    if 'tutor_id' not in session:
        return redirect(url_for('login'))
    
    # Get the tutor's ID from the session
    tutor_id = session['tutor_id']

    # Fetch tutor details from the Realtime Database
    tutor = tutor_ref.child(tutor_id).get()
    
    if tutor:
        return render_template('tutor_dashboard.html', tutor=tutor)
    else:
        return "Tutor not found", 404

def fetch_and_process_data():
    users_ref = db.reference('users')
    users_data = users_ref.get()  # Retrieve all user data

    # Initialize lists to store flattened data
    users_list = []
    events_list = []
    courses_list = []
    sports_list = []
    webinars_list = []

    for user_id, user_info in users_data.items():
        user_basic_info = {
            "user_id": user_id,
            "name": user_info.get("name"),
            "email": user_info.get("email"),
            "department": user_info.get("department"),
            "batch": user_info.get("batch"),
            "year_start": user_info.get("year_start"),
            "year_end": user_info.get("year_end")
        }
        users_list.append(user_basic_info)

        # Parse nested events data
        events = user_info.get("events", {})
        for event_id, event_info in events.items():
            event_info.update({"user_id": user_id, "event_id": event_id})
            events_list.append(event_info)

        # Parse nested courses data
        courses = user_info.get("courses", {})
        for course_id, course_info in courses.items():
            course_info.update({"user_id": user_id, "course_id": course_id})
            courses_list.append(course_info)

        # Parse nested sports data
        sports = user_info.get("sports", {})
        for sport_id, sport_info in sports.items():
            sport_info.update({"user_id": user_id, "sport_id": sport_id})
            sports_list.append(sport_info)

        # Parse nested webinars/seminars data
        webinars = user_info.get("webinar_seminar", {})
        for webinar_id, webinar_info in webinars.items():
            webinar_info.update({"user_id": user_id, "webinar_id": webinar_id})
            webinars_list.append(webinar_info)

    # Convert lists to pandas DataFrames
    users_df = pd.DataFrame(users_list)
    events_df = pd.DataFrame(events_list)
    courses_df = pd.DataFrame(courses_list)
    sports_df = pd.DataFrame(sports_list)
    webinars_df = pd.DataFrame(webinars_list)

    return users_df, events_df, courses_df, sports_df, webinars_df

# Fetch and process data from Firebase
users_df, events_df, courses_df, sports_df, webinars_df = fetch_and_process_data()

# Feature engineering: Calculate engagement counts for each user
users_df['event_count'] = users_df['user_id'].map(events_df['user_id'].value_counts())
users_df['course_count'] = users_df['user_id'].map(courses_df['user_id'].value_counts())
users_df['sports_count'] = users_df['user_id'].map(sports_df['user_id'].value_counts())
users_df['webinar_count'] = users_df['user_id'].map(webinars_df['user_id'].value_counts())
users_df.fillna(0, inplace=True)  # Fill NaN values with 0

# Clustering: Create clusters based on engagement metrics
X = users_df[['event_count', 'course_count', 'sports_count', 'webinar_count']]
kmeans = KMeans(n_clusters=3, random_state=42)
users_df['cluster'] = kmeans.fit_predict(X)

# Create Dash app
dash_app = Dash(server=app, name="User Engagement Dashboard", url_base_pathname="/dashboard/")

# Layout of the Dash app
dash_app.layout = html.Div([
    html.H1("User Engagement Dashboard"),
    html.Label("Select Department:"),
    dcc.Dropdown(
        id='department-dropdown',
        options=[{'label': dept, 'value': dept} for dept in users_df['department'].unique()],
        multi=True,
        placeholder="Filter by department..."
    ),

    # Arrange graphs in a 2x2 grid
    html.Div([
        html.Div(dcc.Graph(id='department-pie-chart'), style={'display': 'inline-block', 'width': '48%'}),
        html.Div(dcc.Graph(id='year-participation-line-chart'), style={'display': 'inline-block', 'width': '48%'}),
    ], style={'display': 'flex', 'flex-wrap': 'wrap', 'justify-content': 'space-around'}),

    html.Div([
        html.Div(dcc.Graph(id='activity-bar-chart'), style={'display': 'inline-block', 'width': '48%'}),
        html.Div(dcc.Graph(id='average-engagement-cluster-chart'), style={'display': 'inline-block', 'width': '48%'}),
    ], style={'display': 'flex', 'flex-wrap': 'wrap', 'justify-content': 'space-around'})
])

# Callback to update pie chart based on department filter
@dash_app.callback(
    Output('department-pie-chart', 'figure'),
    Input('department-dropdown', 'value')
)
def update_pie_chart(selected_departments):
    filtered_df = users_df[users_df['department'].isin(selected_departments)] if selected_departments else users_df
    activity_counts = {
        "Events": filtered_df['event_count'].sum(),
        "Courses": filtered_df['course_count'].sum(),
        "Sports": filtered_df['sports_count'].sum(),
        "Webinars": filtered_df['webinar_count'].sum(),
    }
    fig = px.pie(names=list(activity_counts.keys()), values=list(activity_counts.values()),
                  title="Department-wise Activity Count")
    return fig

# Callback to update line chart for year-wise participation
@dash_app.callback(
    Output('year-participation-line-chart', 'figure'),
    Input('department-dropdown', 'value')
)
def update_line_chart(selected_departments):
    filtered_df = users_df[users_df['department'].isin(selected_departments)] if selected_departments else users_df
    year_participation = filtered_df.groupby(['year_start'])[['event_count', 'course_count', 'sports_count', 'webinar_count']].sum().reset_index()
    fig = px.line(year_participation, x='year_start', y=['event_count', 'course_count', 'sports_count', 'webinar_count'],
                  title="Year-wise Participation in Activities",
                  labels={'value': 'Count', 'year_start': 'Year'},
                  markers=True)
    return fig

# Callback to update bar chart for activity by type
@dash_app.callback(
    Output('activity-bar-chart', 'figure'),
    Input('department-dropdown', 'value')
)
def update_bar_chart(selected_departments):
    filtered_df = users_df[users_df['department'].isin(selected_departments)] if selected_departments else users_df
    activity_totals = {
        "Events": filtered_df['event_count'].sum(),
        "Courses": filtered_df['course_count'].sum(),
        "Sports": filtered_df['sports_count'].sum(),
        "Webinars": filtered_df['webinar_count'].sum(),
    }
    fig = px.bar(x=list(activity_totals.keys()), y=list(activity_totals.values()),
                  title="Total Activities Done by Type",
                  labels={'x': 'Activity Type', 'y': 'Total Count'})
    return fig

# Callback to update cluster engagement chart
@dash_app.callback(
    Output('average-engagement-cluster-chart', 'figure'),
    Input('department-dropdown', 'value')
)
def update_cluster_chart(selected_departments):
    filtered_df = users_df[users_df['department'].isin(selected_departments)] if selected_departments else users_df
    cluster_averages = filtered_df.groupby('cluster')[['event_count', 'course_count', 'sports_count', 'webinar_count']].mean().reset_index()
    fig = px.bar(cluster_averages, x='cluster', y=['event_count', 'course_count', 'sports_count', 'webinar_count'],
                  title="Average Engagement by Cluster",
                  labels={'value': 'Average Count', 'cluster': 'Cluster'},
                  barmode='group')
    return fig
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

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please login to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    # Fetch existing tutors
    tutors = tutor_ref.get()

    if request.method == 'POST':
        # Handle adding or editing a tutor
        tutor_id = request.form.get('tutor_id')  # For editing
        name = request.form['name']
        email = request.form['email']
        department = request.form['department']
        batch = request.form['batch']
        phone = request.form['phone']
        
        temporary_password = "SRM1234"
        if tutor_id:
            # Editing an existing tutor
            tutor_ref.child(tutor_id).update({
                'name': name,
                'email': email,
                'department': department,
                'batch': batch,
                'phone': phone
            })
        else:
            # Adding a new tutor
            new_tutor_ref = tutor_ref.push()
            new_tutor_ref.set({
                'name': name,
                'email': email,
                'department': department,
                'batch': batch,
                'phone': phone
            })
            # Create the tutor user in Firebase with the temporary password
            user = auth.create_user_with_email_and_password(email, temporary_password)
            print(f"Created user with email: {email}")  # For your reference in logs
            
            # Send password reset email to the tutor
            auth.send_password_reset_email(email)
            print(f"Sent password reset email to: {email}")  # For your reference in logs
            
        return redirect(url_for('admin'))

    # Handle deletion
    delete_id = request.args.get('delete_id')
    if delete_id:
        tutor_ref.child(delete_id).delete()
        return redirect(url_for('admin'))

    return render_template('admin.html', tutors=tutors)

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
        year_end = request.form['year_end']
        year_start=request.form['year_start']
        
        # Email validation
        if not is_valid_email(email):
            flash("Please use your SRMIST email for sign up.", "danger")
            return render_template('signup.html')

        # Password confirmation validation
        if password != retype_password:
            flash("Passwords do not match. Please try again.", "danger")
            return render_template('signup.html')

        # Year validation: ensure year_end is greater than year_start
        try:
            if int(year_end) < int(year_start):
                flash("Year of end is not valid. Please try again.", "danger")
                return render_template('signup.html')
        except ValueError:
            flash("Please enter valid numeric values for years.", "danger")
            return render_template('signup.html')


        try:
            # Check if the email is already registered in Firebase Realtime Database
            encoded = urllib.parse.quote(email, safe="")
            users = database.child('users').get()
            if users and users.each():
                for user in users.each():
                    user_data = user.val()
                    if user_data.get('email') == email:
                        flash("This email is already signed up. Please go back to the login page.", "danger")
                        return render_template('signup.html')

        except Exception as e:
            flash("Error checking users in the database: " + str(e), "danger")
            return render_template('signup.html')

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
                'year_start':year_start,
                'year_end': year_end,
                'joined': '2024-01-01'  # Example joined date
            }

            # Save the user data in Firebase Realtime Database under the user's UID
            database.child('users').child(uid).set(user_data)

            # Redirect to login page upon successful signup
            flash("Signup successful! Please login.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            flash("Error creating user in Firebase: " + str(e), "danger")
            return render_template('signup.html')

    return render_template('signup.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Email validation
        if not is_valid_email(email):
            flash("Please use your SRMIST email for login.", "danger")
            return render_template('login.html')
        
        try:
            # Attempt to sign in with Firebase Authentication
            user = auth.sign_in_with_email_and_password(email, password)
            
            # Retrieve the user ID and set session variables
            session['user'] = {
                'idToken': user['idToken'],
                'localId': user['localId'],
                'email': email
            }
            
            # Check if the user is a tutor in Firebase Realtime Database
            tutor_ref = db.reference('tutors')
            tutors = tutor_ref.get()
            
            if tutors:
                for tutor_id, tutor_data in tutors.items():
                    if tutor_data['email'] == email:
                        session['tutor_id'] = tutor_id
                        return redirect(url_for('tutor_students', tutor_id=tutor_id))
            
            # Check if the user is an admin
            admins = ['bs1329@srmist.edu.in']
            if email in admins:
                session['is_admin'] = True
                return redirect(url_for('admin'))
            
            # Redirect to a general user dashboard if not an admin or tutor
            return redirect(url_for('user_dashboard'))

        except Exception as e:
            # Error handling and feedback for the login form
            flash("Invalid email or password. Please try again.", "danger")
            return render_template('login.html')

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Email validation for SRMIST domain
        if not is_valid_email(email):
            flash("Please use your SRMIST email for password reset.", "danger")
            return render_template('forgot_password.html')
        
        try:
            # Send password reset email
            auth.send_password_reset_email(email)
            flash('A password reset link has been sent to your email address.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error sending password reset email: {str(e)}", 'danger')
            return render_template('forgot_password.html')

    return render_template('forgot_password.html')

def get_user_data(user_id):
    ref = db.reference(f'users/{user_id}')
    user_snapshot = ref.get()
    if user_snapshot:
        return user_snapshot
    return None

@app.route('/dashboard', methods=['GET'])
@login_required
def user_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session['user']['localId']
    
    # Fetch user data from Firebase
    user_data = get_user_data(user_id)
    if not user_data:
        flash("User data not found. Please try again.", "danger")
        return redirect(url_for('login'))
    
    # Define activity counts for available categories
    activity_counts = {
        "courses": 0,
        "sports": 0,
        "technical": 0,        # New category for technical events
        "non_technical": 0,     # New category for non-technical events
        "webinars": 0,          # New category for webinars
        "seminars": 0,          # New category for seminars
        "workshops": 0          # New category for workshops
    }

    # Check and count activities in each category
    if "courses" in user_data:
        activity_counts["courses"] = len(user_data["courses"])
    
    if "sports" in user_data:
        activity_counts["sports"] = len(user_data["sports"])

    # Count technical and non-technical events
    if "events" in user_data:
        for event in user_data["events"].values():
            if event["event_type"] == "technical":
                activity_counts["technical"] += 1
            elif event["event_type"] == "non-technical":
                activity_counts["non_technical"] += 1

    # Count webinars, seminars, and workshops
    if "webinar_seminar" in user_data:
        for event in user_data["webinar_seminar"].values():
        # Normalize the event type to lowercase for comparison
            event_type = event["event_type"].lower()
            
            if event_type == "webinar":
                activity_counts["webinars"] += 1
            elif event_type == "seminar":
                activity_counts["seminars"] += 1
            elif event_type == "workshop":
                activity_counts["workshops"] += 1

    return render_template('dashboard.html', user=user_data, activity_counts=activity_counts)


@app.route('/logout', methods=["POST", "GET"])
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
           
# Route for uploading activities (only accessible to logged-in users)
@app.route('/upload_activities', methods=['GET', 'POST'])
@login_required
def upload_activities():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user')['localId']
    errors=[]
    if request.method == 'POST':
        form_type = request.form.get('formType')  # Determine whether it's event or course form

        if form_type == 'event':
            # Handle event form submission
            event_type = request.form.get('eventType')
            event_name = request.form.get('eventName')
            participation_type = request.form.get('participationType')
            achievement_level = request.form.get('achievementLevel')
            organizer = request.form.get('organizerOptions')
            other_organizer_name = request.form.get('otherOrganizerName', '')
            participation_dates = request.form.get('participationDates')
            venue_location = request.form.get('venueLocation')
            certificate = request.files.get('certificate')

            if event_type and event_name and participation_type and participation_dates and venue_location:
                activity_data = {
                    "event_type": event_type,
                    "event_name": event_name,
                    "participation_type": participation_type,
                    "achievement_level": achievement_level,
                    "organizer": organizer,
                    "organizer_name": other_organizer_name,
                    "participation_dates": participation_dates,
                    "venue_location": venue_location
                }

                # Handle certificate upload
                file_url = ''
            if certificate and certificate.filename != '':
                if allowed_file(certificate.filename):
                    # Secure the filename
                    filename = secure_filename(certificate.filename)
                    file_extension = os.path.splitext(filename)[1]
                    unique_filename = f"{uuid.uuid4()}{file_extension}"

                    try:
                        # Upload to Firebase Storage
                        bucket = storage.bucket()
                        file_blob = bucket.blob(f"event_certificate/{unique_filename}")
                        file_blob.upload_from_file(certificate)
                        file_blob.make_public()
                        file_url = file_blob.public_url
                        print("File uploaded successfully:", file_url)
                    except Exception as e:
                        print("Error uploading file:", e)
                        errors.append("Failed to upload the certificate/proof file.")
                else:
                    errors.append("Invalid file type for Certificate/Proof. Allowed types: PDF, JPG, JPEG, PNG.")


                # Save to Firebase Realtime Database
                db.reference(f'users/{user_id}/events').push(activity_data)

        elif form_type == 'course':
            # Handle course form submission
            course_name = request.form.get('courseName')
            skills_gained = request.form.get('skillsGained')
            platform = request.form.get('platform')
            completion_date = request.form.get('completionDate')
            course_certificate = request.files.get('courseCertificate')

            if course_name and skills_gained and platform and completion_date:
                course_data = {
                    "course_name": course_name,
                    "skills_gained": skills_gained,
                    "platform": platform,
                    "completion_date": completion_date
                }

                # Handle course certificate upload
                # Handle file upload and errrors 
            file_url = ''
            if course_certificate and course_certificate.filename != '':
                if allowed_file(course_certificate.filename):
                    # Secure the filename
                    filename = secure_filename(course_certificate.filename)
                    file_extension = os.path.splitext(filename)[1]
                    unique_filename = f"{uuid.uuid4()}{file_extension}"

                    try:
                        # Upload to Firebase Storage
                        bucket = storage.bucket()
                        file_blob = bucket.blob(f"Course_certificate/{unique_filename}")
                        
                        # Open course_certificate in binary mode if required
                        file_blob.upload_from_file(course_certificate)  # Ensure this is file-like

                        # Make the file public
                        file_blob.make_public()
                        file_url = file_blob.public_url
                        print("File uploaded successfully:", file_url)
                    except Exception as e:
                        print("Error uploading file:", e)
                        errors.append("Failed to upload the certificate/proof file.")
                else:
                    errors.append("Invalid file type for Certificate/Proof. Allowed types: PDF, JPG, JPEG, PNG.")
                # Save to Firebase Realtime Database
                db.reference(f'users/{user_id}/courses').push(course_data)
                
        elif form_type == 'sports':
        # Handle sports form submission
            event_name = request.form.get('eventName')
            organizer = request.form.get('organizer')
            sport = request.form.get('sport')  # Now directly getting the selected sport
            dates = request.form.get('dates')
            venue = request.form.get('venue')
            competition_level = request.form.get('competitionLevel')
            prize = request.form.get('prize')
            file_upload = request.files.get('fileUpload')

            # Backend Validation
            errors = []

            # Validate required fields
            if not event_name:
                errors.append("Event Name is required.")
            if not organizer:
                errors.append("Organizer is required.")
            if not sport:
                errors.append("Please select a Sport.")
            if not dates:
                errors.append("Dates of Participation are required.")
            if not venue:
                errors.append("Venue/Location is required.")
            if not competition_level:
                errors.append("Level of Competition is required.")
            if not prize:
                errors.append("Prize selection is required.")

            # Initialize sports data dictionary
            sports_data = {
                "event_name": event_name,
                "organizer": organizer,
                "sport": sport,
                "dates": dates,
                "venue": venue,
                "competition_level": competition_level,
                "prize": prize
            }

            # Handle file upload and errors
            file_url = ''
            if file_upload and file_upload.filename != '':
                if allowed_file(file_upload.filename):
                    # Secure the filename
                    filename = secure_filename(file_upload.filename)
                    file_extension = os.path.splitext(filename)[1]
                    unique_filename = f"{uuid.uuid4()}{file_extension}"

                    try:
                        # Upload to Firebase Storage
                        bucket = storage.bucket()
                        file_blob = bucket.blob(f"sports_files/{unique_filename}")
                        file_blob.upload_from_file(file_upload)
                        file_blob.make_public()
                        file_url = file_blob.public_url
                        print("File uploaded successfully:", file_url)
                    except Exception as e:
                        print("Error uploading file:", e)
                        errors.append("Failed to upload the certificate/proof file.")
                else:
                    errors.append("Invalid file type for Certificate/Proof. Allowed types: PDF, JPG, JPEG, PNG.")

            # Save to Firebase Realtime Database if no errors
            if not errors:
                db.reference(f'users/{user_id}/sports').push(sports_data)
            else:
                # Handle the errors (return or log them as needed)
                print("Errors encountered:", errors)


        elif form_type == 'webinar_seminar':
            # Handle webinar/seminar form submission
            event_type = request.form.get('eventType')
            event_name = request.form.get('eventName')
            participation_type = request.form.get('participationType')
            organizer = request.form.get('organizerOptions')
            participation_dates = request.form.get('participationDates')
            venue_location = request.form.get('venueLocation')
            certificate = request.files.get('certificate')
            if event_type and event_name and participation_type and participation_dates and venue_location:
                webinar_seminar_data = {
                    "event_type": event_type,
                    "event_name": event_name,
                    "participation_type": participation_type,
                    "organizer": organizer,
                    "participation_dates": participation_dates,
                    "venue_location": venue_location
                }
                # Handle certificate upload
                file_url = ''
                if certificate and certificate.filename != '':
                    if allowed_file(certificate.filename):
                        # Secure the filename
                        filename = secure_filename(certificate.filename)
                        file_extension = os.path.splitext(filename)[1]
                        unique_filename = f"{uuid.uuid4()}{file_extension}"
                        try:
                            # Upload to Firebase Storage
                            bucket = storage.bucket()
                            file_blob = bucket.blob(f"webinar_seminar_certificate/{unique_filename}")
                            file_blob.upload_from_file(certificate)
                            file_blob.make_public()
                            file_url = file_blob.public_url
                            print("File uploaded successfully:", file_url)
                        except Exception as e:
                            print("Error uploading file:", e)
                            errors.append("Failed to upload the certificate/proof file.")
                    else:
                        errors.append("Invalid file type for Certificate/Proof. Allowed types: PDF, JPG, JPEG, PNG.")
                
                # Save to Firebase Realtime Database
                db.reference(f'users/{user_id}/webinar_seminar').push(webinar_seminar_data)

        flash("Activity uploaded successfully!", "success")
        return redirect(url_for('upload_activities'))

    return render_template('activity.html')
    
@app.route('/test_firebase', methods=['GET'])
def test_firebase():
    try:
        ref = db.reference('test_data')
        ref.set({"message": "Hello, Firebase!"})
        return "Data written successfully"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/tutor/<tutor_id>', methods=['GET'])
def tutor_students(tutor_id):
    # Get tutor details
    tutor = database.child("tutors").child(tutor_id).get().val()
    if not tutor:
        return "Tutor not found", 404

    # Get tutor's department and batch
    tutor_department = tutor.get("department")
    tutor_batch = tutor.get("batch")

    # Fetch all students from the Firebase database
    students = database.child("users").get().val()

    # Filter students based on the tutor's department and batch
    filtered_students = []
    for student_id, student_data in students.items():
        if student_data["department"] == tutor_department and student_data["batch"] == tutor_batch:
            filtered_students.append(student_data)

    return render_template('tutor_students.html', students=filtered_students, tutor=tutor)

def get_student_by_email(email):
    # Fetch all users and filter by email
    users_ref = db.reference('users')
    all_users = users_ref.get()
    
    for user_id, user_data in all_users.items():
        if user_data.get("email") == email:
            return user_data  # Return the matched student data
    
    return None  # Return None if no student with the email is found

@app.route('/student_details/<email>', methods=['GET'])
def student_details(email):
    students = get_student_by_email(email)
    
    if students:
        return render_template('student_details.html', student=students)
    return "Student not found", 404


if __name__ == '__main__':
    app.run(debug=True)
