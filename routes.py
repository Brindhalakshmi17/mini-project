from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import re
from firebase import verify_id_token

routes = Blueprint('routes', __name__)

@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        id_token = request.form['id_token']
        decoded_token = verify_id_token(id_token)
        
        if decoded_token:
            net_id = decoded_token['email']
            if re.match(r'^[a-zA-Z0-9]+@srmist\.edu\.in$', net_id):
                session['net_id'] = net_id
                return redirect(url_for('routes.dashboard'))
            else:
                flash('Invalid SRM Net ID format')
        else:
            flash('Invalid ID token')

    return render_template('login.html')

@routes.route('/dashboard')
def dashboard():
    if 'net_id' in session:
        return f'Logged in as {session["net_id"]}'
    return redirect(url_for('routes.login'))

@routes.route('/logout')
def logout():
    session.pop('net_id', None)
    return redirect(url_for('routes.login'))
