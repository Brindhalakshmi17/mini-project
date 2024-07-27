import firebase_admin
from firebase_admin import credentials, auth

class Config:
    SECRET_KEY = 'your_secret_key'  # Flask secret key for session management

class FirebaseConfig:
    def __init__(self):
        self.cred = credentials.Certificate('firebase_key.json')
        firebase_admin.initialize_app(self.cred)

firebase_config = FirebaseConfig()
