import firebase_admin
from firebase_admin import credentials, messaging
import os

# Path al file delle credenziali
cred_path = os.path.join(os.path.dirname(__file__), 'firebase-credentials.json')
cred = credentials.Certificate(cred_path)

# Inizializza Firebase Admin (solo una volta)
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

def send_push_notification(fcm_token, title, body, data=None):
    """Invia una notifica push a un dispositivo specifico"""
    try:
        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
            data=data or {},
            token=fcm_token,
        )
        
        response = messaging.send(message)
        print(f"✅ Notifica inviata: {response}")
        return True
    except Exception as e:
        print(f"❌ Errore invio notifica: {e}")
        return False