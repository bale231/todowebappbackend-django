import os

# Prova a importare firebase_admin, ma non bloccare l'app se non è disponibile
try:
    import firebase_admin
    from firebase_admin import credentials, messaging

    # Path al file delle credenziali
    cred_path = os.path.join(os.path.dirname(__file__), 'firebase-credentials.json')

    # Inizializza Firebase Admin solo se il file di credenziali esiste
    if os.path.exists(cred_path) and not firebase_admin._apps:
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        FIREBASE_AVAILABLE = True
        print("✅ Firebase inizializzato correttamente")
    else:
        FIREBASE_AVAILABLE = False
        if not os.path.exists(cred_path):
            print("⚠️ File firebase-credentials.json non trovato. Notifiche push disabilitate.")
except ImportError:
    FIREBASE_AVAILABLE = False
    print("⚠️ firebase-admin non installato. Notifiche push disabilitate.")
    print("   Per abilitarle: pip install firebase-admin")

def send_push_notification(fcm_token, title, body, data=None):
    """Invia una notifica push a un dispositivo specifico"""
    if not FIREBASE_AVAILABLE:
        print(f"⚠️ Firebase non disponibile. Notifica non inviata: {title}")
        return False

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
        print(f"✅ Notifica push inviata: {response}")
        return True
    except Exception as e:
        print(f"❌ Errore invio notifica push: {e}")
        return False
