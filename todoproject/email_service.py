"""
Servizio per l'invio di email tramite API Brevo (ex-Sendinblue)
Compatibile con PythonAnywhere Free Tier
"""

import requests
import logging
import os

logger = logging.getLogger(__name__)

# ⚠️ IMPORTANTE: Per configurare Brevo, crea il file 'brevo_key.py' con la tua chiave API
# Copia brevo_key.example.py e rinominalo in brevo_key.py, poi inserisci la chiave vera
# Ottienila da: https://app.brevo.com/settings/keys/api

# Prova a importare la chiave dal file locale (se esiste)
try:
    from todoproject.brevo_key import BREVO_API_KEY
except ImportError:
    # Fallback alla variabile d'ambiente
    BREVO_API_KEY = os.environ.get('BREVO_API_KEY', '')

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

# Verifica se Brevo è configurato
EMAIL_ENABLED = bool(BREVO_API_KEY and BREVO_API_KEY.startswith('xkeysib-'))


def send_verification_email(to_email, subject, html_content):
    """
    Invia email di verifica tramite API Brevo

    Args:
        to_email (str): Email destinatario
        subject (str): Oggetto dell'email
        html_content (str): Contenuto HTML dell'email

    Returns:
        bool: True se email inviata con successo o se email disabilitate, False solo in caso di errore
    """

    # Se email non sono abilitate, ritorna True (successo silenzioso)
    if not EMAIL_ENABLED:
        logger.info(f"⚠️ Invio email disabilitato. Email non inviata a {to_email}")
        logger.info("   Per abilitare: imposta variabile d'ambiente BREVO_API_KEY")
        return True

    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }

    payload = {
        "sender": {
            "name": "ToDoApp",
            "email": "todoapp@webdesign-vito-luigi.it"
        },
        "to": [
            {
                "email": to_email
            }
        ],
        "subject": subject,
        "htmlContent": html_content
    }

    try:
        response = requests.post(BREVO_API_URL, json=payload, headers=headers)

        if response.status_code in [200, 201]:
            logger.info(f"✅ Email inviata con successo a {to_email}")
            return True
        else:
            logger.error(f"❌ Errore invio email: {response.status_code} - {response.text}")
            return False

    except Exception as e:
        logger.error(f"❌ Eccezione durante invio email: {str(e)}")
        return False


def send_password_reset_email(to_email, subject, html_content):
    """
    Invia email di reset password tramite API Brevo
    (usa la stessa funzione di send_verification_email)
    """
    return send_verification_email(to_email, subject, html_content)
