"""
Servizio per l'invio di email tramite API Brevo (ex-Sendinblue)
Compatibile con PythonAnywhere Free Tier
"""

import requests
import logging

logger = logging.getLogger(__name__)

# ⚠️ IMPORTANTE: Sostituisci questa API key con la tua da Brevo
# Per ottenerla: https://app.brevo.com/settings/keys/api
# La API key attuale è un placeholder e va sostituita
BREVO_API_KEY = "xkeysib-INSERISCI_TUA_API_KEY_QUI"

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


def send_verification_email(to_email, subject, html_content):
    """
    Invia email di verifica tramite API Brevo

    Args:
        to_email (str): Email destinatario
        subject (str): Oggetto dell'email
        html_content (str): Contenuto HTML dell'email

    Returns:
        bool: True se email inviata con successo, False altrimenti
    """

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
