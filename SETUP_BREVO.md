# Configurazione Brevo per Email Verification

## Come configurare la chiave API Brevo su PythonAnywhere

### Passo 1: Crea il file di configurazione

Sulla console Bash di PythonAnywhere, esegui:

```bash
cd ~/todobackend/todoproject/todoproject
nano brevo_key.py
```

### Passo 2: Incolla questo contenuto

```python
"""
Configurazione chiave API Brevo
Questo file NON viene mai caricato su GitHub (è nel .gitignore)
"""

BREVO_API_KEY = "LA_TUA_CHIAVE_BREVO_QUI"
```

**Sostituisci `LA_TUA_CHIAVE_BREVO_QUI` con la chiave vera che hai ricevuto.**

### Passo 3: Salva e chiudi

- Premi `Ctrl+O` per salvare
- Premi `Enter` per confermare
- Premi `Ctrl+X` per uscire

### Passo 4: Ricarica l'app

Vai sulla dashboard Web di PythonAnywhere e clicca "Reload" sulla tua web app.

---

## ✅ Fatto!

Ora la verifica email funzionerà correttamente. Gli utenti riceveranno email di conferma quando si registrano.

## Note di Sicurezza

- Il file `brevo_key.py` non verrà mai caricato su GitHub
- Se vuoi cambiare la chiave in futuro, modifica solo questo file
- Per rigenerare una nuova chiave: https://app.brevo.com/settings/keys/api
