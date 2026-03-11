# ToDoApp Backend - Django REST API

Backend API per **ToDoApp**, un'applicazione web per la gestione di liste e to-do con supporto offline, condivisione in tempo reale e integrazione con assistenti vocali.

## Stack Tecnologico

- **Django 5.1** + **Django REST Framework**
- **SQLite** (database)
- **Simple JWT** per autenticazione
- **Firebase Cloud Messaging** per notifiche push
- **Brevo (Sendinblue)** per invio email
- **Anthropic Claude Haiku** per chatbot AI
- **PythonAnywhere** (hosting)

## Setup Locale

```bash
git clone https://github.com/bale231/todowebappbackend-django.git
cd todowebappbackend-django
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

## Variabili d'Ambiente

Crea un file `.env` nella root del progetto:

```
ANTHROPIC_API_KEY=sk-ant-...
```

## Struttura Progetto

```
todowebappbackend-django/
├── todoproject/          # Configurazione Django
│   ├── settings.py       # Impostazioni principali
│   ├── urls.py           # URL root (/api/ -> todos.urls)
│   ├── firebase_config.py
│   ├── email_service.py
│   └── wsgi.py
├── todos/                # App principale
│   ├── models.py         # Modelli database
│   ├── views.py          # Logica API
│   ├── urls.py           # Routing endpoint
│   ├── serializers.py    # Serializzatori DRF
│   ├── authentication.py # Auth custom VoiceKey
│   └── templates/        # Template HTML
├── manage.py
└── requirements.txt
```

## Modelli

| Modello | Descrizione |
|---------|-------------|
| `User` | Modello utente Django built-in |
| `Profile` | Profilo utente (foto, tema, preferenze, FCM token) |
| `ListCategory` | Categorie per raggruppare le liste (es. Casa, Lavoro) |
| `Category` | Lista di todo (nome, colore, ordinamento, archivio) |
| `Todo` | Singolo elemento todo (titolo, completato, quantità, unità) |
| `Notification` | Notifiche in-app e push |
| `FriendRequest` | Richieste di amicizia |
| `Friendship` | Relazione di amicizia tra utenti |
| `SharedList` | Condivisione lista con permessi |
| `SharedCategory` | Condivisione categoria con permessi |
| `PasswordResetToken` | Token per reset password |
| `VoiceAPIKey` | API key permanenti per assistenti vocali |

## Autenticazione

Il backend supporta due metodi di autenticazione:

### JWT (Bearer Token)
Usato da frontend web e mobile.
```
Authorization: Bearer <access_token>
```
- Access token: 30 minuti di validità
- Refresh token: 1 giorno (30 giorni con "Rimani loggato")

### VoiceKey
Usato dagli endpoint `/api/voice/*` per Siri Shortcuts.
```
Authorization: VoiceKey <api_key>
```
- Non scade, revocabile dall'utente
- Max 3 key per utente

---

## Endpoint API

Base URL: `https://bale231.pythonanywhere.com/api/`

### Autenticazione & Account

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `POST` | `/register/` | Registra nuovo utente | No |
| `POST` | `/login/` | Login con username o email | No |
| `POST` | `/mobile-login/` | Login per app mobile | No |
| `POST` | `/logout/` | Logout | No |
| `DELETE` | `/delete-account/` | Elimina account | JWT |
| `GET` | `/jwt-user/` | Dati utente autenticato | JWT |
| `POST` | `/update-profile-jwt/` | Aggiorna profilo | JWT |
| `POST` | `/update-theme/` | Cambia tema (light/dark) | JWT |

**POST /register/**
```json
// Request
{ "username": "mario", "email": "mario@email.com", "password": "Password1" }
// Response 201
{ "message": "Registrazione completata!", "email_verification_required": true }
```

**POST /login/**
```json
// Request
{ "username": "mario", "email": "mario@email.com", "password": "Password1", "remember_me": true }
// Response 200
{ "access": "eyJ...", "refresh": "eyJ...", "user": { "id": 1, "username": "mario", ... } }
```

---

### Email & Password Reset

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `POST` | `/send-verification-email/` | Invia email di verifica | JWT |
| `GET` | `/verify-email/<uidb64>/<token>/` | Verifica email | No |
| `POST` | `/reset-password/` | Richiedi reset password | No |
| `POST` | `/reset-password/<uidb64>/<token>/` | Conferma reset password | No |

---

### Token JWT

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `POST` | `/token/` | Ottieni coppia JWT (access + refresh) | No |
| `POST` | `/token/refresh/` | Rinnova access token | No |

**POST /token/**
```json
// Request
{ "username": "mario", "password": "Password1", "remember_me": false }
// Response 200
{ "access": "eyJ...", "refresh": "eyJ..." }
```

---

### Categorie (raggruppamento liste)

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `GET` | `/categories/` | Lista categorie utente + condivise | JWT |
| `POST` | `/categories/` | Crea categoria | JWT |
| `PATCH` | `/categories/<pk>/` | Modifica categoria | JWT |
| `DELETE` | `/categories/<pk>/` | Elimina categoria | JWT |
| `GET` | `/categories/sort_preference/` | Preferenza ordinamento | JWT |
| `PATCH` | `/categories/sort_preference/` | Salva preferenza ordinamento | JWT |
| `GET` | `/categories/selected/` | Categoria selezionata | JWT |
| `PATCH` | `/categories/selected/` | Salva categoria selezionata | JWT |

**POST /categories/**
```json
// Request
{ "name": "Casa" }
// Response 201
{ "id": 1, "name": "Casa" }
```

---

### Liste (Category)

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `GET` | `/lists/` | Tutte le liste + todo (query: `?include_archived=false`) | JWT |
| `POST` | `/lists/` | Crea lista | JWT |
| `GET` | `/lists/<id>/` | Dettaglio lista con todo | JWT |
| `PUT` | `/lists/<id>/` | Modifica lista | JWT |
| `DELETE` | `/lists/<id>/` | Elimina lista | JWT |
| `PATCH` | `/lists/<id>/rename/` | Rinomina lista | JWT |
| `PATCH` | `/lists/<id>/archive/` | Archivia lista | JWT |
| `PATCH` | `/lists/<id>/unarchive/` | Ripristina lista | JWT |
| `GET` | `/lists/sort_order/` | Ordinamento liste | JWT |
| `PATCH` | `/lists/sort_order/` | Aggiorna ordinamento | JWT |

**POST /lists/**
```json
// Request
{ "name": "Spesa", "color": "green", "category": 1 }
// Response 201
{ "id": 5, "name": "Spesa", "color": "green" }
```

**GET /lists/**
```json
// Response 200
[
  {
    "id": 5,
    "name": "Spesa",
    "color": "green",
    "created_at": "2024-01-15T10:30:00Z",
    "sort_order": "created",
    "category": { "id": 1, "name": "Casa" },
    "is_owner": true,
    "is_shared": false,
    "can_edit": true,
    "shared_by": null,
    "is_archived": false,
    "todos": [
      {
        "id": 10,
        "title": "Latte",
        "completed": false,
        "order": 0,
        "quantity": 2,
        "unit": "litri",
        "created_by": { "id": 1, "username": "mario", "full_name": "Mario Rossi" }
      }
    ]
  }
]
```

---

### Todo

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `POST` | `/lists/<list_id>/todos/` | Crea todo | JWT |
| `PATCH` | `/todos/<id>/toggle/` | Completa/scompleta | JWT |
| `PATCH` | `/todos/<id>/update/` | Modifica todo | JWT |
| `DELETE` | `/todos/<id>/` | Elimina todo | JWT |
| `PATCH` | `/todos/<id>/move/` | Sposta in altra lista | JWT |
| `PATCH` | `/lists/<list_id>/sort_order/` | Ordinamento todo nella lista | JWT |

**POST /lists/5/todos/**
```json
// Request
{ "title": "Latte", "quantity": 2, "unit": "litri" }
// Response 201
{
  "id": 10,
  "title": "Latte",
  "completed": false,
  "order": 0,
  "quantity": 2,
  "unit": "litri",
  "created_by": { "id": 1, "username": "mario", "full_name": "Mario Rossi" }
}
```

**PATCH /todos/10/move/**
```json
// Request
{ "new_list_id": 8 }
// Response 200
{ "success": true, "message": "Todo spostata", "new_list_id": 8, "new_list_name": "Lavoro" }
```

---

### Notifiche

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `GET` | `/notifications/` | Lista notifiche | JWT |
| `PATCH` | `/notifications/<id>/read/` | Segna come letta | JWT |
| `POST` | `/notifications/mark_all_read/` | Segna tutte come lette | JWT |
| `DELETE` | `/notifications/<id>/` | Elimina notifica | JWT |
| `PATCH` | `/notifications/preferences/` | Preferenze push | JWT |
| `POST` | `/notifications/update/` | Crea notifica aggiornamento | JWT |
| `POST` | `/notifications/save-fcm-token/` | Salva token FCM | JWT |

---

### Amicizie

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `GET` | `/users/?search=...` | Cerca utenti | JWT |
| `GET` | `/friends/` | Lista amici | JWT |
| `GET` | `/friend-requests/` | Richieste ricevute | JWT |
| `POST` | `/friend-requests/send/<user_id>/` | Invia richiesta | JWT |
| `POST` | `/friend-requests/<id>/accept/` | Accetta richiesta | JWT |
| `POST` | `/friend-requests/<id>/reject/` | Rifiuta richiesta | JWT |
| `DELETE` | `/friends/<user_id>/remove/` | Rimuovi amico | JWT |

---

### Condivisione Liste

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `POST` | `/lists/<id>/share/` | Condividi lista | JWT |
| `DELETE` | `/lists/<id>/share/<user_id>/` | Rimuovi condivisione | JWT |
| `GET` | `/lists/<id>/shares/` | Vedi condivisioni | JWT |

**POST /lists/5/share/**
```json
// Request
{ "user_id": 2, "can_edit": true }
// Response 200
{ "message": "Lista condivisa con successo" }
```

---

### Condivisione Categorie

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `POST` | `/categories/<id>/share/` | Condividi categoria | JWT |
| `DELETE` | `/categories/<id>/share/<user_id>/` | Rimuovi condivisione | JWT |
| `GET` | `/categories/<id>/shares/` | Vedi condivisioni | JWT |

---

### AI Chatbot

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `POST` | `/ai-chat/` | Chat con assistente AI | No |

**POST /ai-chat/**
```json
// Request
{
  "message": "Come creo una lista?",
  "conversation_history": [
    { "role": "user", "content": "Ciao" },
    { "role": "assistant", "content": "Ciao! Come posso aiutarti?" }
  ]
}
// Response 200
{ "reply": "Per creare una nuova lista, vai nella Home e clicca sul pulsante + ..." }
```

Usa il modello **Claude Haiku** (`claude-haiku-4-20250414`). Risponde solo a domande relative all'app.

---

### Voice / Siri Shortcuts

| Metodo | Endpoint | Descrizione | Auth |
|--------|----------|-------------|------|
| `POST` | `/voice/add-todo/` | Aggiungi todo via voce | JWT o VoiceKey |
| `GET` | `/voice/lists/` | Nomi liste per Siri | JWT o VoiceKey |
| `GET` | `/voice/setup/` | Pagina HTML setup | JWT |
| `GET` | `/voice/keys/` | Lista API key | JWT |
| `POST` | `/voice/keys/` | Crea API key | JWT |
| `DELETE` | `/voice/keys/<id>/` | Revoca API key | JWT |

**POST /voice/add-todo/**
```json
// Request
{ "title": "Latte", "quantity": 2, "unit": "litri", "list_name": "Spesa" }
// Response 201
{
  "success": true,
  "message": "Aggiunto: 2 litri di Latte alla lista Spesa",
  "todo": { "id": 10, "title": "Latte", "quantity": 2, "unit": "litri" },
  "list": { "id": 5, "name": "Spesa" }
}
```

**POST /voice/keys/**
```json
// Request
{ "name": "iPhone di Luigi" }
// Response 201
{
  "id": 1,
  "key": "abc123xyz...",
  "name": "iPhone di Luigi",
  "created_at": "2024-01-15T10:30:00Z",
  "message": "Salva questa chiave! Non potrai vederla di nuovo."
}
```

---

## Codici di Stato HTTP

| Codice | Significato |
|--------|-------------|
| `200` | Successo |
| `201` | Creato con successo |
| `400` | Richiesta non valida |
| `401` | Non autenticato |
| `403` | Permesso negato |
| `404` | Non trovato |
| `500` | Errore server |
| `503` | Servizio non disponibile (AI non configurata) |
