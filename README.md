# API Authentication System (Flask + JWT)

A production‑style authentication backend built with **Flask**, **SQLAlchemy**, and **JWT tokens**.
This project provides a clean, reusable authentication module that can plug into any web or mobile application (React, Vue, mobile apps, or other services).

It was designed following an **API‑First architecture** — the frontend is completely separated and communicates only through HTTP requests.

---

## 🚀 Features

* User registration
* Secure login with hashed passwords
* JWT Access Token authentication
* Protected routes (authenticated users only)
* Token identity endpoint (`/auth/me`)
* PostgreSQL database support
* Environment variable configuration
* Clean modular Flask structure
* Ready to connect to React / Vue frontend

---

## 🧠 Tech Stack

| Layer              | Technology            |
| ------------------ | --------------------- |
| Backend Framework  | Flask                 |
| Database           | PostgreSQL            |
| ORM                | SQLAlchemy            |
| Authentication     | JSON Web Tokens (JWT) |
| Password Security  | Werkzeug hashing      |
| Environment Config | python-dotenv         |

---

## 📂 Project Structure

```
Backend/
│
├── app/
│   ├── __init__.py        # App factory & extensions
│   ├── models/            # Database models
│   ├── routes/            # Auth routes
│   ├── services/          # Business logic (auth handling)
│   └── utils/             # Helper functions
│
├── run.py                 # Application entry point
├── requirements.txt       # Python dependencies
├── .env.example           # Environment variables template
└── .gitignore
```

---

## ⚙️ Setup Instructions

### 1) Clone the repository

```
git clone https://github.com/Charles-DEV-1/Authentication-System.git
cd Backend
```

### 2) Create virtual environment

**Linux / WSL / Mac**

```
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell)**

```
python -m venv venv
venv\Scripts\activate
```

### 3) Install dependencies

```
pip install -r requirements.txt
```

### 4) Configure environment variables

Create a `.env` file based on `.env.example`:

```
SECRET_KEY=supersecretkey
DATABASE_URL=postgresql://postgres:password@localhost:5432/learning_platform
JWT_SECRET_KEY=jwtsecretkey
FLASK_ENV=development
```

---

## 🗄️ Database

Make sure PostgreSQL is running and the database exists.

Then run migrations or create tables (depending on your setup):

```
python run.py
```

The server will automatically connect and create tables if configured in the app factory.

---

## ▶️ Running the Server

```
python run.py
```

Server starts at:

```
http://127.0.0.1:5000
```

---

## 🔐 Authentication Flow

1. User registers
2. User logs in
3. Server returns JWT access token
4. Frontend stores token
5. Token is sent in request headers
6. Protected routes verify token

### Authorization Header

```
Authorization: Bearer <your_token>
```

---

## 📡 API Endpoints

### Register

`POST /auth/register`

Body:

```
{
  "username": "charles",
  "password": "mypassword"
}
```

---

### Login

`POST /auth/login`

Response:

```
{
  "access_token": "JWT_TOKEN"
}
```

---

### Current User (Protected)

`GET /auth/me`

Headers:

```
Authorization: Bearer <token>
```

---

## 🧪 Testing (Postman)

1. Login to obtain token
2. Copy the token
3. Go to **Authorization tab** in Postman
4. Select **Bearer Token**
5. Paste the token
6. Access `/auth/me`

---

## 🌱 Future Improvements

* Refresh tokens
* Email verification
* Password reset
* Rate limiting
* Role‑based authorization (admin, student, instructor)
* Docker deployment

---

## 🤝 Use Case

This authentication module is intended to be used as the foundation for a larger system such as:

* Online learning platforms
* SaaS dashboards
* Mobile applications
* Collaboration tools

---

## 👨‍💻 Author

**Charles (Backend Developer in Training)**
Focused on Python, APIs, and full‑stack web development.

---

## 📜 License

This project is open‑source and free to use for learning and educational purposes.
