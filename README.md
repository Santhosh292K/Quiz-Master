
# 🎯 QuizMaster – Flask-Based Quiz Application

QuizMaster is a dynamic and responsive quiz platform built using Flask. It provides role-based functionality, enabling administrators to manage quizzes, subjects, and users, while users can register, attempt quizzes, and track their performance through analytics and summaries.

---

## 🚀 Features

- 👤 **Authentication System**  
  User registration, login, logout, and profile management with secure password hashing.

- 🧑‍🏫 **Admin Portal**
  - Manage users, subjects, chapters, quizzes, and questions
  - Dashboard for monitoring user progress
  - View and analyze quiz performance and summaries

- 🎯 **User Dashboard**
  - Attempt timed quizzes
  - Review quiz history
  - Access performance summaries

- 📈 **Performance Analytics**
  - Track scores over time
  - Compare quiz attempts
  - View statistical summaries via charts

---

## 🛠️ Tech Stack

### Backend
- **Flask** – Web application framework
- **Flask-SQLAlchemy** – ORM to interact with SQLite
- **Werkzeug Security** – For password hashing
- **functools** – Used for creating access control decorators
- **datetime** – For quiz timing and logs

### Frontend
- **Jinja2** – Flask templating engine
- **Bootstrap 5** – For UI components and responsiveness
- **Tailwind CSS** – Utility-first CSS for styling
- **FontAwesome** – Icons for enhanced UI/UX

### Database
- **SQLite** – Lightweight embedded database system

---

## 📡 API Overview

### 🧾 Authentication & User Management
- `/login`, `/register`, `/logout`, `/profile`, `/profile/edit`
- Admin: `/admin/user/add`, `/admin/user/<user_id>/edit`, `/admin/user/<user_id>/delete`

### 📊 Dashboards
- `/dashboard`, `/user/dashboard`, `/admin/dashboard`
- Summaries: `/summary`, `/user/summary`, `/admin/summary`

### 📚 Subject & Chapter Management (Admin)
- `/admin/subjects`, `/admin/subject/add`, `/admin/subject/<id>/edit`, `/admin/subject/<id>/delete`
- Chapters: `/admin/subject/<id>/chapters`, `/admin/subject/<id>/chapter/add`, `/admin/chapter/<id>/edit`, `/admin/chapter/<id>/delete`

### 📝 Quiz Management
- Admin: `/admin/quizzes`, `/admin/quiz/<id>/view`, `/admin/quiz/<id>`, `/admin/quiz/<id>/delete`
- User: `/quiz/<id>/start`, `/quiz/<id>`, `/quiz/result/<attempt_id>`

### 🔌 Quiz APIs
- `/api/subject/<id>/quizzes`, `/api/chapter/<id>/quizzes`
- `/api/quiz/<id>/questions`, `/api/quiz/<id>/submit`, `/api/quiz/<id>/attempts`
- `/api/quiz/<id>/question/<question_id>/answer`, `/api/quiz/<id>/time-analysis`

### 📈 Performance Stats
- `/api/user/statistics`, `/api/user/performance-comparison`

---

## 📁 Project Structure

```
quizmaster/
│
├── app.py                 # Main Flask app
├── templates/             # HTML templates
│   ├── admin/             # Admin views
│   ├── user/              # User views
│   └── login/             # Login/Register views
│
├── static/                # CSS, JS, and assets
├── user.db                # SQLite database
├── requirements.txt       # Dependencies
└── README.md              # Project documentation
```

---

## ⚙️ Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/Santhosh292k/Quiz-Master.git
cd quizmaster
```

### 2. Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the App
```bash
python app.py
```

### 5. Open in Browser
Visit: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🔐 Default Admin Credentials

> You can define a default admin user within the app or use programmatic database creation to initialize with admin rights.

---

## 🧪 Sample Quiz Flow

1. Admin adds a subject and chapters
2. Admin creates a quiz and adds questions
3. User logs in and attempts a quiz
4. User views results and analytics
5. Admin tracks attempts and user performance

---

## 📝 Notes

- MCQ-based questions (single correct option)
- Quiz duration and start date customization
- Charts available for both admin and users
- Programmatic DB creation (no manual setup)

---

