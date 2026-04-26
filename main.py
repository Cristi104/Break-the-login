import src.db
from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import re
import bcrypt

MAX_ATTEMPTS = 3
user_attempts = {} # Dictionary to store login attempts for each user

def login(username, password):
    if username not in user_attempts:
        user_attempts[username] = 0

    if user_attempts[username] >= MAX_ATTEMPTS:
        print(f"Account for {username} is locked due to too many failed attempts.")
        return False

    # In a real application, you'd verify the password against a stored hash
    if username == "myuser" and password == "mypassword": # Placeholder for actual password check
        print(f"Welcome, {username}!")
        user_attempts[username] = 0 # Reset attempts on successful login
        return True
    else:
        user_attempts[username] += 1
        attempts_left = MAX_ATTEMPTS - user_attempts[username]
        if attempts_left > 0:
            print(f"Incorrect password for {username}. {attempts_left} attempts remaining.")
        else:
            print(f"Incorrect password for {username}. Account locked.")
        return False

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def check_password_policy(password):
    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"[0-9]", password):
        return False

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
        return False

    return True

db = src.db.Database()
app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/login", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "register.html", {"request": request})

@app.get("/forgot/password", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "forgot_password.html", {"request": request})

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html", {"request": request})

@app.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...)):
    existing = db.get_user_by_email(email)

    if existing:
        return templates.TemplateResponse(request, "register.html", {"request": request, "message": "email allready in use"})

    if not check_password_policy(password):
        return templates.TemplateResponse(request, "register.html", {"request": request, "message": "weak password"})


    user_id = db.create_user(email, hash_password(password))

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="auth",
        value=user_id,
    )

    return response


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    user = db.get_user_by_email(email)
    if email not in user_attempts:
        user_attempts[email] = 0


    user_attempts[email] += 1
    print(user["locked"])
    if user_attempts[email] == MAX_ATTEMPTS:
        db.user_update_locked(user["id"], 1)
    if not user:
        return templates.TemplateResponse(request, "login.html", {"request": request, "message": "no account associated with email"})
    if user["locked"] == 1:
        return templates.TemplateResponse(request, "login.html", {"request": request, "message": "account locked"})
    if not check_password(password, user["password_hash"]):
        return templates.TemplateResponse(request, "login.html", {"request": request, "message": "invalid password"})

    user_attempts[email] = 0
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="auth",
        value=user["id"],
    )

    return response

@app.post("/forgot/password")
def login(request: Request, email: str = Form(...)):
    user = db.get_user_by_email(email)

    if not user:
        return templates.TemplateResponse(request, "forgot_password.html", {"request": request, "message": "no account associated with email"})

    token = user["id"]
    print(f"http://localhost:8000/reset/password?token={token}")

    response = RedirectResponse(url="/login", status_code=303)
    return response

@app.get("/reset/password", response_class=HTMLResponse)
def form(request: Request, token: str):
    return templates.TemplateResponse( 
        request, 
        "reset_password.html",
        {"request": request, "token": token}
    )

@app.post("/reset/password")
def login(request: Request, password: str = Form(...), token: str = Form(...)):
    
    if not check_password_policy(password):
        return templates.TemplateResponse( 
            request, 
            "reset_password.html",
            {"request": request, "token": token, "message": "weak password"}
        )

    id = token
    db.user_update_password(id, hash_password(password))
    db.user_update_locked(id, 0)

    response = RedirectResponse(url="/login", status_code=303)
    return response

@app.get("/tickets")
def list_tickets(request: Request):
    tickets = db.get_tickets()
    return templates.TemplateResponse(request, "list.html", {
        "request": request,
        "tickets": tickets
    })


@app.get("/tickets/new")
def new_ticket_form(request: Request):
    return templates.TemplateResponse(request, "form.html", {
        "request": request,
        "ticket": None
    })


@app.post("/tickets/new")
def create_ticket(
    request: Request, 
    title: str = Form(...),
    description: str = Form(""),
    severity: str = Form("LOW"),
    status: str = Form("OPEN"),
):
    owner_id = request.cookies.get("auth")
    db.create_ticket(title, description, severity, status, owner_id)
    return RedirectResponse("/tickets", status_code=303)


@app.get("/tickets/{ticket_id}", response_class=HTMLResponse)
def view_ticket(request: Request, ticket_id: int):
    ticket = db.get_ticket_by_id(ticket_id)

    return templates.TemplateResponse(request, "detail.html", {
        "request": request,
        "ticket": ticket
    })


@app.get("/tickets/{ticket_id}/edit")
def edit_form(request: Request, ticket_id: int):
    ticket = db.get_ticket_by_id(ticket_id)
    return templates.TemplateResponse(request, "form.html", {
        "request": request,
        "ticket": ticket
    })


@app.post("/tickets/{ticket_id}/edit")
def update_ticket(
    request: Request, 
    ticket_id: int,
    title: str = Form(...),
    description: str = Form(""),
    severity: str = Form("LOW"),
    status: str = Form("OPEN"),
):
    owner_id = request.cookies.get("auth")
    db.ticket_update(title, description, severity, status, owner_id, ticket_id)
    return RedirectResponse(f"/tickets/{ticket_id}", status_code=303)

@app.post("/tickets/{ticket_id}/delete")
def delete_ticket(ticket_id: int):
    db.ticket_delete(ticket_id)
    return RedirectResponse("/tickets", status_code=303)
