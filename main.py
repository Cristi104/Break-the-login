import src.db
from fastapi import FastAPI, HTTPException, Form, Request, Response, status, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from datetime import datetime, timedelta
from typing import Optional
import re
import bcrypt
import secrets

MAX_ATTEMPTS = 3
user_attempts = {}
logged_in_users = {}
SECRET_KEY = "secret-key"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
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
    auth = request.cookies.get("auth")
    if not auth or datetime.utcnow() > logged_in_users[auth][0]:
        logged_in_users.pop(auth, None)
        return templates.TemplateResponse(request, "index.html", {"request": request, "loggedin": 0})
    return templates.TemplateResponse(request, "index.html", {"request": request, "loggedin": 1})

@app.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...)):
    existing = db.get_user_by_email(email)

    if existing or not check_password_policy(password):
        return templates.TemplateResponse(request, "register.html", {"request": request, "message": "invalid password or email"})

    user_id = db.create_user(email, hash_password(password))

    expires_at = datetime.utcnow() + timedelta(minutes=30)
    session_token = secrets.token_urlsafe(32)
    logged_in_users[session_token] = (expires_at, user_id)
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="auth",
        value=session_token,
        expires=int(expires_at.timestamp()),
        httponly=True,
        secure=True,
        samesite="Strict",
        path="/"
    )

    return response


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    user = db.get_user_by_email(email)
    if email not in user_attempts:
        user_attempts[email] = 0


    user_attempts[email] += 1
    if user_attempts[email] == MAX_ATTEMPTS:
        db.user_update_locked(user["id"], 1)
    if not user or user["locked"] == 1 or not check_password(password, user["password_hash"]):
        return templates.TemplateResponse(request, "login.html", {"request": request, "message": "wrong password or email"})

    user_attempts[email] = 0

    expires_at = datetime.utcnow() + timedelta(minutes=30)
    session_token = secrets.token_urlsafe(32)
    logged_in_users[session_token] = (expires_at, user["id"])
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="auth",
        value=session_token,
        expires=int(expires_at.timestamp()),
        httponly=True,
        secure=True,
        samesite="Strict",
        path="/"
    )

    return response

@app.post("/forgot/password")
def login(request: Request, email: str = Form(...)):
    user = db.get_user_by_email(email)

    if not user:
        response = RedirectResponse(url="/login", status_code=303)
        return response

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
    auth = request.cookies.get("auth")
    if not auth or datetime.utcnow() > logged_in_users[auth][0]:
        logged_in_users.pop(auth, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    tickets = db.get_tickets()
    return templates.TemplateResponse(request, "list.html", {
        "request": request,
        "tickets": tickets
    })


@app.get("/tickets/new")
def new_ticket_form(request: Request):
    auth = request.cookies.get("auth")
    if not auth or datetime.utcnow() > logged_in_users[auth][0]:
        logged_in_users.pop(auth, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

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
    auth = request.cookies.get("auth")
    if not auth or datetime.utcnow() > logged_in_users[auth][0]:
        logged_in_users.pop(auth, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    owner_id = logged_in_users[auth][1]
    db.create_ticket(title, description, severity, status, owner_id)
    return RedirectResponse("/tickets", status_code=303)


@app.get("/tickets/{ticket_id}", response_class=HTMLResponse)
def view_ticket(request: Request, ticket_id: int):
    auth = request.cookies.get("auth")
    if not auth or datetime.utcnow() > logged_in_users[auth][0]:
        logged_in_users.pop(auth, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    ticket = db.get_ticket_by_id(ticket_id)

    return templates.TemplateResponse(request, "detail.html", {
        "request": request,
        "ticket": ticket
    })


@app.get("/tickets/{ticket_id}/edit")
def edit_form(request: Request, ticket_id: int):
    auth = request.cookies.get("auth")
    if not auth or datetime.utcnow() > logged_in_users[auth][0]:
        logged_in_users.pop(auth, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

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
    auth = request.cookies.get("auth")
    if not auth or datetime.utcnow() > logged_in_users[auth][0]:
        logged_in_users.pop(auth, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    owner_id = logged_in_users[auth][1]
    db.ticket_update(title, description, severity, status, owner_id, ticket_id)
    return RedirectResponse(f"/tickets/{ticket_id}", status_code=303)

@app.post("/tickets/{ticket_id}/delete")
def delete_ticket(request: Request, ticket_id: int):
    auth = request.cookies.get("auth")
    if not auth or datetime.utcnow() > logged_in_users[auth][0]:
        logged_in_users.pop(auth, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    db.ticket_delete(ticket_id)
    return RedirectResponse("/tickets", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    auth = request.cookies.get("auth")
    logged_in_users.pop(auth, None)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        key="auth",
        value="",
        expires=0,
        httponly=True,
        secure=True,
        samesite="Strict",
        path="/"
    )
    return response
