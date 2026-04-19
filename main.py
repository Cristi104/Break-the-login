import src.db
from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

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

    user_id = db.create_user(email, password)

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="auth",
        value=user_id,
    )

    return response


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    user = db.get_user_by_email(email)

    if not user:
        return templates.TemplateResponse(request, "login.html", {"request": request, "message": "no account associated with email"})
    if user[5] == 1:
        return templates.TemplateResponse(request, "login.html", {"request": request, "message": "account locked"})
    if password != user[2]:
        return templates.TemplateResponse(request, "login.html", {"request": request, "message": "invalid password"})

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="auth",
        value=user[0],
    )

    return response

@app.post("/forgot/password")
def login(request: Request, email: str = Form(...)):
    user = db.get_user_by_email(email)

    if not user:
        return templates.TemplateResponse(request, "forgot_password.html", {"request": request, "message": "no account associated with email"})
    if user[5] == 1:
        return templates.TemplateResponse(request, "forgot_password.html", {"request": request, "message": "account locked"})

    token = user[0]
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
    
    id = token
    db.user_update_password(id, password)

    response = RedirectResponse(url="/login", status_code=303)
    return response
