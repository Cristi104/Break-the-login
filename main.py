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

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html", {"request": request})

@app.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...)):
    existing = db.get_user_by_email(email)

    if existing:
        return templates.TemplateResponse(request, "invalid_cred.html", {"request": request})

    user_id = db.create_user(email, password)

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="auth",
        value=user_id,
    )

    return response


@app.post("/login")
def login(response: Response, email: str = Form(...), password: str = Form(...)):
    user = db.get_user_by_email(email)

    if not user or user[5] == 1 or password != user[2]:
        return templates.TemplateResponse(request, "invalid_cred.html", {"request": request})

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="auth",
        value=user[0],
    )

    return response
