
import os
import re
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from pwdlib import PasswordHash


# --------------------------------------------------
# Project paths and environment variables
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "Please set SECRET_KEY in your environment variables."
    )

TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Fail clearly if required folders are missing.
if not TEMPLATES_DIR.is_dir():
    raise RuntimeError(
        f"Templates folder not found: {TEMPLATES_DIR}"
    )

if not STATIC_DIR.is_dir():
    raise RuntimeError(
        f"Static folder not found: {STATIC_DIR}"
    )

# Fail clearly if required HTML pages are missing.
required_templates = [
    "login.html",
    "register.html",
    "dashboard.html",
]

for filename in required_templates:
    if not (TEMPLATES_DIR / filename).is_file():
        raise RuntimeError(
            f"Required template not found: "
            f"{TEMPLATES_DIR / filename}"
        )


# --------------------------------------------------
# FastAPI application and session configuration
# --------------------------------------------------

app = FastAPI(title="FastAPI Login System")

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="login_session",
    max_age=3600,
    same_site="lax",
    https_only=(
        os.getenv("COOKIE_SECURE", "false").lower() == "true"
    ),
)

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static",
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
password_hasher = PasswordHash.recommended()


# --------------------------------------------------
# Temporary user storage
# WARNING: Data is not persistent on Vercel.
# --------------------------------------------------

users = {}


# --------------------------------------------------
# Helper functions
# --------------------------------------------------

def valid_email(email: str) -> bool:
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return bool(re.fullmatch(pattern, email))


def current_user(request: Request):
    email = request.session.get("user_email")

    if not email:
        return None

    return users.get(email)


def render(request: Request, page: str, **context):
    return templates.TemplateResponse(
        request=request,
        name=page,
        context=context,
    )


# --------------------------------------------------
# Home page
# --------------------------------------------------

@app.get("/")
async def home(request: Request):
    destination = (
        "/dashboard" if current_user(request) else "/login"
    )
    return RedirectResponse(destination, status_code=303)


# --------------------------------------------------
# Registration page
# --------------------------------------------------

@app.get("/register")
async def register_page(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard", status_code=303)

    return render(request, "register.html", error=None)


@app.post("/register")
async def register(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    name = name.strip()
    email = email.strip().lower()

    if not name or len(name) > 80:
        return render(
            request,
            "register.html",
            error="Name must contain 1 to 80 characters.",
        )

    if len(email) > 254 or not valid_email(email):
        return render(
            request,
            "register.html",
            error="Please enter a valid email address.",
        )

    if email in users:
        return render(
            request,
            "register.html",
            error="An account with this email already exists.",
        )

    if not 8 <= len(password) <= 128:
        return render(
            request,
            "register.html",
            error="Password must be between 8 and 128 characters.",
        )

    if password != confirm_password:
        return render(
            request,
            "register.html",
            error="Passwords do not match.",
        )

    users[email] = {
        "name": name,
        "email": email,
        "password_hash": password_hasher.hash(password),
    }

    return RedirectResponse("/login?registered=1", status_code=303)


# --------------------------------------------------
# Login page
# --------------------------------------------------

@app.get("/login")
async def login_page(request: Request, registered: int = 0):
    if current_user(request):
        return RedirectResponse("/dashboard", status_code=303)

    message = (
        "Registration successful! Please log in."
        if registered == 1
        else None
    )

    return render(
        request,
        "login.html",
        error=None,
        message=message,
    )


@app.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    email = email.strip().lower()
    user = users.get(email)

    if not user or not password_hasher.verify(
        password, user["password_hash"]
    ):
        return render(
            request,
            "login.html",
            error="Invalid email or password.",
            message=None,
        )

    request.session.clear()
    request.session["user_email"] = email

    return RedirectResponse("/dashboard", status_code=303)


# --------------------------------------------------
# Dashboard
# --------------------------------------------------

@app.get("/dashboard")
async def dashboard(request: Request):
    user = current_user(request)

    if not user:
        return RedirectResponse("/login", status_code=303)

    return render(request, "dashboard.html", user=user)


# --------------------------------------------------
# Logout
# --------------------------------------------------

@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
