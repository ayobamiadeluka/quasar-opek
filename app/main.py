import os
import re
import psycopg
import hashlib
import secrets

from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware


# =========================================================
# APP CONFIG
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "change-this-secret-key"
)

ADMIN_EMAIL = os.getenv(
    "ADMIN_EMAIL",
    "admin@quasar-opek.com"
).strip().lower()

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD",
    "change-this-password"
)

APP_BASE_URL = os.getenv(
    "APP_BASE_URL",
    "http://127.0.0.1:8000"
).rstrip("/")

DB_PATH = Path(
    os.getenv(
        "DB_PATH",
        str(BASE_DIR / "quasar.db")
    )
)


app = FastAPI(
    title="QUASAR-OPEK Portal"
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=60 * 60 * 24 * 7,
)


# =========================================================
# STATIC FILES / TEMPLATES
# =========================================================

app.mount(
    "/static",
    StaticFiles(
        directory=str(BASE_DIR / "static")
    ),
    name="static",
)

templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)


# =========================================================
# DATABASE
# =========================================================

class HybridRow(dict):
    """Allow database rows to be accessed by column name or numeric index."""

    def __init__(self, columns, values):
        super().__init__(zip(columns, values))
        self._values = values

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


def hybrid_row_factory(cursor):
    # Column descriptions are available when a result row is fetched.
    return lambda values: HybridRow(
        [column.name for column in cursor.description],
        values,
    )


class PostgresConnection:
    """Small compatibility layer for the app's existing parameterized queries."""

    def __init__(self, connection):
        self._connection = connection

    def execute(self, sql, params=()):
        # Existing application queries use SQLite-style question-mark markers.
        return self._connection.execute(
            sql.replace("?", "%s"),
            params,
        )

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()


@contextmanager
def get_db():
    url = os.getenv("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not configured.")

    conn = psycopg.connect(
        url,
        row_factory=hybrid_row_factory,
    )
    db = PostgresConnection(conn)

    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# =========================================================
# GENERAL HELPERS
# =========================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)

    hashed = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
    )

    return f"{salt.hex()}:{hashed.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":", 1)

        salt = bytes.fromhex(salt_hex)

        hashed = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=16384,
            r=8,
            p=1,
        )

        return secrets.compare_digest(
            hashed.hex(),
            hash_hex,
        )

    except Exception:
        return False


def generate_referral_code():
    return secrets.token_hex(4).upper()


def mask_account(account_number):
    if not account_number:
        return ""

    if len(account_number) <= 4:
        return "*" * len(account_number)

    return (
        "*" * (len(account_number) - 4)
        + account_number[-4:]
    )


def flash(
    request: Request,
    message: str,
    category: str = "info",
):
    request.session["flash"] = {
        "message": message,
        "category": category,
    }


def get_flash(request: Request):
    return request.session.pop(
        "flash",
        None,
    )


def valid_email(email: str) -> bool:
    return bool(
        re.fullmatch(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
            email,
        )
    )


def valid_account_number(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"\d{10}",
            value,
        )
    )


def valid_password(password: str) -> bool:
    return len(password) >= 8


# =========================================================
# DATABASE INITIALIZATION / MIGRATION
# =========================================================

def init_db():
    # The tables already exist in Supabase. Do not recreate or migrate them
    # using SQLite-specific SQL during application startup.
    with get_db() as conn:
        admin = conn.execute(
            "SELECT id FROM users WHERE email=?",
            (ADMIN_EMAIL,),
        ).fetchone()

        if not admin:
            conn.execute("""
                INSERT INTO users (
                    full_name, email, phone, password_hash,
                    role, status, registration_fee_status,
                    weekly_target, referral_code, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "QUASAR-OPEK Administrator",
                ADMIN_EMAIL,
                "",
                hash_password(ADMIN_PASSWORD),
                "admin",
                "approved",
                "approved",
                1000,
                None,
                now_iso(),
            ))
        else:
            conn.execute("""
                UPDATE users
                SET role='admin',
                    status='approved',
                    registration_fee_status='approved'
                WHERE email=?
            """, (ADMIN_EMAIL,))


init_db()


# =========================================================
# NOTIFICATIONS
# =========================================================

def create_notification(
    user_id: int,
    title: str,
    message: str,
    category: str = "info",
):
    with get_db() as conn:
        conn.execute("""
            INSERT INTO notifications (
                user_id,
                title,
                message,
                category,
                is_read,
                created_at
            )
            VALUES (?, ?, ?, ?, 0, ?)
        """, (
            user_id,
            title,
            message,
            category,
            now_iso(),
        ))


def get_notifications(user_id: int, limit=10):

    with get_db() as conn:
        return conn.execute("""
            SELECT *
            FROM notifications
            WHERE user_id=?
            ORDER BY id DESC
            LIMIT ?
        """, (
            user_id,
            limit,
        )).fetchall()


def get_unread_notification_count(user_id: int):

    with get_db() as conn:
        return conn.execute("""
            SELECT COUNT(*)
            FROM notifications
            WHERE user_id=?
              AND is_read=0
        """, (user_id,)).fetchone()[0]


# =========================================================
# CURRENT USER
# =========================================================

def current_user(request: Request):

    user_id = request.session.get("user_id")

    if not user_id:
        return None

    with get_db() as conn:

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE id=?
        """, (user_id,)).fetchone()

    return user


def require_user(request: Request):

    user = current_user(request)

    if not user:
        return None

    if user["role"] == "admin":
        return user

    if user["status"] != "approved":

        request.session.clear()

        return None

    return user


def require_admin(request: Request):

    user = current_user(request)

    if not user:
        return None

    if user["role"] != "admin":
        return None

    return user


# =========================================================
# HOME
# =========================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):

    user = current_user(request)

    if user:

        if user["role"] == "admin":
            return RedirectResponse(
                "/admin",
                status_code=303,
            )

        if user["status"] == "approved":
            return RedirectResponse(
                "/dashboard",
                status_code=303,
            )

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "flash": get_flash(request),
        },
    )


# =========================================================
# REGISTER
# =========================================================

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):

    return templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "user": current_user(request),
            "flash": get_flash(request),
        },
    )


@app.post("/register")
def register(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    bank_name: str = Form(...),
    account_name: str = Form(...),
    account_number: str = Form(...),
    registration_reference: str = Form(...),
    registration_transfer_account_name: str = Form(...),
    referral_code: str = Form(""),
):

    full_name = full_name.strip()
    email = email.strip().lower()
    phone = phone.strip()
    bank_name = bank_name.strip()
    account_name = account_name.strip()
    account_number = account_number.strip()
    registration_reference = registration_reference.strip()
    registration_transfer_account_name = (
        registration_transfer_account_name.strip()
    )
    referral_code = referral_code.strip().upper()

    # -------------------------------------------------
    # VALIDATION
    # -------------------------------------------------

    if not full_name:
        flash(
            request,
            "Please enter your full name.",
            "error",
        )
        return RedirectResponse(
            "/register",
            status_code=303,
        )

    if not valid_email(email):
        flash(
            request,
            "Please enter a valid email address.",
            "error",
        )
        return RedirectResponse(
            "/register",
            status_code=303,
        )

    if not valid_password(password):
        flash(
            request,
            "Password must be at least 8 characters.",
            "error",
        )
        return RedirectResponse(
            "/register",
            status_code=303,
        )

    if password != confirm_password:
        flash(
            request,
            "Passwords do not match.",
            "error",
        )
        return RedirectResponse(
            "/register",
            status_code=303,
        )

    if not valid_account_number(account_number):
        flash(
            request,
            "Account number must contain exactly 10 digits.",
            "error",
        )
        return RedirectResponse(
            "/register",
            status_code=303,
        )

    if not registration_reference:
        flash(
            request,
            "Please enter your registration payment reference.",
            "error",
        )
        return RedirectResponse(
            "/register",
            status_code=303,
        )

    if not registration_transfer_account_name:
        flash(
            request,
            "Please enter the name used for the registration payment.",
            "error",
        )
        return RedirectResponse(
            "/register",
            status_code=303,
        )

    # -------------------------------------------------
    # DATABASE
    # -------------------------------------------------

    with get_db() as conn:

        existing = conn.execute("""
            SELECT id
            FROM users
            WHERE email=?
        """, (email,)).fetchone()

        if existing:

            flash(
                request,
                "An account with this email already exists.",
                "error",
            )

            return RedirectResponse(
                "/register",
                status_code=303,
            )

        # -------------------------------------------------
        # CHECK REGISTRATION REFERENCE
        # -------------------------------------------------

        existing_reference = conn.execute("""
            SELECT id
            FROM transactions
            WHERE reference=?
        """, (registration_reference,)).fetchone()

        if existing_reference:

            flash(
                request,
                "This payment reference has already been used.",
                "error",
            )

            return RedirectResponse(
                "/register",
                status_code=303,
            )

        # -------------------------------------------------
        # REFERRAL
        # -------------------------------------------------

        referred_by = None

        if referral_code:

            referrer = conn.execute("""
                SELECT id
                FROM users
                WHERE referral_code=?
                  AND role='user'
                  AND status='approved'
            """, (referral_code,)).fetchone()

            if not referrer:

                flash(
                    request,
                    "Invalid referral code.",
                    "error",
                )

                return RedirectResponse(
                    "/register",
                    status_code=303,
                )

            referred_by = referral_code

        # -------------------------------------------------
        # GENERATE REFERRAL CODE
        # -------------------------------------------------

        new_referral_code = generate_referral_code()

        while conn.execute("""
            SELECT id
            FROM users
            WHERE referral_code=?
        """, (new_referral_code,)).fetchone():

            new_referral_code = generate_referral_code()

        # -------------------------------------------------
        # CREATE USER
        # -------------------------------------------------

        cursor = conn.execute("""
            INSERT INTO users (
                full_name,
                email,
                phone,
                password_hash,
                bank_name,
                account_name,
                account_number,
                role,
                status,
                registration_fee_status,
                weekly_target,
                referral_code,
                referred_by,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
        """, (
            full_name,
            email,
            phone,
            hash_password(password),
            bank_name,
            account_name,
            account_number,
            "user",
            "pending",
            "pending",
            1000,
            new_referral_code,
            referred_by,
            now_iso(),
        ))

        user_id = cursor.fetchone()[0]

        # -------------------------------------------------
        # REGISTRATION FEE
        # -------------------------------------------------

        conn.execute("""
            INSERT INTO transactions (
                user_id,
                kind,
                amount,
                status,
                reference,
                transfer_account_name,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            "registration_fee",
            2000,
            "pending",
            registration_reference,
            registration_transfer_account_name,
            now_iso(),
        ))

    flash(
        request,
        "Registration successful. Your account is now waiting for admin approval.",
        "success",
    )

    return RedirectResponse(
        "/login",
        status_code=303,
    )


# =========================================================
# LOGIN
# =========================================================

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "user": current_user(request),
            "flash": get_flash(request),
        },
    )


@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):

    email = email.strip().lower()

    with get_db() as conn:

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE email=?
        """, (email,)).fetchone()

    if not user:

        flash(
            request,
            "Invalid email or password.",
            "error",
        )

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if not verify_password(
        password,
        user["password_hash"],
    ):

        flash(
            request,
            "Invalid email or password.",
            "error",
        )

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    # -------------------------------------------------
    # ADMIN
    # -------------------------------------------------

    if user["role"] == "admin":

        request.session.clear()

        request.session["user_id"] = user["id"]

        return RedirectResponse(
            "/admin",
            status_code=303,
        )

    # -------------------------------------------------
    # MEMBER STATUS
    # -------------------------------------------------

    if user["status"] == "pending":

        flash(
            request,
            "Your account is still waiting for admin approval.",
            "info",
        )

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if user["status"] == "rejected":

        flash(
            request,
            "Your account registration was rejected.",
            "error",
        )

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    request.session.clear()

    request.session["user_id"] = user["id"]

    return RedirectResponse(
        "/dashboard",
        status_code=303,
    )


# =========================================================
# LOGOUT
# =========================================================

@app.get("/logout")
def logout(request: Request):

    request.session.clear()

    return RedirectResponse(
        "/",
        status_code=303,
    )


# =========================================================
# MEMBER DASHBOARD
# =========================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):

    user = require_user(request)

    if not user:

        flash(
            request,
            "Please log in with an approved account.",
            "error",
        )

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if user["role"] == "admin":
        return RedirectResponse(
            "/admin",
            status_code=303,
        )

    with get_db() as conn:

        # -------------------------------------------------
        # TOTAL APPROVED
        # -------------------------------------------------

        approved_total = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE user_id=?
              AND kind='contribution'
              AND status='approved'
        """, (user["id"],)).fetchone()[0]

        # -------------------------------------------------
        # TOTAL PENDING
        # -------------------------------------------------

        pending_total = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE user_id=?
              AND kind='contribution'
              AND status='pending'
        """, (user["id"],)).fetchone()[0]

        # -------------------------------------------------
        # TRANSACTIONS
        # -------------------------------------------------

        transactions = conn.execute("""
            SELECT *
            FROM transactions
            WHERE user_id=?
            ORDER BY id DESC
        """, (user["id"],)).fetchall()

        # -------------------------------------------------
        # REFERRALS
        # -------------------------------------------------

        referral_count = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE referred_by=?
        """, (user["referral_code"],)).fetchone()[0]

        referred_members = conn.execute("""
            SELECT
                id,
                full_name,
                email,
                status,
                created_at
            FROM users
            WHERE referred_by=?
            ORDER BY id DESC
        """, (user["referral_code"],)).fetchall()

        # -------------------------------------------------
        # REGISTRATION FEE
        # -------------------------------------------------

        registration_fee = conn.execute("""
            SELECT *
            FROM transactions
            WHERE user_id=?
              AND kind='registration_fee'
            ORDER BY id DESC
            LIMIT 1
        """, (user["id"],)).fetchone()

    # -------------------------------------------------
    # WEEKLY CONTRIBUTION
    # -------------------------------------------------

    weekly_target = user["weekly_target"] or 1000

    today = datetime.now(timezone.utc).date()

    monday = today.fromordinal(
        today.toordinal() - today.weekday()
    )

    monday_iso = datetime.combine(
        monday,
        datetime.min.time(),
        tzinfo=timezone.utc,
    ).isoformat()

    with get_db() as conn:

        weekly_approved = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE user_id=?
              AND kind='contribution'
              AND status='approved'
              AND created_at >=?
        """, (
            user["id"],
            monday_iso,
        )).fetchone()[0]

        weekly_pending = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE user_id=?
              AND kind='contribution'
              AND status='pending'
              AND created_at >=?
        """, (
            user["id"],
            monday_iso,
        )).fetchone()[0]

    remaining = max(
        0,
        weekly_target - weekly_approved,
    )

    progress = min(
        100,
        int(
            (weekly_approved / weekly_target) * 100
        )
        if weekly_target
        else 0,
    )

    notifications = get_notifications(
        user["id"],
        10,
    )

    unread_notifications = (
        get_unread_notification_count(
            user["id"]
        )
    )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,

            "transactions": transactions,

            "approved_total": approved_total,
            "pending_total": pending_total,

            "weekly_approved": weekly_approved,
            "weekly_pending": weekly_pending,
            "weekly_target": weekly_target,
            "remaining": remaining,
            "progress": progress,

            "referral_count": referral_count,
            "referred_members": referred_members,

            "registration_fee": registration_fee,

            "notifications": notifications,
            "unread_notifications": unread_notifications,

            "masked_account": mask_account(
                user["account_number"]
            ),

            "flash": get_flash(request),
        },
    )


# =========================================================
# PROFILE
# =========================================================

@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request):

    user = require_user(request)

    if not user:

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": user,
            "flash": get_flash(request),
        },
    )


# =========================================================
# UPDATE PROFILE
# =========================================================

@app.post("/profile/update")
def update_profile(
    request: Request,
    full_name: str = Form(...),
    phone: str = Form(...),
    bank_name: str = Form(...),
    account_name: str = Form(...),
    account_number: str = Form(...),
):

    user = require_user(request)

    if not user:

        flash(
            request,
            "Please log in first.",
            "error",
        )

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    full_name = full_name.strip()
    phone = phone.strip()
    bank_name = bank_name.strip()
    account_name = account_name.strip()
    account_number = account_number.strip()

    if not full_name:

        flash(
            request,
            "Full name is required.",
            "error",
        )

        return RedirectResponse(
            "/profile",
            status_code=303,
        )

    if not valid_account_number(account_number):

        flash(
            request,
            "Account number must contain exactly 10 digits.",
            "error",
        )

        return RedirectResponse(
            "/profile",
            status_code=303,
        )

    with get_db() as conn:

        conn.execute("""
            UPDATE users
            SET full_name=?,
                phone=?,
                bank_name=?,
                account_name=?,
                account_number=?
            WHERE id=?
        """, (
            full_name,
            phone,
            bank_name,
            account_name,
            account_number,
            user["id"],
        ))

    flash(
        request,
        "Profile updated successfully.",
        "success",
    )

    return RedirectResponse(
        "/profile",
        status_code=303,
    )


# =========================================================
# CHANGE PASSWORD
# =========================================================

@app.post("/profile/password")
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):

    user = require_user(request)

    if not user:

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if not verify_password(
        current_password,
        user["password_hash"],
    ):

        flash(
            request,
            "Your current password is incorrect.",
            "error",
        )

        return RedirectResponse(
            "/profile",
            status_code=303,
        )

    if not valid_password(new_password):

        flash(
            request,
            "New password must be at least 8 characters.",
            "error",
        )

        return RedirectResponse(
            "/profile",
            status_code=303,
        )

    if new_password != confirm_password:

        flash(
            request,
            "New passwords do not match.",
            "error",
        )

        return RedirectResponse(
            "/profile",
            status_code=303,
        )

    with get_db() as conn:

        conn.execute("""
            UPDATE users
            SET password_hash=?
            WHERE id=?
        """, (
            hash_password(new_password),
            user["id"],
        ))

    flash(
        request,
        "Password changed successfully.",
        "success",
    )

    return RedirectResponse(
        "/profile",
        status_code=303,
    )


# =========================================================
# DEPOSIT
# =========================================================

@app.post("/deposit")
def deposit(
    request: Request,
    amount: float = Form(...),
    transfer_bank: str = Form(...),
    transfer_account_name: str = Form(...),
    transfer_account_number: str = Form(...),
    reference: str = Form(...),
):

    user = require_user(request)

    if not user:

        flash(
            request,
            "Please log in with an approved account.",
            "error",
        )

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if amount < 1000:

        flash(
            request,
            "Minimum weekly contribution is ₦1,000.",
            "error",
        )

        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    transfer_bank = transfer_bank.strip()
    transfer_account_name = transfer_account_name.strip()
    transfer_account_number = transfer_account_number.strip()
    reference = reference.strip()

    if not transfer_bank:

        flash(
            request,
            "Please enter the bank used for the transfer.",
            "error",
        )

        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    if not transfer_account_name:

        flash(
            request,
            "Please enter the transfer account name.",
            "error",
        )

        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    if not valid_account_number(
        transfer_account_number
    ):

        flash(
            request,
            "Transfer account number must contain exactly 10 digits.",
            "error",
        )

        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    if not reference:

        flash(
            request,
            "Please enter your transfer reference.",
            "error",
        )

        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    with get_db() as conn:

        existing = conn.execute("""
            SELECT id
            FROM transactions
            WHERE reference=?
        """, (reference,)).fetchone()

        if existing:

            flash(
                request,
                "This transaction reference has already been used.",
                "error",
            )

            return RedirectResponse(
                "/dashboard",
                status_code=303,
            )

        conn.execute("""
            INSERT INTO transactions (
                user_id,
                kind,
                amount,
                status,
                reference,
                transfer_bank,
                transfer_account_name,
                transfer_account_number,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user["id"],
            "contribution",
            amount,
            "pending",
            reference,
            transfer_bank,
            transfer_account_name,
            transfer_account_number,
            now_iso(),
        ))

    create_notification(
        user["id"],
        "Deposit submitted",
        f"Your ₦{amount:,.2f} contribution is waiting for admin approval.",
        "info",
    )

    flash(
        request,
        "Deposit submitted successfully. Waiting for admin approval.",
        "success",
    )

    return RedirectResponse(
        "/dashboard",
        status_code=303,
    )


# =========================================================
# NOTIFICATIONS
# =========================================================

@app.get("/notifications/read-all")
def read_all_notifications(request: Request):

    user = require_user(request)

    if not user:

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with get_db() as conn:

        conn.execute("""
            UPDATE notifications
            SET is_read=1
            WHERE user_id=?
        """, (user["id"],))

    return RedirectResponse(
        "/dashboard",
        status_code=303,
    )


@app.post("/notifications/{notification_id}/read")
def read_notification(
    request: Request,
    notification_id: int,
):

    user = require_user(request)

    if not user:

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with get_db() as conn:

        conn.execute("""
            UPDATE notifications
            SET is_read=1
            WHERE id=?
              AND user_id=?
        """, (
            notification_id,
            user["id"],
        ))

    return RedirectResponse(
        "/dashboard",
        status_code=303,
    )


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    search: str = "",
    status: str = "",
):

    admin = require_admin(request)

    if not admin:

        flash(
            request,
            "Administrator access required.",
            "error",
        )

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with get_db() as conn:

        # -------------------------------------------------
        # MEMBER COUNTS
        # -------------------------------------------------

        total_members = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role='user'
        """).fetchone()[0]

        pending_members = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role='user'
              AND status='pending'
        """).fetchone()[0]

        approved_members = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role='user'
              AND status='approved'
        """).fetchone()[0]

        rejected_members = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role='user'
              AND status='rejected'
        """).fetchone()[0]

        # -------------------------------------------------
        # DEPOSITS
        # -------------------------------------------------

        pending_deposits = conn.execute("""
            SELECT COUNT(*)
            FROM transactions
            WHERE kind='contribution'
              AND status='pending'
        """).fetchone()[0]

        approved_deposits_total = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE kind='contribution'
              AND status='approved'
        """).fetchone()[0]

        pending_deposits_total = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE kind='contribution'
              AND status='pending'
        """).fetchone()[0]

        rejected_deposits_total = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE kind='contribution'
              AND status='rejected'
        """).fetchone()[0]

        # -------------------------------------------------
        # REGISTRATION FEES
        # -------------------------------------------------

        approved_registration_fees = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE kind='registration_fee'
              AND status='approved'
        """).fetchone()[0]

        pending_registration_fees = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE kind='registration_fee'
              AND status='pending'
        """).fetchone()[0]

        # -------------------------------------------------
        # MEMBER SEARCH
        # -------------------------------------------------

        query = """
            SELECT *
            FROM users
            WHERE role='user'
        """

        params = []

        if search:

            query += """
                AND (
                    full_name LIKE ?
                    OR email LIKE ?
                    OR phone LIKE ?
                )
            """

            search_value = f"%{search}%"

            params.extend([
                search_value,
                search_value,
                search_value,
            ])

        if status:

            query += """
                AND status=?
            """

            params.append(status)

        query += """
            ORDER BY id DESC
        """

        members = conn.execute(
            query,
            params,
        ).fetchall()

        # -------------------------------------------------
        # PENDING REGISTRATIONS
        # -------------------------------------------------

        pending_registrations = conn.execute("""
            SELECT
                u.*,
                t.id AS transaction_id,
                t.amount AS registration_amount,
                t.reference AS registration_reference,
                t.transfer_account_name
                    AS registration_transfer_account_name,
                t.status AS registration_transaction_status
            FROM users u
            LEFT JOIN transactions t
                ON t.user_id=u.id
               AND t.kind='registration_fee'
            WHERE u.role='user'
              AND u.status='pending'
            ORDER BY u.id DESC
        """).fetchall()

        # -------------------------------------------------
        # ALL CONTRIBUTIONS
        # -------------------------------------------------

        deposits = conn.execute("""
            SELECT
                t.*,
                u.full_name,
                u.email
            FROM transactions t
            JOIN users u
                ON u.id=t.user_id
            WHERE t.kind='contribution'
            ORDER BY t.id DESC
        """).fetchall()

    return templates.TemplateResponse(
        "admin/dashboard.html",
        {
            "request": request,
            "user": admin,

            "members": members,

            "pending_registrations":
                pending_registrations,

            "deposits": deposits,

            "total_members":
                total_members,

            "pending_members":
                pending_members,

            "approved_members":
                approved_members,

            "rejected_members":
                rejected_members,

            "pending_deposits":
                pending_deposits,

            "approved_deposits_total":
                approved_deposits_total,

            "pending_deposits_total":
                pending_deposits_total,

            "rejected_deposits_total":
                rejected_deposits_total,

            "approved_registration_fees":
                approved_registration_fees,

            "pending_registration_fees":
                pending_registration_fees,

            "search": search,
            "status": status,

            "flash":
                get_flash(request),
        },
    )


# =========================================================
# ADMIN MEMBER PROFILE
# =========================================================

@app.get(
    "/admin/member/{user_id}",
    response_class=HTMLResponse,
)
def admin_member_profile(
    request: Request,
    user_id: int,
):

    admin = require_admin(request)

    if not admin:

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with get_db() as conn:

        member = conn.execute("""
            SELECT *
            FROM users
            WHERE id=?
              AND role='user'
        """, (user_id,)).fetchone()

        if not member:

            flash(
                request,
                "Member not found.",
                "error",
            )

            return RedirectResponse(
                "/admin",
                status_code=303,
            )

        transactions = conn.execute("""
            SELECT *
            FROM transactions
            WHERE user_id=?
            ORDER BY id DESC
        """, (user_id,)).fetchall()

        referrals = conn.execute("""
            SELECT
                full_name,
                email,
                status,
                created_at
            FROM users
            WHERE referred_by=?
            ORDER BY id DESC
        """, (member["referral_code"],)).fetchall()

        approved_total = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE user_id=?
              AND kind='contribution'
              AND status='approved'
        """, (user_id,)).fetchone()[0]

        pending_total = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE user_id=?
              AND kind='contribution'
              AND status='pending'
        """, (user_id,)).fetchone()[0]

    return templates.TemplateResponse(
        "member_profile.html",
        {
            "request": request,
            "user": admin,
            "member": member,
            "transactions": transactions,
            "referrals": referrals,
            "approved_total": approved_total,
            "pending_total": pending_total,
            "flash": get_flash(request),
        },
    )


# =========================================================
# ADMIN APPROVE MEMBER
# =========================================================

@app.post("/admin/member/{user_id}/approve")
def approve_member(
    request: Request,
    user_id: int,
):

    admin = require_admin(request)

    if not admin:

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with get_db() as conn:

        member = conn.execute("""
            SELECT *
            FROM users
            WHERE id=?
              AND role='user'
        """, (user_id,)).fetchone()

        if not member:

            flash(
                request,
                "Member not found.",
                "error",
            )

            return RedirectResponse(
                "/admin",
                status_code=303,
            )

        conn.execute("""
            UPDATE users
            SET status='approved',
                registration_fee_status='approved'
            WHERE id=?
        """, (user_id,))

        conn.execute("""
            UPDATE transactions
            SET status='approved'
            WHERE user_id=?
              AND kind='registration_fee'
              AND status='pending'
        """, (user_id,))

    create_notification(
        user_id,
        "Account approved",
        "Your QUASAR-OPEK account has been approved. You can now log in.",
        "success",
    )

    flash(
        request,
        f"{member['full_name']} has been approved.",
        "success",
    )

    return RedirectResponse(
        "/admin",
        status_code=303,
    )


# =========================================================
# ADMIN REJECT MEMBER
# =========================================================

@app.post("/admin/member/{user_id}/reject")
def reject_member(
    request: Request,
    user_id: int,
):

    admin = require_admin(request)

    if not admin:

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with get_db() as conn:

        member = conn.execute("""
            SELECT *
            FROM users
            WHERE id=?
              AND role='user'
        """, (user_id,)).fetchone()

        if not member:

            flash(
                request,
                "Member not found.",
                "error",
            )

            return RedirectResponse(
                "/admin",
                status_code=303,
            )

        conn.execute("""
            UPDATE users
            SET status='rejected',
                registration_fee_status='rejected'
            WHERE id=?
        """, (user_id,))

        conn.execute("""
            UPDATE transactions
            SET status='rejected'
            WHERE user_id=?
              AND kind='registration_fee'
              AND status='pending'
        """, (user_id,))

    create_notification(
        user_id,
        "Account rejected",
        "Your account registration was rejected by the administrator.",
        "error",
    )

    flash(
        request,
        f"{member['full_name']} has been rejected.",
        "success",
    )

    return RedirectResponse(
        "/admin",
        status_code=303,
    )


# =========================================================
# ADMIN APPROVE DEPOSIT
# =========================================================

@app.post(
    "/admin/deposit/{transaction_id}/approve"
)
def approve_deposit(
    request: Request,
    transaction_id: int,
):

    admin = require_admin(request)

    if not admin:

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with get_db() as conn:

        transaction = conn.execute("""
            SELECT *
            FROM transactions
            WHERE id=?
              AND kind='contribution'
        """, (transaction_id,)).fetchone()

        if not transaction:

            flash(
                request,
                "Deposit not found.",
                "error",
            )

            return RedirectResponse(
                "/admin",
                status_code=303,
            )

        if transaction["status"] != "pending":

            flash(
                request,
                "This deposit has already been processed.",
                "info",
            )

            return RedirectResponse(
                "/admin",
                status_code=303,
            )

        conn.execute("""
            UPDATE transactions
            SET status='approved'
            WHERE id=?
        """, (transaction_id,))

    create_notification(
        transaction["user_id"],
        "Deposit approved",
        f"Your ₦{transaction['amount']:,.2f} contribution has been approved.",
        "success",
    )

    flash(
        request,
        "Deposit approved successfully.",
        "success",
    )

    return RedirectResponse(
        "/admin",
        status_code=303,
    )


# =========================================================
# ADMIN REJECT DEPOSIT
# =========================================================

@app.post(
    "/admin/deposit/{transaction_id}/reject"
)
def reject_deposit(
    request: Request,
    transaction_id: int,
):

    admin = require_admin(request)

    if not admin:

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with get_db() as conn:

        transaction = conn.execute("""
            SELECT *
            FROM transactions
            WHERE id=?
              AND kind='contribution'
        """, (transaction_id,)).fetchone()

        if not transaction:

            flash(
                request,
                "Deposit not found.",
                "error",
            )

            return RedirectResponse(
                "/admin",
                status_code=303,
            )

        if transaction["status"] != "pending":

            flash(
                request,
                "This deposit has already been processed.",
                "info",
            )

            return RedirectResponse(
                "/admin",
                status_code=303,
            )

        conn.execute("""
            UPDATE transactions
            SET status='rejected'
            WHERE id=?
        """, (transaction_id,))

    create_notification(
        transaction["user_id"],
        "Deposit rejected",
        f"Your ₦{transaction['amount']:,.2f} contribution was rejected.",
        "error",
    )

    flash(
        request,
        "Deposit rejected.",
        "success",
    )

    return RedirectResponse(
        "/admin",
        status_code=303,
    )


# =========================================================
# ADMIN DELETE MEMBER
# =========================================================

@app.post("/admin/member/{user_id}/delete")
def delete_member(
    request: Request,
    user_id: int,
):

    admin = require_admin(request)

    if not admin:

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with get_db() as conn:

        member = conn.execute("""
            SELECT *
            FROM users
            WHERE id=?
              AND role='user'
        """, (user_id,)).fetchone()

        if not member:

            flash(
                request,
                "Member not found.",
                "error",
            )

            return RedirectResponse(
                "/admin",
                status_code=303,
            )

        conn.execute("""
            DELETE FROM transactions
            WHERE user_id=?
        """, (user_id,))

        conn.execute("""
            DELETE FROM notifications
            WHERE user_id=?
        """, (user_id,))

        conn.execute("""
            DELETE FROM users
            WHERE id=?
              AND role='user'
        """, (user_id,))

    flash(
        request,
        "Member deleted successfully.",
        "success",
    )

    return RedirectResponse(
        "/admin",
        status_code=303,
    )


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():

    try:

        with get_db() as conn:

            conn.execute(
                "SELECT 1"
            ).fetchone()

        return {
            "status": "ok",
            "database": "connected",
            "email_verification": "disabled",
            "notifications": "enabled",
        }

    except Exception as exc:

        return {
            "status": "error",
            "database": str(exc),
            "email_verification": "disabled",
            "notifications": "enabled",
        }