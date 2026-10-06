import hashlib
import hmac
import os
import secrets
import sqlite3

from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

from dotenv import load_dotenv

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from starlette.middleware.sessions import SessionMiddleware


# ============================================================
# PATHS / ENVIRONMENT
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "quasar.db"

load_dotenv(BASE_DIR / ".env")


# ============================================================
# CONFIGURATION
# ============================================================

SECRET_KEY = os.getenv("SECRET_KEY")

ADMIN_EMAIL = os.getenv(
    "ADMIN_EMAIL",
    "admin@quasar-opek.com"
)

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")


# Development fallback only.
# For production, SECRET_KEY and ADMIN_PASSWORD
# should always be placed in .env.
if not SECRET_KEY:
    SECRET_KEY = "development-only-quasar-secret-change-me"

if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = "QuasarAdmin123!"


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="QUASAR-OPEK Portal",
    version="1.0.0"
)


# ============================================================
# SESSION SECURITY
# ============================================================

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=60 * 60 * 8,
    same_site="lax",
    https_only=False
)


# ============================================================
# STATIC / TEMPLATES
# ============================================================

app.mount(
    "/static",
    StaticFiles(
        directory=str(BASE_DIR / "static")
    ),
    name="static"
)

templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)


# ============================================================
# DATABASE
# ============================================================

@contextmanager
def db():

    conn = sqlite3.connect(
        DB_PATH,
        timeout=10
    )

    conn.row_factory = sqlite3.Row

    try:

        # Enable foreign keys for this connection.
        conn.execute("PRAGMA foreign_keys = ON")

        yield conn

        conn.commit()

    except Exception:

        conn.rollback()

        raise

    finally:

        conn.close()


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password: str) -> str:

    salt = secrets.token_bytes(16)

    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=64
    )

    return f"{salt.hex()}:{key.hex()}"


def verify_password(
    password: str,
    stored_password: str
) -> bool:

    try:

        salt_hex, key_hex = stored_password.split(":")

        salt = bytes.fromhex(salt_hex)

        stored_key = bytes.fromhex(key_hex)

        new_key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=16384,
            r=8,
            p=1,
            dklen=64
        )

        return hmac.compare_digest(
            new_key,
            stored_key
        )

    except Exception:

        return False


# ============================================================
# TIME
# ============================================================

def now_iso():

    return datetime.now(
        timezone.utc
    ).isoformat(
        timespec="seconds"
    )


# ============================================================
# ACCOUNT MASKING
# ============================================================

def mask_account_number(account_number):

    if not account_number:
        return "Not provided"

    account_number = str(account_number)

    if len(account_number) <= 4:
        return account_number

    return "****" + account_number[-4:]


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    with db() as conn:

        # ====================================================
        # USERS
        # ====================================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                full_name TEXT NOT NULL,

                email TEXT NOT NULL UNIQUE,

                phone TEXT NOT NULL,

                password_hash TEXT NOT NULL,

                bank_name TEXT,

                account_name TEXT,

                account_number TEXT,

                role TEXT NOT NULL DEFAULT 'user',

                status TEXT NOT NULL DEFAULT 'approved',

                registration_fee_status TEXT
                    NOT NULL DEFAULT 'approved',

                weekly_target INTEGER
                    NOT NULL DEFAULT 1000,

                created_at TEXT NOT NULL
            )
        """)

        columns = [
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        ]

        if "weekly_target" not in columns:

            conn.execute("""
                ALTER TABLE users
                ADD COLUMN weekly_target
                INTEGER NOT NULL DEFAULT 1000
            """)

        if "bank_name" not in columns:

            conn.execute("""
                ALTER TABLE users
                ADD COLUMN bank_name TEXT
            """)

        if "account_name" not in columns:

            conn.execute("""
                ALTER TABLE users
                ADD COLUMN account_name TEXT
            """)

        if "account_number" not in columns:

            conn.execute("""
                ALTER TABLE users
                ADD COLUMN account_number TEXT
            """)

        # ====================================================
        # TRANSACTIONS
        # ====================================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                user_id INTEGER NOT NULL,

                kind TEXT NOT NULL,

                amount INTEGER NOT NULL,

                status TEXT NOT NULL DEFAULT 'pending',

                reference TEXT NOT NULL,

                transfer_bank TEXT,

                transfer_account_name TEXT,

                transfer_account_number TEXT,

                created_at TEXT NOT NULL,

                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        transaction_columns = [
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(transactions)"
            ).fetchall()
        ]

        if "transfer_bank" not in transaction_columns:

            conn.execute("""
                ALTER TABLE transactions
                ADD COLUMN transfer_bank TEXT
            """)

        if "transfer_account_name" not in transaction_columns:

            conn.execute("""
                ALTER TABLE transactions
                ADD COLUMN transfer_account_name TEXT
            """)

        if "transfer_account_number" not in transaction_columns:

            conn.execute("""
                ALTER TABLE transactions
                ADD COLUMN transfer_account_number TEXT
            """)

        # ====================================================
        # INDEXES
        # ====================================================

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_users_status
            ON users(status)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_users_role
            ON users(role)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_transactions_user
            ON transactions(user_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_transactions_status
            ON transactions(status)
        """)

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_transactions_reference
            ON transactions(reference)
        """)

        # ====================================================
        # ADMIN
        # ====================================================

        admin = conn.execute(
            """
            SELECT id
            FROM users
            WHERE email=?
            """,
            (ADMIN_EMAIL,)
        ).fetchone()

        if not admin:

            conn.execute("""
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
                    created_at

                )

                VALUES (
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?,
                    ?, ?
                )
            """, (

                "QUASAR-OPEK Administrator",

                ADMIN_EMAIL,

                "00000000000",

                hash_password(
                    ADMIN_PASSWORD
                ),

                None,
                None,
                None,

                "admin",

                "approved",

                "approved",

                1000,

                now_iso()
            ))


init_db()


# ============================================================
# FLASH MESSAGES
# ============================================================

def flash(
    request: Request,
    message: str,
    category: str = "success"
):

    request.session["flash"] = {
        "message": message,
        "category": category
    }


def get_flash(request: Request):

    return request.session.pop(
        "flash",
        None
    )


# ============================================================
# CURRENT USER
# ============================================================

def current_user(request: Request):

    user_id = request.session.get("user_id")

    if not user_id:
        return None

    with db() as conn:

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE id=?
            """,
            (user_id,)
        ).fetchone()

    if not user:

        request.session.clear()

        return None

    return user


# ============================================================
# RENDER
# ============================================================

def render(
    request: Request,
    template_name: str,
    context: dict | None = None
):

    context = context or {}

    context.update({

        "request": request,

        "current_user":
            current_user(request),

        "flash":
            get_flash(request)

    })

    return templates.TemplateResponse(
        template_name,
        context
    )


# ============================================================
# REQUIRE USER
# ============================================================

def require_user(request: Request):

    user = current_user(request)

    if not user:

        flash(
            request,
            "Please log in first.",
            "error"
        )

        return None

    if user["role"] == "admin":

        return user

    if user["status"] != "approved":

        request.session.clear()

        flash(
            request,
            "Your account is waiting for admin approval.",
            "error"
        )

        return None

    return user


# ============================================================
# REQUIRE ADMIN
# ============================================================

def require_admin(request: Request):

    user = current_user(request)

    if not user or user["role"] != "admin":

        flash(
            request,
            "Administrator access required.",
            "error"
        )

        return None

    return user


# ============================================================
# HOME
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
def home(request: Request):

    return render(
        request,
        "index.html"
    )


# ============================================================
# REGISTER PAGE
# ============================================================

@app.get(
    "/register",
    response_class=HTMLResponse
)
def register_page(request: Request):

    return render(
        request,
        "register.html"
    )


# ============================================================
# REGISTER
# ============================================================

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

    registration_transfer_account_name: str = Form(...)

):

    # --------------------------------------------------------
    # CLEAN INPUT
    # --------------------------------------------------------

    full_name = full_name.strip()

    email = email.strip().lower()

    phone = phone.strip()

    bank_name = bank_name.strip()

    account_name = account_name.strip()

    account_number = account_number.strip()

    registration_reference = (
        registration_reference.strip()
    )

    registration_transfer_account_name = (
        registration_transfer_account_name.strip()
    )

    # --------------------------------------------------------
    # REQUIRED FIELDS
    # --------------------------------------------------------

    if not all([

        full_name,
        email,
        phone,

        password,
        confirm_password,

        bank_name,
        account_name,
        account_number,

        registration_reference,
        registration_transfer_account_name

    ]):

        flash(
            request,
            "Please complete all registration and payment fields.",
            "error"
        )

        return RedirectResponse(
            "/register",
            status_code=303
        )

    # --------------------------------------------------------
    # PASSWORD
    # --------------------------------------------------------

    if password != confirm_password:

        flash(
            request,
            "Passwords do not match.",
            "error"
        )

        return RedirectResponse(
            "/register",
            status_code=303
        )

    if len(password) < 8:

        flash(
            request,
            "Password must be at least 8 characters.",
            "error"
        )

        return RedirectResponse(
            "/register",
            status_code=303
        )

    # --------------------------------------------------------
    # EMAIL
    # --------------------------------------------------------

    if "@" not in email or "." not in email.split("@")[-1]:

        flash(
            request,
            "Please enter a valid email address.",
            "error"
        )

        return RedirectResponse(
            "/register",
            status_code=303
        )

    # --------------------------------------------------------
    # ACCOUNT NUMBER
    # --------------------------------------------------------

    if (
        not account_number.isdigit()
        or len(account_number) != 10
    ):

        flash(
            request,
            "Account number must contain exactly 10 digits.",
            "error"
        )

        return RedirectResponse(
            "/register",
            status_code=303
        )

    # --------------------------------------------------------
    # PHONE
    # --------------------------------------------------------

    phone_digits = (
        phone
        .replace("+", "")
        .replace(" ", "")
        .replace("-", "")
    )

    if (
        not phone_digits.isdigit()
        or len(phone_digits) < 10
    ):

        flash(
            request,
            "Please enter a valid phone number.",
            "error"
        )

        return RedirectResponse(
            "/register",
            status_code=303
        )

    # --------------------------------------------------------
    # PAYMENT REFERENCE
    # --------------------------------------------------------

    if len(registration_reference) < 3:

        flash(
            request,
            "Please enter a valid payment transaction reference.",
            "error"
        )

        return RedirectResponse(
            "/register",
            status_code=303
        )

    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    with db() as conn:

        existing = conn.execute(
            """
            SELECT id
            FROM users
            WHERE email=?
            """,
            (email,)
        ).fetchone()

        if existing:

            flash(
                request,
                "An account with that email already exists.",
                "error"
            )

            return RedirectResponse(
                "/login",
                status_code=303
            )

        duplicate_reference = conn.execute(
            """
            SELECT id
            FROM transactions
            WHERE reference=?
            """,
            (registration_reference,)
        ).fetchone()

        if duplicate_reference:

            flash(
                request,
                "That transaction reference has already been used.",
                "error"
            )

            return RedirectResponse(
                "/register",
                status_code=303
            )

        # ----------------------------------------------------
        # CREATE USER
        # ----------------------------------------------------

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
                created_at

            )

            VALUES (
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?,
                ?, ?
            )
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

            now_iso()
        ))

        user_id = cursor.lastrowid

        # ----------------------------------------------------
        # REGISTRATION PAYMENT
        # ----------------------------------------------------

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

            now_iso()
        ))

    flash(
        request,
        "Registration submitted successfully. Your account is waiting for admin approval.",
        "success"
    )

    return RedirectResponse(
        "/login",
        status_code=303
    )


# ============================================================
# LOGIN PAGE
# ============================================================

@app.get(
    "/login",
    response_class=HTMLResponse
)
def login_page(request: Request):

    return render(
        request,
        "login.html"
    )


# ============================================================
# LOGIN
# ============================================================

@app.post("/login")
def login(

    request: Request,

    email: str = Form(...),

    password: str = Form(...)

):

    email = email.strip().lower()

    with db() as conn:

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email=?
            """,
            (email,)
        ).fetchone()

    if not user:

        flash(
            request,
            "Invalid email or password.",
            "error"
        )

        return RedirectResponse(
            "/login",
            status_code=303
        )

    if not verify_password(
        password,
        user["password_hash"]
    ):

        flash(
            request,
            "Invalid email or password.",
            "error"
        )

        return RedirectResponse(
            "/login",
            status_code=303
        )

    # --------------------------------------------------------
    # ADMIN
    # --------------------------------------------------------

    if user["role"] == "admin":

        request.session.clear()

        request.session["user_id"] = user["id"]

        return RedirectResponse(
            "/admin",
            status_code=303
        )

    # --------------------------------------------------------
    # PENDING
    # --------------------------------------------------------

    if user["status"] == "pending":

        flash(
            request,
            "Your account is waiting for admin approval.",
            "error"
        )

        return RedirectResponse(
            "/login",
            status_code=303
        )

    # --------------------------------------------------------
    # REJECTED
    # --------------------------------------------------------

    if user["status"] == "rejected":

        flash(
            request,
            "Your registration was rejected.",
            "error"
        )

        return RedirectResponse(
            "/login",
            status_code=303
        )

    # --------------------------------------------------------
    # APPROVED
    # --------------------------------------------------------

    request.session.clear()

    request.session["user_id"] = user["id"]

    return RedirectResponse(
        "/dashboard",
        status_code=303
    )


# ============================================================
# LOGOUT
# ============================================================

@app.get("/logout")
def logout(request: Request):

    request.session.clear()

    return RedirectResponse(
        "/",
        status_code=303
    )


# ============================================================
# MEMBER DASHBOARD
# ============================================================

@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
def dashboard(request: Request):

    user = require_user(request)

    if not user:

        return RedirectResponse(
            "/login",
            status_code=303
        )

    if user["role"] == "admin":

        return RedirectResponse(
            "/admin",
            status_code=303
        )

    now = datetime.now(timezone.utc)

    monday = (
        now -
        timedelta(days=now.weekday())
    ).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0
    )

    start_of_week_iso = monday.isoformat(
        timespec="seconds"
    )

    with db() as conn:

        approved = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)

            FROM transactions

            WHERE user_id=?

            AND kind='contribution'

            AND status='approved'
        """, (
            user["id"],
        )).fetchone()[0]

        pending = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)

            FROM transactions

            WHERE user_id=?

            AND kind='contribution'

            AND status='pending'
        """, (
            user["id"],
        )).fetchone()[0]

        weekly_approved = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)

            FROM transactions

            WHERE user_id=?

            AND kind='contribution'

            AND status='approved'

            AND created_at >= ?
        """, (
            user["id"],
            start_of_week_iso
        )).fetchone()[0]

        weekly_pending = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)

            FROM transactions

            WHERE user_id=?

            AND kind='contribution'

            AND status='pending'

            AND created_at >= ?
        """, (
            user["id"],
            start_of_week_iso
        )).fetchone()[0]

        transactions = conn.execute("""
            SELECT *

            FROM transactions

            WHERE user_id=?

            ORDER BY id DESC
        """, (
            user["id"],
        )).fetchall()

    target = user["weekly_target"] or 1000

    if target > 0:

        progress = min(
            100,
            round(
                weekly_approved
                / target
                * 100
            )
        )

    else:

        progress = 0

    remaining = max(
        0,
        target - weekly_approved
    )

    return render(
        request,
        "dashboard.html",
        {

            "user": user,

            "approved": approved,

            "pending": pending,

            "weekly_approved":
                weekly_approved,

            "weekly_pending":
                weekly_pending,

            "target": target,

            "progress": progress,

            "remaining": remaining,

            "transactions":
                transactions,

            "masked_account":
                mask_account_number(
                    user["account_number"]
                )
        }
    )


# ============================================================
# MEMBER PROFILE
# ============================================================

@app.get(
    "/profile",
    response_class=HTMLResponse
)
def profile(request: Request):

    user = require_user(request)

    if not user:

        return RedirectResponse(
            "/login",
            status_code=303
        )

    return render(
        request,
        "profile.html",
        {
            "user": user,

            "masked_account":
                mask_account_number(
                    user["account_number"]
                )
        }
    )


# ============================================================
# MEMBER CONTRIBUTION
# ============================================================

@app.post("/deposit")
def deposit(

    request: Request,

    amount: int = Form(...),

    transfer_bank: str = Form(...),

    transfer_account_name: str = Form(...),

    transfer_account_number: str = Form(...),

    reference: str = Form(...)

):

    user = require_user(request)

    if not user:

        return RedirectResponse(
            "/login",
            status_code=303
        )

    transfer_bank = transfer_bank.strip()

    transfer_account_name = (
        transfer_account_name.strip()
    )

    transfer_account_number = (
        transfer_account_number.strip()
    )

    reference = reference.strip()

    if amount < 1000:

        flash(
            request,
            "Minimum contribution is ₦1,000.",
            "error"
        )

        return RedirectResponse(
            "/dashboard",
            status_code=303
        )

    if not all([
        transfer_bank,
        transfer_account_name,
        transfer_account_number,
        reference
    ]):

        flash(
            request,
            "Please complete all transfer details.",
            "error"
        )

        return RedirectResponse(
            "/dashboard",
            status_code=303
        )

    if (
        not transfer_account_number.isdigit()
        or len(transfer_account_number) != 10
    ):

        flash(
            request,
            "Transfer account number must contain exactly 10 digits.",
            "error"
        )

        return RedirectResponse(
            "/dashboard",
            status_code=303
        )

    if len(reference) < 3:

        flash(
            request,
            "Please enter a valid transaction reference.",
            "error"
        )

        return RedirectResponse(
            "/dashboard",
            status_code=303
        )

    with db() as conn:

        duplicate = conn.execute("""
            SELECT id
            FROM transactions
            WHERE reference=?
        """, (
            reference,
        )).fetchone()

        if duplicate:

            flash(
                request,
                "That transaction reference has already been submitted.",
                "error"
            )

            return RedirectResponse(
                "/dashboard",
                status_code=303
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

            now_iso()

        ))

    flash(
        request,
        "Contribution submitted successfully. It is waiting for admin approval.",
        "success"
    )

    return RedirectResponse(
        "/dashboard",
        status_code=303
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.get(
    "/admin",
    response_class=HTMLResponse
)
def admin_dashboard(

    request: Request,

    search: str = "",

    status: str = "all"

):

    admin = require_admin(request)

    if not admin:

        return RedirectResponse(
            "/login",
            status_code=303
        )

    search = search.strip()

    if status not in (
        "all",
        "pending",
        "approved",
        "rejected"
    ):

        status = "all"

    now = datetime.now(timezone.utc)

    monday = (
        now -
        timedelta(days=now.weekday())
    ).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0
    )

    start_of_week_iso = monday.isoformat(
        timespec="seconds"
    )

    with db() as conn:

        # ----------------------------------------------------
        # PENDING REGISTRATIONS
        # ----------------------------------------------------

        pending_reg = conn.execute("""
            SELECT
                users.*,

                transactions.id AS transaction_id,

                transactions.amount
                    AS registration_amount,

                transactions.reference
                    AS transaction_reference,

                transactions.transfer_account_name
                    AS registration_transfer_account_name

            FROM users

            LEFT JOIN transactions

                ON users.id =
                    transactions.user_id

                AND transactions.kind =
                    'registration_fee'

            WHERE users.role='user'

            AND users.status='pending'

            ORDER BY users.id DESC

        """).fetchall()

        # ----------------------------------------------------
        # MEMBER SEARCH
        # ----------------------------------------------------

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

            term = f"%{search}%"

            params.extend([
                term,
                term,
                term
            ])

        if status != "all":

            query += """
                AND status=?
            """

            params.append(status)

        query += """
            ORDER BY id DESC
        """

        member_rows = conn.execute(
            query,
            params
        ).fetchall()

        member_progress = []

        for user in member_rows:

            weekly = conn.execute("""
                SELECT COALESCE(
                    SUM(amount),
                    0
                )

                FROM transactions

                WHERE user_id=?

                AND kind='contribution'

                AND status='approved'

                AND created_at >= ?

            """, (
                user["id"],
                start_of_week_iso
            )).fetchone()[0]

            target = (
                user["weekly_target"]
                or 1000
            )

            if target > 0:

                progress = min(
                    100,
                    round(
                        weekly
                        / target
                        * 100
                    )
                )

            else:

                progress = 0

            member_progress.append({

                "id":
                    user["id"],

                "full_name":
                    user["full_name"],

                "email":
                    user["email"],

                "phone":
                    user["phone"],

                "bank_name":
                    user["bank_name"],

                "account_name":
                    user["account_name"],

                "account_number":
                    user["account_number"],

                "masked_account":
                    mask_account_number(
                        user["account_number"]
                    ),

                "status":
                    user["status"],

                "registration_fee_status":
                    user["registration_fee_status"],

                "created_at":
                    user["created_at"],

                "weekly_target":
                    target,

                "weekly_approved":
                    weekly,

                "progress":
                    progress

            })

        # ----------------------------------------------------
        # MEMBER COUNTS
        # ----------------------------------------------------

        members = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role='user'
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

        pending_members = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role='user'
            AND status='pending'
        """).fetchone()[0]

        # ----------------------------------------------------
        # PENDING CONTRIBUTIONS
        # ----------------------------------------------------

        pending_deposits = conn.execute("""
            SELECT COUNT(*)
            FROM transactions
            WHERE kind='contribution'
            AND status='pending'
        """).fetchone()[0]

        # ----------------------------------------------------
        # APPROVED CONTRIBUTIONS
        # ----------------------------------------------------

        approved_total = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE kind='contribution'
            AND status='approved'
        """).fetchone()[0]

        # ----------------------------------------------------
        # PENDING CONTRIBUTION AMOUNT
        # ----------------------------------------------------

        pending_total = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions
            WHERE kind='contribution'
            AND status='pending'
        """).fetchone()[0]

        # ----------------------------------------------------
        # ALL CONTRIBUTIONS
        # ----------------------------------------------------

        deposits = conn.execute("""
            SELECT

                transactions.*,

                users.full_name,

                users.email

            FROM transactions

            JOIN users
                ON users.id =
                    transactions.user_id

            WHERE transactions.kind=
                'contribution'

            ORDER BY transactions.id DESC

        """).fetchall()

    return render(
        request,
        "admin.html",
        {

            "user":
                admin,

            "members":
                members,

            "approved_members":
                approved_members,

            "rejected_members":
                rejected_members,

            "pending_members":
                pending_members,

            "pending_deposits":
                pending_deposits,

            "approved_total":
                approved_total,

            "pending_total":
                pending_total,

            "registrations":
                member_progress,

            "deposits":
                deposits,

            "search":
                search,

            "status":
                status

        }
    )


# ============================================================
# ADMIN MEMBER PROFILE
# ============================================================

@app.get(
    "/admin/member/{user_id}",
    response_class=HTMLResponse
)
def admin_member_profile(

    request: Request,

    user_id: int

):

    admin = require_admin(request)

    if not admin:

        return RedirectResponse(
            "/login",
            status_code=303
        )

    with db() as conn:

        member = conn.execute("""
            SELECT *

            FROM users

            WHERE id=?

            AND role='user'

        """, (
            user_id,
        )).fetchone()

        if not member:

            flash(
                request,
                "Member not found.",
                "error"
            )

            return RedirectResponse(
                "/admin",
                status_code=303
            )

        transactions = conn.execute("""
            SELECT *

            FROM transactions

            WHERE user_id=?

            ORDER BY id DESC

        """, (
            user_id,
        )).fetchall()

    return render(
        request,
        "member_profile.html",
        {

            "member":
                member,

            "transactions":
                transactions,

            "masked_account":
                mask_account_number(
                    member["account_number"]
                ),

            "admin":
                admin

        }
    )


# ============================================================
# ADMIN APPROVE / REJECT MEMBER
# ============================================================

@app.post(
    "/admin/user/{user_id}/{action}"
)
def admin_user_action(

    request: Request,

    user_id: int,

    action: str

):

    admin = require_admin(request)

    if not admin:

        return RedirectResponse(
            "/login",
            status_code=303
        )

    if action not in (
        "approve",
        "reject"
    ):

        flash(
            request,
            "Invalid action.",
            "error"
        )

        return RedirectResponse(
            "/admin",
            status_code=303
        )

    new_status = (
        "approved"
        if action == "approve"
        else "rejected"
    )

    with db() as conn:

        user = conn.execute("""
            SELECT *

            FROM users

            WHERE id=?

            AND role != 'admin'

        """, (
            user_id,
        )).fetchone()

        if not user:

            flash(
                request,
                "Member not found.",
                "error"
            )

            return RedirectResponse(
                "/admin",
                status_code=303
            )

        conn.execute("""
            UPDATE users

            SET status=?

            WHERE id=?

            AND role != 'admin'

        """, (
            new_status,
            user_id
        ))

        if action == "approve":

            conn.execute("""
                UPDATE transactions

                SET status='approved'

                WHERE user_id=?

                AND kind='registration_fee'

                AND status='pending'

            """, (
                user_id,
            ))

            conn.execute("""
                UPDATE users

                SET registration_fee_status=
                    'approved'

                WHERE id=?

            """, (
                user_id,
            ))

            message = (
                f"{user['full_name']} "
                "has been approved."
            )

        else:

            conn.execute("""
                UPDATE users

                SET registration_fee_status=
                    'rejected'

                WHERE id=?

            """, (
                user_id,
            ))

            conn.execute("""
                UPDATE transactions

                SET status='rejected'

                WHERE user_id=?

                AND kind='registration_fee'

                AND status='pending'

            """, (
                user_id,
            ))

            message = (
                f"{user['full_name']} "
                "has been rejected."
            )

    flash(
        request,
        message,
        "success"
    )

    return RedirectResponse(
        "/admin",
        status_code=303
    )


# ============================================================
# ADMIN APPROVE / REJECT CONTRIBUTION
# ============================================================

@app.post(
    "/admin/deposit/{tx_id}/{action}"
)
def admin_deposit_action(

    request: Request,

    tx_id: int,

    action: str

):

    admin = require_admin(request)

    if not admin:

        return RedirectResponse(
            "/login",
            status_code=303
        )

    if action not in (
        "approve",
        "reject"
    ):

        flash(
            request,
            "Invalid action.",
            "error"
        )

        return RedirectResponse(
            "/admin",
            status_code=303
        )

    new_status = (
        "approved"
        if action == "approve"
        else "rejected"
    )

    with db() as conn:

        transaction = conn.execute("""
            SELECT *

            FROM transactions

            WHERE id=?

            AND kind='contribution'

        """, (
            tx_id,
        )).fetchone()

        if not transaction:

            flash(
                request,
                "Contribution not found.",
                "error"
            )

            return RedirectResponse(
                "/admin",
                status_code=303
            )

        # Prevent changing an already finalized
        # contribution.

        if transaction["status"] != "pending":

            flash(
                request,
                "This contribution has already been processed.",
                "error"
            )

            return RedirectResponse(
                "/admin",
                status_code=303
            )

        conn.execute("""
            UPDATE transactions

            SET status=?

            WHERE id=?

            AND kind='contribution'

        """, (
            new_status,
            tx_id
        ))

    if action == "approve":

        flash(
            request,
            "Contribution approved successfully.",
            "success"
        )

    else:

        flash(
            request,
            "Contribution rejected.",
            "success"
        )

    return RedirectResponse(
        "/admin",
        status_code=303
    )


# ============================================================
# ADMIN DELETE MEMBER
# ============================================================

@app.post(
    "/admin/user/{user_id}/delete"
)
def delete_user(

    request: Request,

    user_id: int

):

    admin = require_admin(request)

    if not admin:

        return RedirectResponse(
            "/login",
            status_code=303
        )

    with db() as conn:

        member = conn.execute("""
            SELECT

                id,
                full_name,
                email,
                role

            FROM users

            WHERE id=?

        """, (
            user_id,
        )).fetchone()

        if not member:

            flash(
                request,
                "Member not found.",
                "error"
            )

            return RedirectResponse(
                "/admin",
                status_code=303
            )

        # NEVER delete an administrator.

        if member["role"] == "admin":

            flash(
                request,
                "The administrator account cannot be deleted.",
                "error"
            )

            return RedirectResponse(
                "/admin",
                status_code=303
            )

        # Delete transactions first.
        # This works with both old and new
        # SQLite foreign-key configurations.

        conn.execute("""
            DELETE FROM transactions

            WHERE user_id=?

        """, (
            user_id,
        ))

        result = conn.execute("""
            DELETE FROM users

            WHERE id=?

            AND role != 'admin'

        """, (
            user_id,
        ))

        if result.rowcount == 0:

            flash(
                request,
                "Member could not be deleted.",
                "error"
            )

            return RedirectResponse(
                "/admin",
                status_code=303
            )

        deleted_name = member["full_name"]

    flash(
        request,
        f"{deleted_name} has been deleted successfully.",
        "success"
    )

    return RedirectResponse(
        "/admin",
        status_code=303
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    try:

        with db() as conn:

            conn.execute(
                "SELECT 1"
            ).fetchone()

        return {
            "status": "ok",
            "database": "connected"
        }

    except Exception:

        return {
            "status": "error",
            "database": "unavailable"
        }