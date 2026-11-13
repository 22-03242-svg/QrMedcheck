import argparse
import base64
import bcrypt
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("QR_MEDCHECK_DATABASE", ROOT / "qr_medcheck_demo.sqlite3"))
MAX_REQUEST_BYTES = 16_384
PASSWORD_ITERATIONS = 310_000
SESSION_COOKIE_NAME = "qrmedcheck_session"
SESSION_HOURS = 12
JWT_ALGORITHM = "HS256"
VALID_SUBSCRIPTION_PLANS = {"Starter", "Growth", "Enterprise"}
VALID_PAYMENT_METHODS = {"GCash", "Maya", "Credit / Debit Card", "Bank Transfer / OTC"}
STAFF_ROLES = {
    "Nurse",
    "Pharmacist",
    "Administrator",
    "Physician",
    "Head Nurse / Nursing Supervisor",
}
CLINICAL_ROLES = {"Nurse", "Pharmacist", "Physician", "Head Nurse / Nursing Supervisor"}
SCHEDULING_ROLES = {"Nurse", "Physician", "Head Nurse / Nursing Supervisor"}
AUDIT_ROLES = {"Administrator", "Nurse", "Pharmacist", "Physician", "Head Nurse / Nursing Supervisor"}
DEMO_MEDICATIONS = (
    ("MED-101", "Amoxicillin 500mg", "LOT-88291", "2027-12-31", "Antibiotic", "Oral Capsule", 120, 10),
    ("MED-102", "Lisinopril 10mg", "LOT-99102", "2028-05-15", "ACE Inhibitor", "Oral Tablet", 54, 10),
    ("MED-103", "Insulin Regular 100U", "LOT-11029", "2026-12-15", "Antidiabetic", "Subcutaneous Injection", 8, 10),
    ("MED-104", "Metoprolol 50mg", "LOT-44120", "2028-01-10", "Beta Blocker", "Oral Tablet", 0, 10),
    ("MED-999", "EXPIRED Heparin 5000U", "LOT-EXPIRED", "2023-01-01", "Anticoagulant", "IV Injection", 18, 10),
)
STATIC_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/manifest.webmanifest": "manifest.webmanifest",
    "/app-icon.svg": "app-icon.svg",
    "/qr-medcheck-logo.png": "qr-medcheck-logo.png",
    "/service-worker.js": "service-worker.js",
}


def connect_database():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def bcrypt_password_input(password):
    return hashlib.sha256(password.encode("utf-8")).digest()


def hash_password(password):
    return bcrypt.hashpw(bcrypt_password_input(password), bcrypt.gensalt()).decode("ascii")


def verify_password(password, encoded_hash):
    try:
        if encoded_hash.startswith(("$2a$", "$2b$", "$2y$")):
            return bcrypt.checkpw(bcrypt_password_input(password), encoded_hash.encode("ascii"))
        algorithm, iterations, salt_hex, expected_hex = encoded_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        ).hex()
    except (AttributeError, ValueError, TypeError, UnicodeEncodeError):
        return False
    return hmac.compare_digest(actual, expected_hex)


def get_jwt_secret(connection):
    configured_secret = os.environ.get("QR_MEDCHECK_JWT_SECRET")
    if configured_secret:
        return configured_secret.encode("utf-8")
    row = connection.execute(
        "SELECT value FROM auth_settings WHERE key = 'jwt_secret'"
    ).fetchone()
    if row is None:
        secret = secrets.token_urlsafe(48)
        connection.execute(
            "INSERT INTO auth_settings (key, value) VALUES ('jwt_secret', ?)",
            (secret,),
        )
        return secret.encode("utf-8")
    return row["value"].encode("utf-8")


def encode_jwt(connection, user_id, issued_at, expires_at):
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    payload = {
        "sub": str(user_id),
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    encode = lambda value: base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    signing_input = f"{encode(header)}.{encode(payload)}"
    signature = hmac.new(
        get_jwt_secret(connection), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{signing_input}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')}"


def verify_jwt(connection, token):
    try:
        header_part, payload_part, signature_part = token.split(".")
        decode = lambda value: base64.urlsafe_b64decode(
            value + "=" * (-len(value) % 4)
        )
        header = json.loads(decode(header_part))
        payload = json.loads(decode(payload_part))
        if header != {"alg": JWT_ALGORITHM, "typ": "JWT"}:
            return None
        signing_input = f"{header_part}.{payload_part}".encode("ascii")
        expected = hmac.new(
            get_jwt_secret(connection), signing_input, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, decode(signature_part)):
            return None
        if (not isinstance(payload, dict)
                or not isinstance(payload.get("sub"), str)
                or not payload["sub"].isdigit()
                or not isinstance(payload.get("iat"), int)
                or not isinstance(payload.get("exp"), int)
                or payload["exp"] <= int(datetime.now(timezone.utc).timestamp())):
            return None
        return payload
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def can_manage_clinic_subscription(user):
    return (
        user["role"] == "Administrator"
        and user["department"].strip().casefold() == "it administration"
    )


def clinic_registration_available(connection):
    return connection.execute(
        "SELECT 1 FROM staff_accounts "
        "WHERE role = 'Administrator' AND TRIM(department) = 'IT Administration' COLLATE NOCASE "
        "AND password_hash IS NOT NULL AND password_hash != '' LIMIT 1"
    ).fetchone() is None


def restore_demo_administrator():
    email = "alex.admin@example.test"
    password = getpass.getpass("New administrator password (8+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 8 or len(password) > 256:
        raise ValueError("Password must be between 8 and 256 characters.")
    if password != confirmation:
        raise ValueError("The passwords do not match.")

    with connect_database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        admin = connection.execute(
            "SELECT id, role FROM staff_accounts WHERE email = ? COLLATE NOCASE",
            (email,),
        ).fetchone()
        if admin is not None and admin["role"] != "Administrator":
            raise ValueError(
                f"{email} already belongs to a non-Administrator staff account; no changes were made."
            )
        if admin is None:
            cursor = connection.execute(
                """INSERT INTO staff_accounts
                   (name, email, role, department, created_at, password_hash)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    "Yesha",
                    email,
                    "Administrator",
                    "IT Administration",
                    datetime.now(timezone.utc).isoformat(),
                    hash_password(password),
                ),
            )
            admin_id = cursor.lastrowid
        else:
            admin_id = admin["id"]
            connection.execute(
                "UPDATE staff_accounts SET password_hash = ? WHERE id = ?",
                (hash_password(password), admin_id),
            )
        connection.execute("DELETE FROM user_sessions WHERE user_id = ?", (admin_id,))
    print(f"Administrator account restored and password set for {email}.")


def public_user(row):
    user = {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "role": row["role"],
        "department": row["department"],
    }
    if "clinic_name" in row.keys():
        user["clinicName"] = row["clinic_name"]
    return user


def initialize_database():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    with connect_database() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS patients (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                room TEXT NOT NULL,
                allergies TEXT NOT NULL,
                sex TEXT NOT NULL DEFAULT 'Not specified',
                age INTEGER,
                dob TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )"""
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(patients)")}
        if "sex" not in columns:
            connection.execute("ALTER TABLE patients ADD COLUMN sex TEXT NOT NULL DEFAULT 'Not specified'")
        if "age" not in columns:
            connection.execute("ALTER TABLE patients ADD COLUMN age INTEGER")
        if "dob" not in columns:
            connection.execute("ALTER TABLE patients ADD COLUMN dob TEXT NOT NULL DEFAULT ''")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS deleted_patients (
                id TEXT PRIMARY KEY,
                deleted_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS staff_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                role TEXT NOT NULL,
                department TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                password_hash TEXT
            )"""
        )
        staff_columns = {row[1] for row in connection.execute("PRAGMA table_info(staff_accounts)")}
        if "department" not in staff_columns:
            connection.execute("ALTER TABLE staff_accounts ADD COLUMN department TEXT NOT NULL DEFAULT ''")
        if "password_hash" not in staff_columns:
            connection.execute("ALTER TABLE staff_accounts ADD COLUMN password_hash TEXT")
        staff_count = connection.execute("SELECT COUNT(*) FROM staff_accounts").fetchone()[0]
        if staff_count == 0:
            added_at = datetime.now(timezone.utc).isoformat()
            demo_profiles = (
                ("Ylona Leigh", "ylona.leigh@example.test", "Nurse", "Ward 4B"),
                ("Eli", "eli.pharmacist@example.test", "Pharmacist", "Pharmacy"),
                ("Yesha", "yesha.admin@example.test", "Administrator", "IT Administration"),
                ("Dr. Ashley Manapat", "ashleymanapat@example.test", "Physician", "Medical Department"),
                ("Taylor", "taylor.supervisor@example.test", "Head Nurse / Nursing Supervisor", "Ward 4B"),
            )
            connection.executemany(
                "INSERT INTO staff_accounts (name, email, role, department, created_at) VALUES (?, ?, ?, ?, ?)",
                [(name, email, role, department, added_at) for name, email, role, department in demo_profiles],
            )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS medications (
                id TEXT PRIMARY KEY COLLATE NOCASE,
                name TEXT NOT NULL,
                batch TEXT NOT NULL,
                exp TEXT NOT NULL,
                category TEXT NOT NULL,
                route TEXT NOT NULL,
                stock INTEGER NOT NULL,
                low_stock_threshold INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS deleted_medications (
                id TEXT PRIMARY KEY COLLATE NOCASE,
                deleted_at TEXT NOT NULL
            )"""
        )
        if connection.execute("SELECT COUNT(*) FROM medications").fetchone()[0] == 0:
            created_at = datetime.now(timezone.utc).isoformat()
            connection.executemany(
                "INSERT INTO medications "
                "(id, name, batch, exp, category, route, stock, low_stock_threshold, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(*medication, created_at) for medication in DEMO_MEDICATIONS],
            )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id TEXT NOT NULL,
                patient_name TEXT NOT NULL,
                patient_phone TEXT NOT NULL DEFAULT '',
                appointment_at TEXT NOT NULL,
                visit_type TEXT NOT NULL,
                assigned_staff TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )"""
        )
        appointment_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(appointments)")
        }
        if "patient_phone" not in appointment_columns:
            connection.execute(
                "ALTER TABLE appointments ADD COLUMN patient_phone TEXT NOT NULL DEFAULT ''"
            )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS user_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES staff_accounts(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                plan TEXT
            )"""
        )
        session_columns = {row[1] for row in connection.execute("PRAGMA table_info(user_sessions)")}
        if "plan" not in session_columns:
            connection.execute("ALTER TABLE user_sessions ADD COLUMN plan TEXT")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS clinic_subscription (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                plan TEXT CHECK (plan IS NULL OR plan IN ('Starter', 'Growth', 'Enterprise')),
                payment_method TEXT NOT NULL DEFAULT ''
            )"""
        )
        subscription_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(clinic_subscription)")
        }
        if "payment_method" not in subscription_columns:
            connection.execute(
                "ALTER TABLE clinic_subscription ADD COLUMN payment_method TEXT NOT NULL DEFAULT ''"
            )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS clinic_profile (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                name TEXT NOT NULL,
                contact_number TEXT NOT NULL DEFAULT '',
                preferred_plan TEXT CHECK (
                    preferred_plan IS NULL OR preferred_plan IN ('Starter', 'Growth', 'Enterprise')
                ),
                owner_user_id INTEGER REFERENCES staff_accounts(id) ON DELETE SET NULL
            )"""
        )
        clinic_columns = {row[1] for row in connection.execute("PRAGMA table_info(clinic_profile)")}
        if "owner_user_id" not in clinic_columns:
            connection.execute(
                "ALTER TABLE clinic_profile ADD COLUMN owner_user_id INTEGER REFERENCES staff_accounts(id) ON DELETE SET NULL"
            )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS auth_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )"""
        )
        connection.execute(
            "INSERT OR IGNORE INTO auth_settings (key, value) VALUES ('jwt_secret', ?)",
            (secrets.token_urlsafe(48),),
        )
        connection.execute(
            "INSERT OR IGNORE INTO clinic_subscription (id, plan) VALUES (1, NULL)"
        )
        clinic_plan = connection.execute(
            "SELECT plan FROM clinic_subscription WHERE id = 1"
        ).fetchone()["plan"]
        if clinic_plan is None:
            legacy_plan = connection.execute(
                "SELECT plan FROM user_sessions "
                "WHERE plan IN ('Starter', 'Growth', 'Enterprise') "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            if legacy_plan:
                connection.execute(
                    "UPDATE clinic_subscription SET plan = ? WHERE id = 1",
                    (legacy_plan["plan"],),
                )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS prescriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id TEXT NOT NULL,
                medication_id TEXT NOT NULL,
                medication_name TEXT NOT NULL,
                strength TEXT NOT NULL,
                dosage TEXT NOT NULL,
                route TEXT NOT NULL,
                frequency TEXT NOT NULL,
                duration_days INTEGER NOT NULL CHECK(duration_days > 0),
                quantity REAL NOT NULL CHECK(quantity > 0),
                quantity_unit TEXT NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL DEFAULT '',
                instructions TEXT NOT NULL DEFAULT '',
                clinical_notes TEXT NOT NULL DEFAULT '',
                prescription_date TEXT NOT NULL,
                prescriber_id INTEGER NOT NULL REFERENCES staff_accounts(id) ON DELETE RESTRICT,
                status TEXT NOT NULL CHECK(status IN ('Draft', 'Active', 'Discontinued', 'Cancelled')),
                safety_warnings TEXT NOT NULL DEFAULT '[]',
                missing_data TEXT NOT NULL DEFAULT '[]',
                status_reason TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        prescription_columns = {row[1] for row in connection.execute("PRAGMA table_info(prescriptions)")}
        if "safety_warnings" not in prescription_columns:
            connection.execute("ALTER TABLE prescriptions ADD COLUMN safety_warnings TEXT NOT NULL DEFAULT '[]'")
        if "missing_data" not in prescription_columns:
            connection.execute("ALTER TABLE prescriptions ADD COLUMN missing_data TEXT NOT NULL DEFAULT '[]'")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_prescriptions_patient_status "
            "ON prescriptions(patient_id, status)"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_user_id INTEGER NOT NULL,
                actor_name TEXT NOT NULL,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            )"""
        )


def validate_staff_profile(name, email, role, department):
    if not name or len(name) > 120:
        return "Enter a staff name up to 120 characters."
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 254:
        return "Enter a valid email address."
    if role not in STAFF_ROLES:
        return "Select a valid staff role."
    if not department or len(department) > 120:
        return "Enter a department or work unit up to 120 characters."
    return None


def calculate_age(dob):
    if not dob:
        return None
    birth_date = datetime.strptime(dob, "%Y-%m-%d").date()
    today = datetime.now(timezone.utc).date()
    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
    return age if 0 <= age <= 130 else None


def add_audit_event(connection, user, action, entity_type, entity_id, details=None):
    connection.execute(
        "INSERT INTO audit_events "
        "(actor_user_id, actor_name, action, entity_type, entity_id, details, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user["id"],
            user["name"],
            action,
            entity_type,
            str(entity_id),
            json.dumps(details or {}, ensure_ascii=False),
            datetime.now(timezone.utc).isoformat(),
        ),
    )


def valid_iso_date(value, required=False):
    if not value:
        return not required
    try:
        return datetime.strptime(value, "%Y-%m-%d").strftime("%Y-%m-%d") == value
    except ValueError:
        return False


def active_order_for_patient(connection, patient_id):
    row = connection.execute(
        "SELECT medication_id, medication_name, dosage, route, frequency "
        "FROM prescriptions WHERE patient_id = ? AND status = 'Active' "
        "ORDER BY updated_at DESC, id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()
    if row is None:
        return {
            "drugId": "",
            "drugName": "No active medication order",
            "dose": "Not assigned",
            "frequency": "Not scheduled",
        }
    return {
        "drugId": row["medication_id"],
        "drugName": row["medication_name"],
        "dose": row["dosage"],
        "frequency": row["frequency"],
        "route": row["route"],
    }


def prescription_row_to_dict(row):
    result = dict(row)
    result["warnings"] = json.loads(result.pop("warnings_json"))
    result["missingData"] = json.loads(result.pop("missing_data_json"))
    return result


def get_lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 80))
            address = probe.getsockname()[0]
            if ipaddress.ip_address(address).is_private:
                return address
    except OSError:
        pass

    for result in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
        address = result[4][0]
        if ipaddress.ip_address(address).is_private and not address.startswith("127."):
            return address
    return None


class QRMedCheckHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def translate_path(self, path):
        filename = STATIC_FILES.get(urlparse(path).path)
        return str(ROOT / filename) if filename else str(ROOT / "__not_found__")

    def send_json(self, status, payload, headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self):
        request_size = int(self.headers.get("Content-Length", "0"))
        if request_size < 1 or request_size > MAX_REQUEST_BYTES:
            raise ValueError("Request size is invalid.")
        payload = json.loads(self.rfile.read(request_size))
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        return payload

    def request_session_token(self):
        authorization = self.headers.get("Authorization", "")
        if authorization.startswith("Bearer "):
            return authorization[7:].strip()
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            morsel = cookie.get(SESSION_COOKIE_NAME)
        except (ValueError, TypeError):
            morsel = None
        return morsel.value if morsel else ""

    def load_authenticated_user(self):
        token = self.request_session_token()
        if not token:
            return None
        now = datetime.now(timezone.utc).isoformat()
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with connect_database() as connection:
            claims = verify_jwt(connection, token)
            row = connection.execute(
                "SELECT s.expires_at, c.plan, u.id, u.name, u.email, u.role, u.department, "
                "p.name AS clinic_name "
                "FROM user_sessions s JOIN staff_accounts u ON u.id = s.user_id "
                "LEFT JOIN clinic_subscription c ON c.id = 1 "
                "LEFT JOIN clinic_profile p ON p.id = 1 "
                "WHERE s.token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            if claims is not None and claims["sub"] != str(row["id"]):
                return None
            if row["expires_at"] <= now:
                connection.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_hash,))
                return None
        return row

    def validate_request_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        origin_host = urlparse(origin).netloc.lower()
        request_host = self.headers.get("Host", "").lower()
        return bool(origin_host and request_host and origin_host == request_host)

    def authenticate_request(self, method, endpoint, require_subscription=True):
        self.authenticated_user = self.load_authenticated_user()
        if self.authenticated_user is None:
            self.send_json(401, {"error": "Sign in to continue."})
            return False
        if method in {"POST", "PUT", "DELETE"} and not self.validate_request_origin():
            self.send_json(403, {"error": "Request origin is not allowed."})
            return False
        if require_subscription and not self.authenticated_user["plan"]:
            self.send_json(402, {"error": "Choose and activate a Demo Mode subscription tier before using QR MedCheck features."})
            return False

        role = self.authenticated_user["role"]
        if method == "GET":
            if endpoint.startswith("/api/staff"):
                allowed = role == "Administrator"
            elif endpoint.startswith(("/api/patients", "/api/medications", "/api/prescriptions")):
                allowed = role in CLINICAL_ROLES
            elif endpoint.startswith("/api/appointments"):
                allowed = role in SCHEDULING_ROLES
            elif endpoint == "/api/audit-events":
                allowed = role in AUDIT_ROLES
            else:
                allowed = True
        elif method in {"POST", "PUT", "DELETE"}:
            if endpoint.startswith("/api/staff"):
                allowed = role == "Administrator"
            elif endpoint.startswith("/api/prescriptions"):
                allowed = role == "Physician"
            elif endpoint.startswith("/api/medications"):
                allowed = role == "Pharmacist" or (role == "Physician" and method == "POST" and endpoint == "/api/medications")
            elif endpoint.startswith("/api/patients"):
                allowed = (
                    role == "Head Nurse / Nursing Supervisor"
                    if method == "DELETE"
                    else role in {"Nurse", "Head Nurse / Nursing Supervisor"}
                )
            elif endpoint.startswith("/api/appointments"):
                allowed = role in SCHEDULING_ROLES
            elif endpoint == "/api/audit-events":
                allowed = role in CLINICAL_ROLES
            else:
                allowed = True
        else:
            allowed = True
        if not allowed:
            self.send_json(403, {"error": "Your signed-in role is not permitted to perform this action."})
            return False
        return True

    def create_session(self, user_id, plan=None):
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=SESSION_HOURS)
        with connect_database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            token = encode_jwt(connection, user_id, now, expires_at)
            connection.execute(
                "INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at, plan) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    hashlib.sha256(token.encode("utf-8")).hexdigest(),
                    user_id,
                    now.isoformat(),
                    expires_at.isoformat(),
                    plan,
                ),
            )
        return token, expires_at

    def set_session_cookie(self, token, expires_at):
        max_age = max(0, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
        return {
            "Set-Cookie": (
                f"{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; "
                f"Max-Age={max_age}"
            )
        }

    def clear_session_cookie(self):
        return {
            "Set-Cookie": (
                f"{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            )
        }

    def login(self):
        if not self.validate_request_origin():
            self.send_json(403, {"error": "Request origin is not allowed."})
            return
        try:
            payload = self.read_json_body()
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error) or "Invalid sign-in request."})
            return
        email = str(payload.get("email", "")).strip().casefold()
        password = payload.get("password", "")
        if not email or not isinstance(password, str):
            self.send_json(400, {"error": "Enter your email address and password."})
            return
        if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            self.send_json(400, {"error": "Enter a valid email address."})
            return
        if len(password) < 8 or len(password) > 256:
            self.send_json(400, {"error": "Password must be between 8 and 256 characters."})
            return
        try:
            with connect_database() as connection:
                row = connection.execute(
                    "SELECT u.id, u.name, u.email, u.role, u.department, u.password_hash, "
                    "COALESCE((SELECT p.name FROM clinic_profile p WHERE p.owner_user_id = u.id), "
                    "(SELECT p.name FROM clinic_profile p WHERE p.id = 1)) AS clinic_name "
                    "FROM staff_accounts u "
                    "WHERE u.email = ? COLLATE NOCASE",
                    (email,),
                ).fetchone()
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not check the staff account."})
            return
        if (row is None or row["role"] not in STAFF_ROLES or not row["password_hash"]
                or not verify_password(password, row["password_hash"])):
            self.send_json(401, {"error": "Invalid email or password."})
            return
        try:
            with connect_database() as connection:
                subscription = connection.execute(
                    "SELECT c.plan, c.payment_method, p.name AS clinic_name "
                    "FROM clinic_subscription c LEFT JOIN clinic_profile p ON p.id = 1 "
                    "WHERE c.id = 1"
                ).fetchone()
                clinic_plan = subscription["plan"]
                clinic_name = subscription["clinic_name"]
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not check the clinic subscription plan."})
            return
        if not can_manage_clinic_subscription(row) and not clinic_plan:
            self.send_json(
                402,
                {"error": "Your clinic's IT Administrator must choose a Demo Mode plan before staff can sign in."},
            )
            return
        try:
            if row["password_hash"].startswith("pbkdf2_sha256$"):
                with connect_database() as connection:
                    connection.execute(
                        "UPDATE staff_accounts SET password_hash = ? WHERE id = ?",
                        (hash_password(password), row["id"]),
                    )
            token, expires_at = self.create_session(row["id"], clinic_plan)
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not start a sign-in session."})
            return
        self.send_json(200, {
            "user": public_user(row),
            "expiresAt": expires_at.isoformat(),
            "plan": clinic_plan,
            "activePlan": clinic_plan,
            "clinic": {"name": clinic_name} if clinic_name else None,
            "token": token,
            "roleLabel": f"{row['role']} · {row['department']}",
        }, headers=self.set_session_cookie(token, expires_at))

    def register_clinic_administrator(self):
        if not self.validate_request_origin():
            self.send_json(403, {"error": "Request origin is not allowed."})
            return
        try:
            payload = self.read_json_body()
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error) or "Invalid account request."})
            return

        name_value = payload.get("name")
        clinic_name_value = payload.get("clinicName")
        email_value = payload.get("email")
        contact_number_value = payload.get("contactNumber", "")
        if not isinstance(name_value, str) or not isinstance(clinic_name_value, str) or not isinstance(email_value, str):
            self.send_json(400, {"error": "Name, clinic name, and email must be text values."})
            return
        if not isinstance(contact_number_value, str):
            self.send_json(400, {"error": "Contact number must be text."})
            return
        name = name_value.strip()
        clinic_name = clinic_name_value.strip()
        email = email_value.strip().casefold()
        password = payload.get("password", "")
        password_confirmation = payload.get("passwordConfirmation", "")
        contact_number = contact_number_value.strip()
        selected_plan = payload.get("plan", payload.get("preferredPlan"))
        payment_method = payload.get("paymentMethod")
        if not name or len(name) > 120:
            self.send_json(400, {"error": "Enter your name (up to 120 characters)."})
            return
        if not clinic_name or len(clinic_name) > 160:
            self.send_json(400, {"error": "Enter your clinic, medical center, or hospital name (up to 160 characters)."})
            return
        if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            self.send_json(400, {"error": "Enter a valid email address."})
            return
        if not isinstance(password, str) or len(password) < 8 or len(password) > 256:
            self.send_json(400, {"error": "Password must be between 8 and 256 characters."})
            return
        if password_confirmation is not None and (
            not isinstance(password_confirmation, str) or password_confirmation != password
        ):
            self.send_json(400, {"error": "Confirm password must match the password."})
            return
        if len(contact_number) > 40 or (contact_number and not re.fullmatch(r"[0-9+() .-]+", contact_number)):
            self.send_json(400, {"error": "Enter a valid contact number up to 40 characters, or leave it blank."})
            return
        if selected_plan == "later":
            selected_plan = None
        if selected_plan is not None and (
            not isinstance(selected_plan, str) or selected_plan not in VALID_SUBSCRIPTION_PLANS
        ):
            self.send_json(400, {"error": "Select a valid subscription plan or choose to select one later."})
            return
        if payment_method is None:
            payment_method = ""
        if not isinstance(payment_method, str) or (
            payment_method and payment_method not in VALID_PAYMENT_METHODS
        ):
            self.send_json(400, {"error": "Select a valid payment method."})
            return
        if payment_method and selected_plan is None:
            self.send_json(400, {"error": "Choose a subscription plan before continuing checkout."})
            return
        active_plan = selected_plan if payment_method else None

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=SESSION_HOURS)
        password_hash = hash_password(password)
        try:
            with connect_database() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing_account = connection.execute(
                    "SELECT 1 FROM staff_accounts WHERE email = ? COLLATE NOCASE LIMIT 1",
                    (email,),
                ).fetchone()
                if existing_account is not None:
                    self.send_json(409, {"error": "An account with that email address already exists."})
                    return
                if not clinic_registration_available(connection) and not payment_method:
                    self.send_json(
                        409,
                        {"error": "Clinic setup is already complete. Ask your clinic administrator to create a staff account."},
                    )
                    return
                if payment_method:
                    connection.execute(
                        "DELETE FROM user_sessions WHERE user_id IN ("
                        "SELECT id FROM staff_accounts "
                        "WHERE role = 'Administrator' "
                        "AND TRIM(department) = 'IT Administration' COLLATE NOCASE)"
                    )
                    connection.execute(
                        "UPDATE staff_accounts SET password_hash = NULL, "
                        "department = 'Previous IT Administration' "
                        "WHERE role = 'Administrator' "
                        "AND TRIM(department) = 'IT Administration' COLLATE NOCASE"
                    )
                cursor = connection.execute(
                    "INSERT INTO staff_accounts "
                    "(name, email, role, department, created_at, password_hash) "
                    "VALUES (?, ?, 'Administrator', 'IT Administration', ?, ?)",
                    (name, email, now.isoformat(), password_hash),
                )
                user_id = cursor.lastrowid
                connection.execute(
                    "INSERT INTO clinic_profile "
                    "(id, name, contact_number, preferred_plan, owner_user_id) "
                    "VALUES (1, ?, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET name = excluded.name, "
                    "contact_number = excluded.contact_number, "
                    "preferred_plan = excluded.preferred_plan, owner_user_id = excluded.owner_user_id",
                    (clinic_name, contact_number, selected_plan, user_id),
                )
                connection.execute(
                    "UPDATE clinic_subscription SET plan = ?, payment_method = ? WHERE id = 1",
                    (active_plan, payment_method),
                )
                user = connection.execute(
                    "SELECT u.id, u.name, u.email, u.role, u.department, p.name AS clinic_name "
                    "FROM staff_accounts u LEFT JOIN clinic_profile p ON p.owner_user_id = u.id "
                    "WHERE u.id = ?",
                    (user_id,),
                ).fetchone()
                add_audit_event(
                    connection,
                    user,
                    "clinic.administrator_registered",
                    "clinic_profile",
                    user_id,
                    {
                        "clinicName": clinic_name,
                        "contactNumberProvided": bool(contact_number),
                        "preferredPlan": selected_plan,
                        "plan": active_plan,
                        "paymentMethod": payment_method,
                        "subscriptionActivated": active_plan is not None,
                        "role": "Administrator",
                        "department": "IT Administration",
                    },
                )
                token = encode_jwt(connection, user_id, now, expires_at)
                connection.execute(
                    "INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at, plan) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        hashlib.sha256(token.encode("utf-8")).hexdigest(),
                        user_id,
                        now.isoformat(),
                        expires_at.isoformat(),
                        active_plan,
                    ),
                )
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "An account with that email address already exists."})
            return
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not create the clinic administrator account."})
            return

        self.send_json(
            201,
            {
                "user": public_user(user),
                "expiresAt": expires_at.isoformat(),
                "plan": active_plan,
                "activePlan": active_plan,
                "preferredPlan": selected_plan if active_plan is None and selected_plan else "",
                "clinic": {"name": clinic_name},
                "paymentMethod": payment_method,
                "token": token,
                "roleLabel": "Administrator · IT Administration",
            },
            headers=self.set_session_cookie(token, expires_at),
        )

    def activate_subscription(self):
        if not can_manage_clinic_subscription(self.authenticated_user):
            self.send_json(403, {"error": "Only the IT Administrator can choose or change the clinic plan."})
            return
        try:
            payload = self.read_json_body()
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error) or "Invalid subscription selection."})
            return
        plan = payload.get("plan")
        payment_method = payload.get("paymentMethod", "")
        if not isinstance(plan, str) or plan not in VALID_SUBSCRIPTION_PLANS:
            self.send_json(400, {"error": "Choose a valid subscription tier."})
            return
        if not isinstance(payment_method, str) or (
            payment_method and payment_method not in VALID_PAYMENT_METHODS
        ):
            self.send_json(400, {"error": "Select a valid payment method."})
            return
        try:
            with connect_database() as connection:
                connection.execute(
                    "UPDATE clinic_subscription SET plan = ?, payment_method = ? WHERE id = 1",
                    (plan, payment_method),
                )
                connection.execute(
                    "UPDATE clinic_profile SET preferred_plan = ? WHERE id = 1",
                    (plan,),
                )
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not activate the Demo Mode subscription tier."})
            return
        self.send_json(200, {"plan": plan, "demoMode": True, "paymentProcessed": False})

    def logout(self):
        if not self.validate_request_origin():
            self.send_json(403, {"error": "Request origin is not allowed."})
            return
        token = self.request_session_token()
        if token:
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            with connect_database() as connection:
                connection.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_hash,))
        self.send_json(200, {"signedOut": True}, headers=self.clear_session_cookie())

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self.send_json(200, {"status": "ok"})
            return

        if parsed.path == "/api/config":
            request_host = self.headers.get("Host", "").strip()
            host_name = request_host.rsplit(":", 1)[0].strip("[]") if ":" in request_host else request_host
            lan_ip = get_lan_ip()
            if host_name in ("localhost", "127.0.0.1", "::1"):
                if lan_ip:
                    mobile_base_url = f"http://{lan_ip}:{self.server.server_port}"
                else:
                    mobile_base_url = f"http://localhost:{self.server.server_port}"
            else:
                forwarded_proto = self.headers.get("X-Forwarded-Proto", "http").split(",", 1)[0].strip().lower()
                protocol = forwarded_proto if forwarded_proto in {"http", "https"} else "http"
                mobile_base_url = f"{protocol}://{request_host or 'localhost'}"
            self.send_json(200, {"mobileBaseUrl": mobile_base_url})
            return

        if parsed.path == "/api/auth/me":
            self.authenticated_user = self.load_authenticated_user()
            if self.authenticated_user is None:
                self.send_json(200, {"authenticated": False})
                return
            self.send_json(200, {
                "authenticated": True,
                "user": public_user(self.authenticated_user),
                "plan": self.authenticated_user["plan"],
            })
            return

        if parsed.path == "/api/auth/registration-status":
            try:
                with connect_database() as connection:
                    first_setup_available = clinic_registration_available(connection)
            except sqlite3.Error:
                self.send_json(500, {"error": "Could not check clinic setup availability."})
                return
            self.send_json(200, {
                "available": True,
                "firstSetupAvailable": first_setup_available,
                "demoTakeover": True,
            })
            return

        public_qr_record = (
            re.fullmatch(r"/api/patients/[A-Za-z0-9_-]{1,64}", parsed.path)
            or re.fullmatch(r"/api/medications/[A-Za-z0-9_-]{1,64}", parsed.path)
        )
        if parsed.path.startswith("/api/"):
            if public_qr_record:
                self.authenticated_user = self.load_authenticated_user()
            elif not self.authenticate_request("GET", parsed.path):
                return

        if parsed.path == "/api/staff":
            with connect_database() as connection:
                rows = connection.execute(
                    "SELECT id, name, email, role, department, created_at "
                    "FROM staff_accounts ORDER BY name COLLATE NOCASE"
                ).fetchall()
            self.send_json(200, [dict(row) for row in rows])
            return

        if parsed.path == "/api/medications":
            with connect_database() as connection:
                rows = connection.execute(
                    "SELECT id, name, batch, exp, category, route, stock, low_stock_threshold "
                    "FROM medications ORDER BY name COLLATE NOCASE"
                ).fetchall()
            self.send_json(200, [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "batch": row["batch"],
                    "exp": row["exp"],
                    "category": row["category"],
                    "route": row["route"],
                    "stock": row["stock"],
                    "lowStockThreshold": row["low_stock_threshold"],
                }
                for row in rows
            ])
            return

        if parsed.path == "/api/medications/deleted":
            with connect_database() as connection:
                rows = connection.execute("SELECT id FROM deleted_medications").fetchall()
            self.send_json(200, [row["id"] for row in rows])
            return

        if parsed.path == "/api/appointments":
            with connect_database() as connection:
                rows = connection.execute(
                    "SELECT id, patient_id, patient_name, patient_phone, appointment_at, visit_type, "
                    "assigned_staff, status, notes "
                    "FROM appointments ORDER BY appointment_at"
                ).fetchall()
            self.send_json(200, [
                {
                    "id": row["id"],
                    "patientId": row["patient_id"],
                    "patientName": row["patient_name"],
                    "patientPhone": row["patient_phone"],
                    "appointmentAt": row["appointment_at"],
                    "visitType": row["visit_type"],
                    "assignedStaff": row["assigned_staff"],
                    "status": row["status"],
                    "notes": row["notes"],
                }
                for row in rows
            ])
            return

        if parsed.path == "/api/prescriptions":
            self.list_prescriptions(parse_qs(parsed.query))
            return

        if re.fullmatch(r"/api/prescriptions/[1-9][0-9]*", parsed.path):
            self.get_prescription(parsed.path.rsplit("/", 1)[1])
            return

        if parsed.path == "/api/audit-events":
            user = self.authenticated_user
            if user["role"] == "Administrator":
                audit_filter = ""
                audit_params = ()
            elif user["role"] in {"Nurse", "Head Nurse / Nursing Supervisor"}:
                audit_filter = (
                    "WHERE actor_user_id IN "
                    "(SELECT id FROM staff_accounts WHERE department = ? COLLATE NOCASE)"
                )
                audit_params = (user["department"],)
            else:
                audit_filter = "WHERE actor_user_id = ?"
                audit_params = (user["id"],)
            with connect_database() as connection:
                rows = connection.execute(
                    "SELECT id, actor_user_id, actor_name, action, entity_type, entity_id, details, created_at "
                    f"FROM audit_events {audit_filter} ORDER BY id DESC LIMIT 500",
                    audit_params,
                ).fetchall()
            self.send_json(200, [{
                "id": row["id"],
                "actorUserId": row["actor_user_id"],
                "actorName": row["actor_name"],
                "action": row["action"],
                "entityType": row["entity_type"],
                "entityId": row["entity_id"],
                "details": json.loads(row["details"]),
                "createdAt": row["created_at"],
            } for row in rows])
            return

        if parsed.path == "/api/patients":
            with connect_database() as connection:
                rows = connection.execute(
                    "SELECT id, name, room, allergies, sex, age, dob FROM patients ORDER BY name COLLATE NOCASE"
                ).fetchall()
                patients = [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "room": row["room"],
                    "allergies": json.loads(row["allergies"]),
                    "sex": row["sex"] or "Not specified",
                    "age": row["age"],
                    "dob": row["dob"] or "Not provided",
                    "order": active_order_for_patient(connection, row["id"]),
                }
                for row in rows
                ]
            self.send_json(200, patients)
            return

        if parsed.path == "/api/patients/deleted":
            with connect_database() as connection:
                rows = connection.execute("SELECT id FROM deleted_patients").fetchall()
            self.send_json(200, [row["id"] for row in rows])
            return

        if parsed.path.startswith("/api/patients/"):
            patient_id = unquote(parsed.path.removeprefix("/api/patients/"))
            with connect_database() as connection:
                deleted = connection.execute(
                    "SELECT 1 FROM deleted_patients WHERE id = ?", (patient_id,)
                ).fetchone()
                if deleted:
                    self.send_json(410, {"error": "Patient record has been deleted."})
                    return
                row = connection.execute(
                    "SELECT id, name, room, allergies, sex, age, dob FROM patients WHERE id = ?",
                    (patient_id,),
                ).fetchone()
            if row is None:
                self.send_json(404, {"error": "Patient record not found."})
                return
            self.send_json(200, {
                "id": row["id"],
                "name": row["name"],
                "room": row["room"],
                "allergies": json.loads(row["allergies"]),
                "sex": row["sex"] or "Not specified",
                "age": row["age"],
                "dob": row["dob"] or "Not provided",
                "order": active_order_for_patient(connection, row["id"]),
            })
            return

        super().do_GET()

    def do_POST(self):
        endpoint = urlparse(self.path).path
        if endpoint == "/api/auth/login":
            self.login()
            return
        if endpoint == "/api/auth/register":
            self.register_clinic_administrator()
            return
        if endpoint == "/api/auth/logout":
            self.logout()
            return
        if endpoint == "/api/subscription/activate":
            if not self.authenticate_request("POST", endpoint, require_subscription=False):
                return
            self.activate_subscription()
            return
        if endpoint.startswith("/api/") and not self.authenticate_request("POST", endpoint):
            return
        if re.fullmatch(r"/api/staff/[1-9][0-9]*/password", endpoint):
            self.set_staff_password(endpoint)
            return
        if endpoint == "/api/staff":
            self.create_staff_account()
            return
        if endpoint == "/api/prescriptions":
            self.create_prescription()
            return
        if endpoint.startswith("/api/prescriptions/") and endpoint.endswith("/status"):
            self.change_prescription_status(endpoint)
            return
        if endpoint == "/api/audit-events":
            self.record_audit_event()
            return
        if endpoint == "/api/appointments":
            self.create_appointment()
            return
        if endpoint.startswith("/api/appointments/") and endpoint.endswith("/status"):
            self.update_appointment_status(endpoint)
            return
        if endpoint == "/api/medications":
            self.create_medication()
            return
        if endpoint.startswith("/api/medications/") and endpoint.endswith("/stock"):
            self.update_medication_stock(endpoint)
            return
        if endpoint != "/api/patients":
            self.send_json(404, {"error": "Endpoint not found."})
            return

        try:
            request_size = int(self.headers.get("Content-Length", "0"))
            if request_size < 1 or request_size > MAX_REQUEST_BYTES:
                self.send_json(413, {"error": "Request size is invalid."})
                return
            payload = json.loads(self.rfile.read(request_size))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON request."})
            return

        patient_id = str(payload.get("id", "")).strip()
        name = str(payload.get("name", "")).strip()
        room = str(payload.get("room", "")).strip()
        sex = str(payload.get("sex", "Not specified")).strip() or "Not specified"
        dob = str(payload.get("dob", "")).strip()
        allergies = payload.get("allergies", [])
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", patient_id):
            self.send_json(400, {"error": "Patient ID must use letters, numbers, hyphens, or underscores."})
            return
        if not name or len(name) > 120 or not room or len(room) > 120:
            self.send_json(400, {"error": "Patient name and room are required and must be 120 characters or fewer."})
            return
        if sex not in {"Not specified", "Female", "Male", "Intersex", "Other", "Prefer not to say"}:
            self.send_json(400, {"error": "Select a valid sex option."})
            return
        try:
            age = calculate_age(dob)
        except ValueError:
            self.send_json(400, {"error": "Date of birth must be a valid date in YYYY-MM-DD format."})
            return
        if dob and age is None:
            self.send_json(400, {"error": "Date of birth must not be in the future and must be within a valid age range."})
            return
        if not isinstance(allergies, list) or len(allergies) > 20 or any(not isinstance(item, str) or len(item) > 120 for item in allergies):
            self.send_json(400, {"error": "Allergies must be a list of up to 20 short text values."})
            return

        try:
            with connect_database() as connection:
                connection.execute(
                    "INSERT INTO patients (id, name, room, allergies, sex, age, dob, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET name=excluded.name, room=excluded.room, "
                    "allergies=excluded.allergies, sex=excluded.sex, age=excluded.age, dob=excluded.dob, "
                    "created_at=excluded.created_at",
                    (patient_id, name, room, json.dumps(allergies), sex, age, dob, datetime.now(timezone.utc).isoformat()),
                )
                connection.execute("DELETE FROM deleted_patients WHERE id = ?", (patient_id,))
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not save the patient record."})
            return

        self.send_json(201, {"id": patient_id, "saved": True})

    def create_appointment(self):
        try:
            request_size = int(self.headers.get("Content-Length", "0"))
            if request_size < 1 or request_size > MAX_REQUEST_BYTES:
                self.send_json(413, {"error": "Request size is invalid."})
                return
            payload = json.loads(self.rfile.read(request_size))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON request."})
            return
        if not isinstance(payload, dict):
            self.send_json(400, {"error": "Appointment details must be a JSON object."})
            return

        patient_id = str(payload.get("patientId", "")).strip()
        patient_name = str(payload.get("patientName", "")).strip()
        patient_phone = str(payload.get("patientPhone", "")).strip()
        appointment_at = str(payload.get("appointmentAt", "")).strip()
        visit_type = str(payload.get("visitType", "")).strip()
        assigned_staff = str(payload.get("assignedStaff", "")).strip()
        status = str(payload.get("status", "")).strip()
        notes = str(payload.get("notes", "")).strip()

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", patient_id):
            self.send_json(400, {"error": "Select a valid patient."})
            return
        if not patient_name or len(patient_name) > 120:
            self.send_json(400, {"error": "Patient name is required and must be 120 characters or fewer."})
            return
        phone_digits = re.sub(r"\D", "", patient_phone)
        if patient_phone and (
            len(patient_phone) > 30
            or not re.fullmatch(r"[0-9+().\s-]+", patient_phone)
            or not 7 <= len(phone_digits) <= 15
        ):
            self.send_json(400, {"error": "Enter a valid patient phone number with 7 to 15 digits."})
            return
        try:
            valid_appointment_time = datetime.strptime(appointment_at, "%Y-%m-%dT%H:%M").strftime("%Y-%m-%dT%H:%M") == appointment_at
        except ValueError:
            valid_appointment_time = False
        if not valid_appointment_time:
            self.send_json(400, {"error": "Enter a valid appointment date and time."})
            return
        if not visit_type or len(visit_type) > 120:
            self.send_json(400, {"error": "Visit or procedure is required and must be 120 characters or fewer."})
            return
        if len(assigned_staff) > 120 or len(notes) > 500:
            self.send_json(400, {"error": "Assigned staff must be 120 characters or fewer and notes 500 characters or fewer."})
            return
        if status not in {"Scheduled", "Completed", "Cancelled"}:
            self.send_json(400, {"error": "Select a valid appointment status."})
            return

        created_at = datetime.now(timezone.utc).isoformat()
        try:
            with connect_database() as connection:
                cursor = connection.execute(
                    "INSERT INTO appointments "
                    "(patient_id, patient_name, patient_phone, appointment_at, visit_type, "
                    "assigned_staff, status, notes, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        patient_id, patient_name, patient_phone, appointment_at, visit_type,
                        assigned_staff, status, notes, created_at,
                    ),
                )
                appointment_id = cursor.lastrowid
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not save the patient appointment."})
            return

        self.send_json(201, {
            "id": appointment_id,
            "patientId": patient_id,
            "patientName": patient_name,
            "patientPhone": patient_phone,
            "appointmentAt": appointment_at,
            "visitType": visit_type,
            "assignedStaff": assigned_staff,
            "status": status,
            "notes": notes,
        })

    def update_appointment_status(self, endpoint):
        appointment_id = endpoint.removeprefix("/api/appointments/").removesuffix("/status").strip("/")
        if not re.fullmatch(r"[1-9][0-9]*", appointment_id):
            self.send_json(400, {"error": "Invalid appointment ID."})
            return
        try:
            request_size = int(self.headers.get("Content-Length", "0"))
            if request_size < 1 or request_size > MAX_REQUEST_BYTES:
                self.send_json(413, {"error": "Request size is invalid."})
                return
            payload = json.loads(self.rfile.read(request_size))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON request."})
            return
        if not isinstance(payload, dict):
            self.send_json(400, {"error": "Appointment status must be a JSON object."})
            return

        status = str(payload.get("status", "")).strip()
        if status not in {"Scheduled", "Completed", "Cancelled"}:
            self.send_json(400, {"error": "Select a valid appointment status."})
            return
        try:
            with connect_database() as connection:
                cursor = connection.execute(
                    "UPDATE appointments SET status = ? WHERE id = ?",
                    (status, int(appointment_id)),
                )
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not update the appointment status."})
            return
        if cursor.rowcount == 0:
            self.send_json(404, {"error": "Appointment not found."})
            return
        self.send_json(200, {"id": int(appointment_id), "status": status, "updated": True})

    def create_medication(self):
        try:
            request_size = int(self.headers.get("Content-Length", "0"))
            if request_size < 1 or request_size > MAX_REQUEST_BYTES:
                self.send_json(413, {"error": "Request size is invalid."})
                return
            payload = json.loads(self.rfile.read(request_size))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON request."})
            return
        if not isinstance(payload, dict):
            self.send_json(400, {"error": "Medication details must be a JSON object."})
            return

        medication_id = str(payload.get("id", "")).strip()
        name = str(payload.get("name", "")).strip()
        batch = str(payload.get("batch", "")).strip()
        expiration = str(payload.get("exp", "")).strip()
        category = str(payload.get("category", "")).strip()
        route = str(payload.get("route", "")).strip()
        stock = payload.get("stock")
        low_stock_threshold = payload.get("lowStockThreshold")

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", medication_id):
            self.send_json(400, {"error": "Medication ID must use letters, numbers, hyphens, or underscores."})
            return
        fields = {
            "Medication name": (name, 120),
            "Batch / lot": (batch, 120),
            "Category": (category, 80),
            "Route / dosage form": (route, 120),
        }
        for label, (value, max_length) in fields.items():
            if not value or len(value) > max_length:
                self.send_json(400, {"error": f"{label} is required and must be {max_length} characters or fewer."})
                return
        try:
            valid_expiration = datetime.strptime(expiration, "%Y-%m-%d").date().isoformat() == expiration
        except ValueError:
            valid_expiration = False
        if not valid_expiration:
            self.send_json(400, {"error": "Enter a valid expiration date."})
            return
        if type(stock) is not int or stock < 0 or stock > 2_147_483_647:
            self.send_json(400, {"error": "Stock quantity must be a whole number from 0 to 2,147,483,647."})
            return
        if type(low_stock_threshold) is not int or low_stock_threshold < 0 or low_stock_threshold > 2_147_483_647:
            self.send_json(400, {"error": "Low-stock threshold must be a whole number from 0 to 2,147,483,647."})
            return
        if self.authenticated_user["role"] == "Physician" and (stock != 0 or low_stock_threshold != 0):
            self.send_json(403, {"error": "Physicians can add medication records with stock set to 0; Pharmacists manage stock levels."})
            return

        created_at = datetime.now(timezone.utc).isoformat()
        try:
            with connect_database() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO medications "
                    "(id, name, batch, exp, category, route, stock, low_stock_threshold, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (medication_id, name, batch, expiration, category, route, stock, low_stock_threshold, created_at),
                )
                connection.execute("DELETE FROM deleted_medications WHERE id = ?", (medication_id,))
                add_audit_event(
                    connection,
                    self.authenticated_user,
                    "medication.created",
                    "medication",
                    medication_id,
                    {
                        "name": name,
                        "category": category,
                        "createdByRole": self.authenticated_user["role"],
                    },
                )
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "A medication with that ID already exists."})
            return
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not save the medication record."})
            return

        self.send_json(201, {
            "id": medication_id,
            "name": name,
            "batch": batch,
            "exp": expiration,
            "category": category,
            "route": route,
            "stock": stock,
            "lowStockThreshold": low_stock_threshold,
            "created_at": created_at,
        })

    def update_medication_stock(self, endpoint):
        medication_id = unquote(endpoint.removeprefix("/api/medications/").removesuffix("/stock"))
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", medication_id):
            self.send_json(400, {"error": "Invalid medication ID."})
            return
        try:
            request_size = int(self.headers.get("Content-Length", "0"))
            if request_size < 1 or request_size > MAX_REQUEST_BYTES:
                self.send_json(413, {"error": "Request size is invalid."})
                return
            payload = json.loads(self.rfile.read(request_size))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON request."})
            return
        if not isinstance(payload, dict):
            self.send_json(400, {"error": "Stock details must be a JSON object."})
            return

        stock = payload.get("stock")
        if type(stock) is not int or stock < 0 or stock > 2_147_483_647:
            self.send_json(400, {"error": "Stock quantity must be a whole number from 0 to 2,147,483,647."})
            return
        try:
            with connect_database() as connection:
                cursor = connection.execute(
                    "UPDATE medications SET stock = ? WHERE id = ?",
                    (stock, medication_id),
                )
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not update medication stock."})
            return
        if cursor.rowcount == 0:
            self.send_json(404, {"error": "Medication record not found."})
            return
        self.send_json(200, {"id": medication_id, "stock": stock, "updated": True})

    def create_staff_account(self):
        try:
            request_size = int(self.headers.get("Content-Length", "0"))
            if request_size < 1 or request_size > MAX_REQUEST_BYTES:
                self.send_json(413, {"error": "Request size is invalid."})
                return
            payload = json.loads(self.rfile.read(request_size))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON request."})
            return

        if not isinstance(payload, dict):
            self.send_json(400, {"error": "Staff details must be a JSON object."})
            return

        name = str(payload.get("name", "")).strip()
        email = str(payload.get("email", "")).strip().casefold()
        role = str(payload.get("role", "")).strip()
        department = str(payload.get("department", "")).strip()
        plan = str(payload.get("plan", "")).strip()
        seat_limits = {"Starter": 5, "Growth": 15, "Enterprise": 50}
        validation_error = validate_staff_profile(name, email, role, department)
        if validation_error:
            self.send_json(400, {"error": validation_error})
            return
        if plan not in seat_limits:
            self.send_json(400, {"error": "Choose a subscription plan before adding staff."})
            return

        try:
            with connect_database() as connection:
                connection.execute("BEGIN IMMEDIATE")
                count = connection.execute("SELECT COUNT(*) FROM staff_accounts").fetchone()[0]
                if count >= seat_limits[plan]:
                    self.send_json(409, {"error": f"{plan} allows up to {seat_limits[plan]} staff accounts."})
                    return
                cursor = connection.execute(
                    "INSERT INTO staff_accounts (name, email, role, department, created_at) VALUES (?, ?, ?, ?, ?)",
                    (name, email, role, department, datetime.now(timezone.utc).isoformat()),
                )
                row = connection.execute(
                    "SELECT id, name, email, role, department, created_at FROM staff_accounts WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "A staff profile with that email already exists."})
            return
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not save the staff profile."})
            return

        self.send_json(201, dict(row))

    def set_staff_password(self, endpoint):
        staff_id = int(endpoint.removeprefix("/api/staff/").removesuffix("/password"))
        try:
            payload = self.read_json_body()
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error) or "Invalid password request."})
            return
        password = payload.get("password", "")
        if not isinstance(password, str) or len(password) < 8 or len(password) > 256:
            self.send_json(400, {"error": "Password must be between 8 and 256 characters."})
            return
        try:
            with connect_database() as connection:
                connection.execute("BEGIN IMMEDIATE")
                target = connection.execute(
                    "SELECT id, email FROM staff_accounts WHERE id = ?", (staff_id,)
                ).fetchone()
                if target is None:
                    self.send_json(404, {"error": "Staff profile not found."})
                    return
                connection.execute(
                    "UPDATE staff_accounts SET password_hash = ? WHERE id = ?",
                    (hash_password(password), staff_id),
                )
                connection.execute("DELETE FROM user_sessions WHERE user_id = ?", (staff_id,))
                add_audit_event(
                    connection, self.authenticated_user, "staff.password_set", "staff_account", staff_id,
                    {"email": target["email"]},
                )
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not set the staff password."})
            return
        self.send_json(200, {"id": staff_id, "passwordSet": True})

    def do_PUT(self):
        endpoint = urlparse(self.path).path
        if endpoint.startswith("/api/") and not self.authenticate_request("PUT", endpoint):
            return
        if re.fullmatch(r"/api/prescriptions/[1-9][0-9]*", endpoint):
            self.update_prescription(endpoint.rsplit("/", 1)[1])
            return
        if not endpoint.startswith("/api/staff/"):
            self.send_json(404, {"error": "Endpoint not found."})
            return
        staff_id = endpoint.removeprefix("/api/staff/")
        if not re.fullmatch(r"[1-9][0-9]*", staff_id):
            self.send_json(400, {"error": "Invalid staff ID."})
            return
        try:
            request_size = int(self.headers.get("Content-Length", "0"))
            if request_size < 1 or request_size > MAX_REQUEST_BYTES:
                self.send_json(413, {"error": "Request size is invalid."})
                return
            payload = json.loads(self.rfile.read(request_size))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON request."})
            return
        if not isinstance(payload, dict):
            self.send_json(400, {"error": "Staff details must be a JSON object."})
            return

        name = str(payload.get("name", "")).strip()
        email = str(payload.get("email", "")).strip().casefold()
        role = str(payload.get("role", "")).strip()
        department = str(payload.get("department", "")).strip()
        validation_error = validate_staff_profile(name, email, role, department)
        if validation_error:
            self.send_json(400, {"error": validation_error})
            return

        try:
            with connect_database() as connection:
                cursor = connection.execute(
                    "UPDATE staff_accounts SET name = ?, email = ?, role = ?, department = ? WHERE id = ?",
                    (name, email, role, department, int(staff_id)),
                )
                if cursor.rowcount == 0:
                    self.send_json(404, {"error": "Staff profile not found."})
                    return
                row = connection.execute(
                    "SELECT id, name, email, role, department, created_at FROM staff_accounts WHERE id = ?",
                    (int(staff_id),),
                ).fetchone()
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "A staff profile with that email already exists."})
            return
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not update the staff profile."})
            return

        self.send_json(200, dict(row))

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/") and not self.authenticate_request("DELETE", parsed.path):
            return
        if parsed.path.startswith("/api/appointments/"):
            appointment_id = parsed.path.removeprefix("/api/appointments/")
            if not re.fullmatch(r"[1-9][0-9]*", appointment_id):
                self.send_json(400, {"error": "Invalid appointment ID."})
                return
            try:
                with connect_database() as connection:
                    cursor = connection.execute("DELETE FROM appointments WHERE id = ?", (int(appointment_id),))
            except sqlite3.Error:
                self.send_json(500, {"error": "Could not delete the patient appointment."})
                return
            if cursor.rowcount == 0:
                self.send_json(404, {"error": "Appointment not found."})
                return
            self.send_json(200, {"id": int(appointment_id), "deleted": True})
            return
        if parsed.path.startswith("/api/medications/"):
            medication_id = unquote(parsed.path.removeprefix("/api/medications/"))
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", medication_id):
                self.send_json(400, {"error": "Invalid medication ID."})
                return
            try:
                with connect_database() as connection:
                    connection.execute("DELETE FROM medications WHERE id = ?", (medication_id,))
                    connection.execute(
                        "INSERT INTO deleted_medications (id, deleted_at) VALUES (?, ?) "
                        "ON CONFLICT(id) DO UPDATE SET deleted_at=excluded.deleted_at",
                        (medication_id, datetime.now(timezone.utc).isoformat()),
                    )
            except sqlite3.Error:
                self.send_json(500, {"error": "Could not delete the medication record."})
                return
            self.send_json(200, {"id": medication_id, "deleted": True})
            return
        if parsed.path.startswith("/api/staff/"):
            try:
                staff_id = int(parsed.path.removeprefix("/api/staff/"))
            except ValueError:
                self.send_json(400, {"error": "Invalid staff ID."})
                return
            try:
                with connect_database() as connection:
                    if staff_id == self.authenticated_user["id"]:
                        self.send_json(409, {"error": "Sign in with another administrator before deleting this account."})
                        return
                    cursor = connection.execute("DELETE FROM staff_accounts WHERE id = ?", (staff_id,))
            except sqlite3.IntegrityError:
                self.send_json(409, {"error": "This staff member is linked to prescription history and cannot be deleted."})
                return
            except sqlite3.Error:
                self.send_json(500, {"error": "Could not delete the staff profile."})
                return
            if cursor.rowcount == 0:
                self.send_json(404, {"error": "Staff profile not found."})
                return
            self.send_json(200, {"id": staff_id, "deleted": True})
            return
        if not parsed.path.startswith("/api/patients/"):
            self.send_json(404, {"error": "Endpoint not found."})
            return

        patient_id = unquote(parsed.path.removeprefix("/api/patients/"))
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", patient_id):
            self.send_json(400, {"error": "Invalid patient ID."})
            return

        try:
            with connect_database() as connection:
                connection.execute("DELETE FROM patients WHERE id = ?", (patient_id,))
                connection.execute(
                    "INSERT INTO deleted_patients (id, deleted_at) VALUES (?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET deleted_at=excluded.deleted_at",
                    (patient_id, datetime.now(timezone.utc).isoformat()),
                )
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not delete the patient record."})
            return

        self.send_json(200, {"id": patient_id, "deleted": True})

    def record_audit_event(self):
        try:
            payload = self.read_json_body()
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error) or "Invalid JSON request."})
            return
        event_type = str(payload.get("eventType", "")).strip()
        status = str(payload.get("status", "")).strip()
        patient = str(payload.get("patient", "")).strip()[:160]
        medication = str(payload.get("medication", "")).strip()[:160]
        detail = str(payload.get("detail", "")).strip()
        if event_type not in {
            "Verification attempt", "Medication alert", "Patient record deletion", "Inventory change"
        }:
            self.send_json(400, {"error": "Select a valid audit event type."})
            return
        permitted_events = {
            "Nurse": {"Verification attempt", "Medication alert"},
            "Head Nurse / Nursing Supervisor": {
                "Verification attempt", "Medication alert", "Patient record deletion"
            },
            "Pharmacist": {"Inventory change", "Medication alert"},
            "Physician": {"Medication alert"},
        }
        if event_type not in permitted_events.get(self.authenticated_user["role"], set()):
            self.send_json(403, {"error": "Your role cannot record this type of safety event."})
            return
        if status not in {"SUCCESS", "ALERT", "BLOCKED", "DELETED", "UPDATED"} or len(detail) > 1000:
            self.send_json(400, {"error": "Audit status or event details are invalid."})
            return
        try:
            with connect_database() as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "INSERT INTO audit_events "
                    "(actor_user_id, actor_name, action, entity_type, entity_id, details, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        self.authenticated_user["id"],
                        self.authenticated_user["name"],
                        event_type.casefold().replace(" ", "."),
                        "safety_event",
                        "pending",
                        json.dumps({
                            "eventType": event_type,
                            "patient": patient,
                            "medication": medication,
                            "status": status,
                            "detail": detail,
                        }, ensure_ascii=False),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                connection.execute(
                    "UPDATE audit_events SET entity_id = ? WHERE id = ?",
                    (str(cursor.lastrowid), cursor.lastrowid),
                )
                row = connection.execute(
                    "SELECT id, actor_user_id, actor_name, action, entity_type, entity_id, details, created_at "
                    "FROM audit_events WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not save the audit event."})
            return
        self.send_json(201, {
            "id": row["id"],
            "actorUserId": row["actor_user_id"],
            "actorName": row["actor_name"],
            "action": row["action"],
            "entityType": row["entity_type"],
            "entityId": row["entity_id"],
            "details": json.loads(row["details"]),
            "createdAt": row["created_at"],
        })

    def list_prescriptions(self, query):
        user = self.authenticated_user
        search = str(query.get("q", [""])[0]).strip()[:120]
        clauses = []
        params = []
        if user["role"] == "Physician":
            clauses.append("p.prescriber_id = ?")
            params.append(user["id"])
        else:
            clauses.append("p.status = 'Active'")
        if search:
            pattern = f"%{search}%"
            clauses.append("(p.patient_id LIKE ? OR pt.name LIKE ? OR p.medication_name LIKE ? OR p.status LIKE ?)")
            params.extend((pattern, pattern, pattern, pattern))
        where = " AND ".join(clauses) if clauses else "1 = 1"
        statement = (
            "SELECT p.*, pt.name AS patient_name, s.name AS prescriber_name, "
            "p.safety_warnings AS warnings_json, p.missing_data AS missing_data_json "
            "FROM prescriptions p JOIN patients pt ON pt.id = p.patient_id "
            "JOIN staff_accounts s ON s.id = p.prescriber_id "
            f"WHERE {where} ORDER BY p.updated_at DESC, p.id DESC"
        )
        with connect_database() as connection:
            rows = connection.execute(statement, params).fetchall()
        self.send_json(200, [prescription_row_to_dict(row) for row in rows])

    def get_prescription(self, prescription_id):
        user = self.authenticated_user
        clauses = ["p.id = ?"]
        params = [int(prescription_id)]
        if user["role"] == "Physician":
            clauses.append("p.prescriber_id = ?")
            params.append(user["id"])
        else:
            clauses.append("p.status = 'Active'")
        with connect_database() as connection:
            row = connection.execute(
                "SELECT p.*, pt.name AS patient_name, s.name AS prescriber_name, "
                "p.safety_warnings AS warnings_json, p.missing_data AS missing_data_json "
                "FROM prescriptions p JOIN patients pt ON pt.id = p.patient_id "
                "JOIN staff_accounts s ON s.id = p.prescriber_id WHERE "
                + " AND ".join(clauses),
                params,
            ).fetchone()
        if row is None:
            self.send_json(404, {"error": "Prescription was not found or is not available to this role."})
            return
        self.send_json(200, prescription_row_to_dict(row))

    def validate_prescription(self, connection, payload, exclude_id=None):
        patient_id = str(payload.get("patientId", "")).strip()
        medication_id = str(payload.get("medicationId", "")).strip()
        fields = {
            "strength": (120, True),
            "dosage": (120, True),
            "route": (120, True),
            "frequency": (120, True),
            "quantityUnit": (40, True),
            "instructions": (1000, False),
            "clinicalNotes": (2000, False),
        }
        values = {}
        for field, (max_length, required) in fields.items():
            value = str(payload.get(field, "")).strip()
            if required and not value:
                raise ValueError(f"{field} is required.")
            if len(value) > max_length:
                raise ValueError(f"{field} must be {max_length} characters or fewer.")
            values[field] = value
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", patient_id):
            raise ValueError("Select a valid patient.")
        patient = connection.execute(
            "SELECT p.id, p.name, p.allergies FROM patients p "
            "LEFT JOIN deleted_patients d ON d.id = p.id WHERE p.id = ? AND d.id IS NULL",
            (patient_id,),
        ).fetchone()
        if patient is None:
            raise ValueError("The selected patient does not exist or has been deleted.")
        if not medication_id or len(medication_id) > 120:
            raise ValueError("Enter a medication name or inventory ID.")
        medication = connection.execute(
            "SELECT id, name, exp, route, stock, low_stock_threshold FROM medications "
            "WHERE id = ? COLLATE NOCASE OR name = ? COLLATE NOCASE",
            (medication_id, medication_id),
        ).fetchone()
        if medication is None:
            raise ValueError(
                "That medication is not in Medication Inventory. It was not created. "
                "Enter an existing medication name or inventory ID."
            )
        medication_id = medication["id"]
        try:
            duration = int(payload.get("durationDays"))
        except (TypeError, ValueError):
            raise ValueError("Duration must be a whole number of days.")
        if not 1 <= duration <= 3650:
            raise ValueError("Duration must be between 1 and 3650 days.")
        try:
            quantity = float(payload.get("quantity"))
        except (TypeError, ValueError):
            raise ValueError("Quantity must be a positive number.")
        if not 0 < quantity <= 1_000_000:
            raise ValueError("Quantity must be greater than 0 and no more than 1,000,000.")
        start_date = str(payload.get("startDate", "")).strip()
        end_date = str(payload.get("endDate", "")).strip()
        prescription_date = str(payload.get("prescriptionDate", "")).strip()
        if not valid_iso_date(start_date, required=True):
            raise ValueError("Enter a valid start date.")
        if not valid_iso_date(end_date):
            raise ValueError("Enter a valid end date.")
        if end_date and end_date < start_date:
            raise ValueError("End date cannot be before the start date.")
        if not valid_iso_date(prescription_date, required=True):
            raise ValueError("Enter a valid prescription date.")
        if prescription_date > datetime.now(timezone.utc).date().isoformat():
            raise ValueError("Prescription date cannot be in the future.")

        warnings = []
        missing_data = []
        try:
            allergies = json.loads(patient["allergies"])
        except (TypeError, json.JSONDecodeError):
            allergies = []
        if not allergies or any(str(item).strip().casefold() in {"unknown", "not recorded", "not provided"} for item in allergies):
            missing_data.append("Allergy information is missing or marked unknown.")
        elif any(
            str(item).strip().casefold() not in {"none", "no known allergies"}
            and str(item).strip().casefold() in medication["name"].casefold()
            for item in allergies
        ):
            warnings.append("Medication name matches a documented allergy entry; requires clinical review.")
        if medication["route"].strip().casefold() != values["route"].casefold():
            warnings.append("Prescribed route differs from the medication record route; verify before activation.")
        if not medication["exp"]:
            missing_data.append("Medication expiration information is missing.")
        elif not valid_iso_date(medication["exp"]):
            missing_data.append("Medication expiration information is invalid.")
        elif medication["exp"] < datetime.now(timezone.utc).date().isoformat():
            warnings.append("Medication record lists an expired product; review before activation.")
        if medication["stock"] <= 0:
            warnings.append("No stock is recorded for this medication.")
        elif medication["stock"] <= medication["low_stock_threshold"]:
            warnings.append("Medication stock is at or below the recorded low-stock threshold.")

        duplicate_params = [patient_id, medication_id]
        duplicate_sql = (
            "SELECT id FROM prescriptions WHERE patient_id = ? AND medication_id = ? "
            "AND status IN ('Draft', 'Active')"
        )
        if exclude_id is not None:
            duplicate_sql += " AND id != ?"
            duplicate_params.append(exclude_id)
        duplicate = connection.execute(duplicate_sql, duplicate_params).fetchone()
        if duplicate:
            warnings.append("Another draft or active prescription for this patient and medication exists.")
        return {
            "patient_id": patient_id,
            "patient_name": patient["name"],
            "medication_id": medication_id,
            "medication_name": medication["name"],
            "strength": values["strength"],
            "dosage": values["dosage"],
            "route": values["route"],
            "frequency": values["frequency"],
            "duration_days": duration,
            "quantity": quantity,
            "quantity_unit": values["quantityUnit"],
            "start_date": start_date,
            "end_date": end_date,
            "instructions": values["instructions"],
            "clinical_notes": values["clinicalNotes"],
            "prescription_date": prescription_date,
            "safety_warnings": json.dumps(warnings, ensure_ascii=False),
            "missing_data": json.dumps(missing_data, ensure_ascii=False),
            "warnings": warnings,
            "missingData": missing_data,
        }

    def create_prescription(self):
        try:
            payload = self.read_json_body()
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error) or "Invalid JSON request."})
            return
        if payload.get("status", "Active") != "Active":
            self.send_json(400, {"error": "New prescriptions must be saved as Active orders."})
            return
        now = datetime.now(timezone.utc).isoformat()
        try:
            with connect_database() as connection:
                connection.execute("BEGIN IMMEDIATE")
                normalized = self.validate_prescription(connection, payload)
                columns = (
                    "patient_id, medication_id, medication_name, strength, dosage, route, frequency, "
                    "duration_days, quantity, quantity_unit, start_date, end_date, instructions, "
                    "clinical_notes, prescription_date, prescriber_id, status, safety_warnings, missing_data, "
                    "created_at, updated_at"
                )
                placeholders = ", ".join("?" for _ in range(21))
                cursor = connection.execute(
                    f"INSERT INTO prescriptions ({columns}) VALUES ({placeholders})",
                    (
                        normalized["patient_id"], normalized["medication_id"], normalized["medication_name"],
                        normalized["strength"], normalized["dosage"], normalized["route"], normalized["frequency"],
                        normalized["duration_days"], normalized["quantity"], normalized["quantity_unit"],
                        normalized["start_date"], normalized["end_date"], normalized["instructions"],
                        normalized["clinical_notes"], normalized["prescription_date"],
                        self.authenticated_user["id"], "Active", normalized["safety_warnings"],
                        normalized["missing_data"], now, now,
                    ),
                )
                add_audit_event(
                    connection, self.authenticated_user, "prescription.created",
                    "prescription", cursor.lastrowid,
                    {
                        "patientId": normalized["patient_id"],
                        "medicationId": normalized["medication_id"],
                        "status": "Active",
                        "warningCount": len(normalized["warnings"]),
                        "missingDataCount": len(normalized["missingData"]),
                        "safetyReviewRequired": True,
                    }
                )
                prescription_id = cursor.lastrowid
            self.get_prescription(str(prescription_id))
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not save the prescription."})

    def update_prescription(self, prescription_id):
        try:
            payload = self.read_json_body()
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error) or "Invalid JSON request."})
            return
        if payload.get("status", "Active") != "Active":
            self.send_json(400, {"error": "Saving a prescription must create an Active order."})
            return
        try:
            with connect_database() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT id, status, prescriber_id FROM prescriptions WHERE id = ?",
                    (int(prescription_id),),
                ).fetchone()
                if existing is None:
                    self.send_json(404, {"error": "Prescription not found."})
                    return
                if existing["prescriber_id"] != self.authenticated_user["id"]:
                    self.send_json(403, {"error": "Physicians may edit only their own draft prescriptions."})
                    return
                if existing["status"] != "Draft":
                    self.send_json(409, {"error": "Finalized prescriptions cannot be edited. Use the authorized status workflow."})
                    return
                normalized = self.validate_prescription(connection, payload, int(prescription_id))
                connection.execute(
                    "UPDATE prescriptions SET patient_id=?, medication_id=?, medication_name=?, strength=?, "
                    "dosage=?, route=?, frequency=?, duration_days=?, quantity=?, quantity_unit=?, start_date=?, "
                    "end_date=?, instructions=?, clinical_notes=?, prescription_date=?, status='Active', "
                    "status_reason='', safety_warnings=?, "
                    "missing_data=?, updated_at=? WHERE id=?",
                    (
                        normalized["patient_id"], normalized["medication_id"], normalized["medication_name"],
                        normalized["strength"], normalized["dosage"], normalized["route"], normalized["frequency"],
                        normalized["duration_days"], normalized["quantity"], normalized["quantity_unit"],
                        normalized["start_date"], normalized["end_date"], normalized["instructions"],
                        normalized["clinical_notes"], normalized["prescription_date"],
                        normalized["safety_warnings"], normalized["missing_data"],
                        datetime.now(timezone.utc).isoformat(), int(prescription_id),
                    ),
                )
                add_audit_event(
                    connection, self.authenticated_user, "prescription.activated",
                    "prescription", prescription_id,
                    {
                        "patientId": normalized["patient_id"],
                        "medicationId": normalized["medication_id"],
                        "previousStatus": "Draft",
                        "status": "Active",
                        "warningCount": len(normalized["warnings"]),
                        "missingDataCount": len(normalized["missingData"]),
                        "safetyReviewRequired": True,
                    }
                )
            self.get_prescription(prescription_id)
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not update the prescription."})

    def change_prescription_status(self, endpoint):
        prescription_id = endpoint.removeprefix("/api/prescriptions/").removesuffix("/status")
        if not re.fullmatch(r"[1-9][0-9]*", prescription_id):
            self.send_json(400, {"error": "Invalid prescription ID."})
            return
        try:
            payload = self.read_json_body()
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error) or "Invalid JSON request."})
            return
        target = str(payload.get("status", "")).strip()
        reason = str(payload.get("reason", "")).strip()
        if len(reason) > 500:
            self.send_json(400, {"error": "Status reason must be 500 characters or fewer."})
            return
        try:
            with connect_database() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT status, prescriber_id, patient_id, medication_id FROM prescriptions WHERE id = ?",
                    (int(prescription_id),),
                ).fetchone()
                if existing is None:
                    self.send_json(404, {"error": "Prescription not found."})
                    return
                if existing["prescriber_id"] != self.authenticated_user["id"]:
                    self.send_json(403, {"error": "Only the prescribing physician may change this prescription's status."})
                    return
                allowed = {
                    "Draft": {"Active", "Cancelled"},
                    "Active": {"Discontinued"},
                    "Discontinued": set(),
                    "Cancelled": set(),
                }
                if target not in allowed.get(existing["status"], set()):
                    self.send_json(409, {"error": f"Cannot change status from {existing['status']} to {target}."})
                    return
                if target in {"Cancelled", "Discontinued"} and not reason:
                    self.send_json(400, {"error": "Enter a reason when cancelling or discontinuing a prescription."})
                    return
                now = datetime.now(timezone.utc).isoformat()
                connection.execute(
                    "UPDATE prescriptions SET status = ?, status_reason = ?, updated_at = ? WHERE id = ?",
                    (target, reason, now, int(prescription_id)),
                )
                add_audit_event(
                    connection, self.authenticated_user, f"prescription.{target.casefold()}",
                    "prescription", prescription_id,
                    {"previousStatus": existing["status"], "status": target, "reason": reason,
                     "patientId": existing["patient_id"], "medicationId": existing["medication_id"],
                     "safetyReviewRequired": target == "Active"}
                )
            self.get_prescription(prescription_id)
        except sqlite3.Error:
            self.send_json(500, {"error": "Could not change prescription status."})


def main():
    parser = argparse.ArgumentParser(description="Run the QR MedCheck local-network prototype server.")
    parser.add_argument("--host", default="0.0.0.0", help="Network interface to listen on (default: all interfaces).")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8766")), help="Port to serve on.")
    parser.add_argument(
        "--set-password",
        metavar="ADMIN_EMAIL",
        help="Set or reset a fictional Administrator password, then exit.",
    )
    parser.add_argument(
        "--restore-admin",
        action="store_true",
        help="Restore the Alex demo Administrator account and set its password, then exit.",
    )
    args = parser.parse_args()

    if args.restore_admin and args.set_password:
        parser.error("Use either --restore-admin or --set-password, not both.")

    initialize_database()
    if args.restore_admin:
        try:
            restore_demo_administrator()
        except ValueError as error:
            parser.error(str(error))
        except sqlite3.IntegrityError:
            parser.error("Could not restore the Administrator account because its email is already in use.")
        return

    if args.set_password:
        email = args.set_password.strip()
        with connect_database() as connection:
            admin = connection.execute(
                "SELECT id FROM staff_accounts WHERE email = ? COLLATE NOCASE AND role = 'Administrator'",
                (email,),
            ).fetchone()
        if admin is None:
            parser.error("No administrator account with that email exists.")
        password = getpass.getpass("New administrator password (8+ characters): ")
        confirmation = getpass.getpass("Confirm password: ")
        if len(password) < 8 or len(password) > 256:
            parser.error("Password must be between 8 and 256 characters.")
        if password != confirmation:
            parser.error("The passwords do not match.")
        with connect_database() as connection:
            connection.execute(
                "UPDATE staff_accounts SET password_hash = ? WHERE id = ?",
                (hash_password(password), admin["id"]),
            )
            connection.execute("DELETE FROM user_sessions WHERE user_id = ?", (admin["id"],))
        print(f"Password set for administrator {email}.")
        return

    server = ThreadingHTTPServer((args.host, args.port), QRMedCheckHandler)
    lan_ip = get_lan_ip()
    print(f"QR MedCheck prototype: http://localhost:{args.port}/")
    if lan_ip:
        print(f"Phone on the same Wi-Fi: http://{lan_ip}:{args.port}/")
    else:
        print("Could not detect a LAN address. Use your computer's Wi-Fi IPv4 address for phone access.")
    print("Prototype only: use fictional data. Password sign-in and role checks are not production-ready security.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping QR MedCheck server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
