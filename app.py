from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import secrets
import hashlib
import hmac
import os
import smtplib
from email.message import EmailMessage
from email.utils import formataddr
from datetime import datetime, date, time, timedelta
from functools import wraps


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)
CORS(app)
app.config["JSON_SORT_KEYS"] = False


# ============================================================
# DATABASE
# ============================================================

DB_CONFIG = {
    "host": "localhost",
    "user": "outpass_user",
    "password": "Outpass@123",
    "database": "smart_outpass"
}


def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


# ============================================================
# APPLICATION SETTINGS
# ============================================================

OTP_TEST_MODE = os.environ.get(
    "OTP_TEST_MODE",
    "false"
).lower() == "true"

OTP_EXPIRY_MINUTES = 10
MAX_OTP_ATTEMPTS = 5


# ============================================================
# SMTP EMAIL SETTINGS
# ============================================================

SMTP_HOST = os.environ.get(
    "SMTP_HOST",
    "smtp.gmail.com"
).strip()

try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
except (TypeError, ValueError):
    SMTP_PORT = 587


SMTP_USERNAME = os.environ.get(
    "SMTP_USERNAME",
    ""
).strip()

SMTP_PASSWORD = os.environ.get(
    "SMTP_PASSWORD",
    ""
).strip()

SMTP_FROM_EMAIL = os.environ.get(
    "SMTP_FROM_EMAIL",
    SMTP_USERNAME
).strip()

SMTP_FROM_NAME = os.environ.get(
    "SMTP_FROM_NAME",
    "Smart Outpass"
).strip()

SMTP_USE_SSL = os.environ.get(
    "SMTP_USE_SSL",
    "true" if SMTP_PORT == 465 else "false"
).lower() == "true"


# ============================================================
# DEFAULT PASSWORDS
# ============================================================

DEFAULT_STUDENT_PASSWORD = os.environ.get(
    "DEFAULT_STUDENT_PASSWORD",
    "Student@123"
)

DEFAULT_MENTOR_PASSWORD = os.environ.get(
    "DEFAULT_MENTOR_PASSWORD",
    "Mentor@123"
)

DEFAULT_SECURITY_PASSWORD = os.environ.get(
    "DEFAULT_SECURITY_PASSWORD",
    "Security@123"
)

DEFAULT_PARENT_PASSWORD = os.environ.get(
    "DEFAULT_PARENT_PASSWORD",
    "Parent@123"
)

DEFAULT_ADMIN_USERNAME = os.environ.get(
    "DEFAULT_ADMIN_USERNAME",
    "admin"
)

DEFAULT_ADMIN_NAME = os.environ.get(
    "DEFAULT_ADMIN_NAME",
    "System Administrator"
)

DEFAULT_ADMIN_EMAIL = os.environ.get(
    "DEFAULT_ADMIN_EMAIL",
    os.environ.get("ADMIN_EMAIL", "")
)

DEFAULT_ADMIN_PASSWORD = os.environ.get(
    "DEFAULT_ADMIN_PASSWORD",
    "Admin@123"
)


# ============================================================
# SIMPLE TOKEN AUTHENTICATION
# ============================================================

ACTIVE_TOKENS = {}


def generate_token():
    return secrets.token_urlsafe(32)


def get_auth_user():
    auth_header = request.headers.get(
        "Authorization",
        ""
    )

    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.replace(
        "Bearer ",
        "",
        1
    ).strip()

    if not token:
        return None

    return ACTIVE_TOKENS.get(token)


def login_required(role=None):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            user = get_auth_user()

            if not user:
                return jsonify({
                    "success": False,
                    "message": "Authentication required."
                }), 401

            if role:

                allowed_roles = (
                    role
                    if isinstance(role, list)
                    else [role]
                )

                if user["role"] not in allowed_roles:
                    return jsonify({
                        "success": False,
                        "message":
                            "You do not have permission for this action."
                    }), 403

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password):

    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


def verify_password(password, password_hash):

    if not password_hash:
        return False

    calculated_hash = hash_password(password)

    return hmac.compare_digest(
        calculated_hash,
        password_hash
    )


# ============================================================
# OTP
# ============================================================

def generate_parent_otp():

    return str(
        secrets.randbelow(900000) + 100000
    )


def hash_otp(otp):

    return hashlib.sha256(
        otp.encode("utf-8")
    ).hexdigest()


def verify_otp(otp, otp_hash):

    if not otp_hash:
        return False

    calculated_hash = hash_otp(otp)

    return hmac.compare_digest(
        calculated_hash,
        otp_hash
    )


def mask_mobile_number(number):

    number = str(number)

    if len(number) <= 4:
        return "*" * len(number)

    return "*" * (len(number) - 4) + number[-4:]


# ============================================================
# EMAIL
# ============================================================

def _email_configured():

    return bool(
        SMTP_HOST
        and SMTP_PORT
        and SMTP_USERNAME
        and SMTP_PASSWORD
        and SMTP_FROM_EMAIL
    )


def send_email(
    to_email,
    subject,
    body,
    html_body=None
):

    if not to_email:
        return False, "Recipient email address is missing."

    if not _email_configured():

        return False, (
            "SMTP is not configured. "
            "Set SMTP_HOST, SMTP_PORT, SMTP_USERNAME, "
            "SMTP_PASSWORD and SMTP_FROM_EMAIL."
        )

    message = EmailMessage()

    message["From"] = formataddr(
        (
            SMTP_FROM_NAME,
            SMTP_FROM_EMAIL
        )
    )

    message["To"] = to_email
    message["Subject"] = subject

    message.set_content(body)

    if html_body:
        message.add_alternative(
            html_body,
            subtype="html"
        )

    try:

        smtp_class = smtplib.SMTP_SSL if SMTP_USE_SSL else smtplib.SMTP

        with smtp_class(
            SMTP_HOST,
            SMTP_PORT,
            timeout=20
        ) as server:

            server.ehlo()

            if not SMTP_USE_SSL:
                server.starttls()
                server.ehlo()
            server.login(
                SMTP_USERNAME,
                SMTP_PASSWORD
            )

            server.send_message(message)

        return True, None

    except smtplib.SMTPAuthenticationError:
        return False, (
            "SMTP authentication failed. Check SMTP_USERNAME and SMTP_PASSWORD. "
            "For Gmail, use a Google App Password, not the normal Gmail password."
        )
    except smtplib.SMTPConnectError as error:
        return False, f"Could not connect to SMTP server: {error}"
    except smtplib.SMTPServerDisconnected as error:
        return False, f"SMTP server disconnected the connection: {error}"
    except Exception as error:
        return False, f"SMTP email error: {error}"


def log_email_notification(
    notification_type,
    recipient_email,
    recipient_name,
    roll_number,
    outpass_id,
    subject,
    message,
    status,
    error_message=None
):

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO email_notifications
            (
                notification_type,
                recipient_email,
                recipient_name,
                roll_number,
                outpass_id,
                subject,
                message,
                status,
                error_message,
                sent_at
            )
            VALUES
            (
                %s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s
            )
            """,
            (
                notification_type,
                recipient_email,
                recipient_name,
                roll_number,
                outpass_id,
                subject,
                message,
                status,
                error_message,
                datetime.now()
                if status == "Sent"
                else None
            )
        )

        connection.commit()

    except Exception as error:

        print(
            "WARNING: Could not record email notification:",
            error
        )

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


def notify_outpass_event(
    outpass_id,
    notification_type,
    subject,
    body,
    recipients
):

    unique = {}

    for recipient in recipients or []:

        email = str(
            recipient.get("email") or ""
        ).strip()

        if email:

            unique[
                email.lower()
            ] = recipient

    results = []

    for recipient in unique.values():

        email = str(
            recipient.get("email")
        ).strip()

        success, error = send_email(
            email,
            subject,
            body
        )

        status = (
            "Sent"
            if success
            else "Failed"
        )

        log_email_notification(
            notification_type,
            email,
            recipient.get("name"),
            recipient.get("roll_number"),
            outpass_id,
            subject,
            body,
            status,
            error
        )

        results.append({
            "email": email,
            "status": status,
            "error": error
        })

    return results


def get_outpass_email_recipients(
    outpass_id,
    include_student=True,
    include_parent=True,
    include_mentors=False,
    include_security=False
):

    connection = None
    cursor = None
    recipients = []

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                o.outpass_id,
                o.roll_number,
                o.student_name,
                o.department,

                s.email AS student_email,

                p.name AS parent_name,
                p.email AS parent_email,

                m.email AS mentor_email,
                m.name AS mentor_name,

                su.email AS security_email,
                su.name AS security_name,
                su.employee_id AS security_employee_id

            FROM outpass_requests o

            LEFT JOIN students s
                ON s.roll_number = o.roll_number

            LEFT JOIN parents p
                ON p.student_roll_number = o.roll_number

            LEFT JOIN mentors m
                ON m.email IS NOT NULL
                AND m.email <> ''

            LEFT JOIN security_users su
                ON su.email IS NOT NULL
                AND su.email <> ''

            WHERE o.outpass_id = %s
            """,
            (outpass_id,)
        )

        rows = cursor.fetchall()

        if not rows:
            return []

        first = rows[0]

        if (
            include_student
            and first.get("student_email")
        ):

            recipients.append({
                "email":
                    first["student_email"],
                "name":
                    first["student_name"],
                "roll_number":
                    first["roll_number"]
            })

        if (
            include_parent
            and first.get("parent_email")
        ):

            recipients.append({
                "email":
                    first["parent_email"],
                "name":
                    first["parent_name"],
                "roll_number":
                    first["roll_number"]
            })

        if include_mentors:

            for row in rows:

                if row.get("mentor_email"):

                    recipients.append({
                        "email":
                            row["mentor_email"],
                        "name":
                            row["mentor_name"],
                        "roll_number":
                            row["roll_number"]
                    })

        if include_security:

            for row in rows:

                if row.get("security_email"):

                    recipients.append({
                        "email":
                            row["security_email"],
                        "name":
                            row["security_name"],
                        "roll_number":
                            row["roll_number"]
                    })

        return recipients

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


def notify_outpass(
    outpass_id,
    notification_type,
    subject,
    body,
    include_student=True,
    include_parent=True,
    include_mentors=False,
    include_security=False
):

    recipients = get_outpass_email_recipients(
        outpass_id,
        include_student,
        include_parent,
        include_mentors,
        include_security
    )

    return notify_outpass_event(
        outpass_id,
        notification_type,
        subject,
        body,
        recipients
    )


# ============================================================
# SERIALIZE MYSQL VALUES
# ============================================================

def serialize_datetime_fields(item):

    for key, value in item.items():

        if value is None:
            continue

        if isinstance(value, datetime):

            item[key] = value.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        elif isinstance(value, date):

            item[key] = value.strftime(
                "%Y-%m-%d"
            )

        elif isinstance(value, time):

            item[key] = value.strftime(
                "%H:%M:%S"
            )

        elif isinstance(value, timedelta):

            total_seconds = int(
                value.total_seconds()
            )

            sign = (
                "-"
                if total_seconds < 0
                else ""
            )

            total_seconds = abs(
                total_seconds
            )

            hours, remainder = divmod(
                total_seconds,
                3600
            )

            minutes, seconds = divmod(
                remainder,
                60
            )

            item[key] = (
                f"{sign}"
                f"{hours:02d}:"
                f"{minutes:02d}:"
                f"{seconds:02d}"
            )

    return item


# ============================================================
# DATABASE COMPATIBILITY HELPERS
# ============================================================

def column_exists(
    cursor,
    table_name,
    column_name
):

    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        """,
        (
            table_name,
            column_name
        )
    )

    result = cursor.fetchone()

    return result["count"] > 0


def make_column_nullable(
    cursor,
    table_name,
    column_name
):

    cursor.execute(
        """
        SELECT
            COLUMN_TYPE,
            IS_NULLABLE
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        """,
        (
            table_name,
            column_name
        )
    )

    result = cursor.fetchone()

    if not result:
        return

    if (
        str(result["IS_NULLABLE"]).upper()
        == "YES"
    ):
        return

    column_type = result["COLUMN_TYPE"]

    cursor.execute(
        f"""
        ALTER TABLE `{table_name}`
        MODIFY COLUMN `{column_name}`
        {column_type} NULL
        """
    )


# ============================================================
# DATABASE COMPATIBILITY
# ============================================================

def ensure_database_compatibility():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        # ----------------------------------------------------
        # PASSWORD COLUMNS
        # ----------------------------------------------------

        password_tables = (
            "students",
            "mentors",
            "security_users",
            "parents"
        )

        for table in password_tables:

            if not column_exists(
                cursor,
                table,
                "password_hash"
            ):

                cursor.execute(
                    f"""
                    ALTER TABLE `{table}`
                    ADD COLUMN password_hash
                    VARCHAR(255)
                    DEFAULT NULL
                    """
                )

        # ----------------------------------------------------
        # EMAIL COLUMNS
        # ----------------------------------------------------

        email_tables = (
            "students",
            "parents",
            "mentors",
            "security_users"
        )

        for table in email_tables:

            if not column_exists(
                cursor,
                table,
                "email"
            ):

                cursor.execute(
                    f"""
                    ALTER TABLE `{table}`
                    ADD COLUMN email
                    VARCHAR(255)
                    DEFAULT NULL
                    """
                )

        if not column_exists(
            cursor,
            "students",
            "mobile_number"
        ):
            cursor.execute(
                """
                ALTER TABLE students
                ADD COLUMN mobile_number VARCHAR(30) DEFAULT NULL
                """
            )

        # ----------------------------------------------------
        # USER STATUS COLUMNS
        # ----------------------------------------------------

        for table in email_tables:

            if not column_exists(
                cursor,
                table,
                "status"
            ):

                cursor.execute(
                    f"""
                    ALTER TABLE `{table}`
                    ADD COLUMN status
                    VARCHAR(20)
                    NOT NULL
                    DEFAULT 'Active'
                    """
                )

        for table in email_tables:

            cursor.execute(
                f"""
                UPDATE `{table}`
                SET status = 'Active'
                WHERE status IS NULL
                   OR TRIM(status) = ''
                """
            )

        # ----------------------------------------------------
        # OUTPASS COMPATIBILITY
        # ----------------------------------------------------

        outpass_columns = [
            (
                "actual_exit_time",
                """
                ALTER TABLE outpass_requests
                ADD COLUMN actual_exit_time
                DATETIME NULL
                """
            ),
            (
                "actual_return_time",
                """
                ALTER TABLE outpass_requests
                ADD COLUMN actual_return_time
                DATETIME NULL
                """
            ),
            (
                "mentor_rejection_reason",
                """
                ALTER TABLE outpass_requests
                ADD COLUMN mentor_rejection_reason
                VARCHAR(500) NULL
                """
            ),
            (
                "mentor_rejected_at",
                """
                ALTER TABLE outpass_requests
                ADD COLUMN mentor_rejected_at
                DATETIME NULL
                """
            )
        ]

        for column_name, sql in outpass_columns:

            if not column_exists(
                cursor,
                "outpass_requests",
                column_name
            ):

                cursor.execute(sql)

        if column_exists(
            cursor,
            "outpass_requests",
            "return_time"
        ):

            make_column_nullable(
                cursor,
                "outpass_requests",
                "return_time"
            )

        # ----------------------------------------------------
        # EMAIL NOTIFICATIONS
        # ----------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS
            email_notifications
            (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,

                notification_type
                    VARCHAR(50) NOT NULL,

                recipient_email
                    VARCHAR(255) NOT NULL,

                recipient_name
                    VARCHAR(100) DEFAULT NULL,

                roll_number
                    VARCHAR(30) DEFAULT NULL,

                outpass_id
                    VARCHAR(20) DEFAULT NULL,

                subject
                    VARCHAR(255) NOT NULL,

                message
                    TEXT NOT NULL,

                status
                    VARCHAR(20)
                    NOT NULL
                    DEFAULT 'Pending',

                error_message
                    TEXT DEFAULT NULL,

                sent_at
                    DATETIME NULL,

                created_at
                    DATETIME
                    DEFAULT CURRENT_TIMESTAMP,

                INDEX idx_email_recipient
                    (recipient_email),

                INDEX idx_email_roll_number
                    (roll_number),

                INDEX idx_email_outpass
                    (outpass_id),

                INDEX idx_email_status
                    (status),

                INDEX idx_email_created_at
                    (created_at)
            )
            """
        )

        # ----------------------------------------------------
        # ADMIN TABLE
        # ----------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS admins
            (
                id INT AUTO_INCREMENT PRIMARY KEY,

                username
                    VARCHAR(50) NOT NULL UNIQUE,

                name
                    VARCHAR(100) NOT NULL,

                email
                    VARCHAR(255) DEFAULT NULL,

                password_hash
                    VARCHAR(255) NOT NULL,

                status
                    VARCHAR(20)
                    NOT NULL
                    DEFAULT 'Active',

                created_at
                    DATETIME
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.commit()

        # ----------------------------------------------------
        # DEFAULT PASSWORDS
        # ----------------------------------------------------

        student_hash = hash_password(
            DEFAULT_STUDENT_PASSWORD
        )

        mentor_hash = hash_password(
            DEFAULT_MENTOR_PASSWORD
        )

        security_hash = hash_password(
            DEFAULT_SECURITY_PASSWORD
        )

        parent_hash = hash_password(
            DEFAULT_PARENT_PASSWORD
        )

        admin_hash = hash_password(
            DEFAULT_ADMIN_PASSWORD
        )

        cursor.execute(
            """
            UPDATE students
            SET password_hash = %s
            WHERE password_hash IS NULL
            """,
            (student_hash,)
        )

        cursor.execute(
            """
            UPDATE mentors
            SET password_hash = %s
            WHERE password_hash IS NULL
            """,
            (mentor_hash,)
        )

        cursor.execute(
            """
            UPDATE security_users
            SET password_hash = %s
            WHERE password_hash IS NULL
            """,
            (security_hash,)
        )

        cursor.execute(
            """
            UPDATE parents
            SET password_hash = %s
            WHERE password_hash IS NULL
            """,
            (parent_hash,)
        )

        # ----------------------------------------------------
        # CREATE DEFAULT ADMIN
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT id
            FROM admins
            WHERE username = %s
            """,
            ("admin",)
        )

        admin_exists = cursor.fetchone()

        if not admin_exists:

            cursor.execute(
                """
                INSERT INTO admins
                (
                    username,
                    name,
                    email,
                    password_hash,
                    status
                )
                VALUES
                (
                    %s,%s,%s,%s,%s
                )
                """,
                (
                    DEFAULT_ADMIN_USERNAME,
                    DEFAULT_ADMIN_NAME,
                    DEFAULT_ADMIN_EMAIL,
                    admin_hash,
                    "Active"
                )
            )

        else:

            cursor.execute(
                """
                UPDATE admins
                SET password_hash = %s
                WHERE username = %s
                  AND password_hash IS NULL
                """,
                (
                    admin_hash,
                    DEFAULT_ADMIN_USERNAME
                )
            )

        connection.commit()

        print(
            "Database compatibility check completed."
        )

    except Exception as error:

        if connection:
            connection.rollback()

        print(
            "WARNING: Database compatibility check failed:"
        )

        print(error)

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT DATABASE()"
        )

        database_name = cursor.fetchone()[0]

        return (
            "SMART OUTPASS BACKEND IS RUNNING!"
            f"<br>Connected to database: "
            f"{database_name}"
        )

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/api/login",
    methods=["POST"]
)
def login():

    connection = None
    cursor = None

    try:

        data = request.get_json(
            silent=True
        )

        if not data:

            return jsonify({
                "success": False,
                "message":
                    "No login data received."
            }), 400

        role = str(
            data.get("role", "")
        ).strip().lower()

        username = str(
            data.get("username", "")
        ).strip()

        password = str(
            data.get("password", "")
        )

        if not role or not username or not password:

            return jsonify({
                "success": False,
                "message":
                    "Please enter username, password and role."
            }), 400

        valid_roles = {
            "student",
            "parent",
            "mentor",
            "security",
            "admin"
        }

        if role not in valid_roles:

            return jsonify({
                "success": False,
                "message":
                    "Invalid role."
            }), 400

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        user_data = None

        # ====================================================
        # STUDENT
        # ====================================================

        if role == "student":

            cursor.execute(
                """
                SELECT
                    id,
                    roll_number,
                    name,
                    department,
                    year,
                    email,
                    password_hash,
                    status
                FROM students
                WHERE roll_number = %s
                """,
                (username,)
            )

            user = cursor.fetchone()

            if not user:

                return jsonify({
                    "success": False,
                    "message":
                        "Student not found."
                }), 401

            if user["status"] != "Active":

                return jsonify({
                    "success": False,
                    "message": "This student account is inactive."
                }), 403

            if not verify_password(
                password,
                user["password_hash"]
            ):

                return jsonify({
                    "success": False,
                    "message":
                        "Invalid password."
                }), 401

            user_data = {
                "id": user["id"],
                "username":
                    user["roll_number"],
                "name": user["name"],
                "department":
                    user["department"],
                "year": user["year"],
                "role": "student"
            }

        # ====================================================
        # MENTOR
        # ====================================================

        elif role == "mentor":

            cursor.execute(
                """
                SELECT
                    id,
                    employee_id,
                    name,
                    email,
                    password_hash,
                    status
                FROM mentors
                WHERE employee_id = %s
                """,
                (username,)
            )

            user = cursor.fetchone()

            if not user:

                return jsonify({
                    "success": False,
                    "message":
                        "Mentor not found."
                }), 401

            if user["status"] != "Active":

                return jsonify({
                    "success": False,
                    "message": "This mentor account is inactive."
                }), 403

            if not verify_password(
                password,
                user["password_hash"]
            ):

                return jsonify({
                    "success": False,
                    "message":
                        "Invalid password."
                }), 401

            user_data = {
                "id": user["id"],
                "username":
                    user["employee_id"],
                "name": user["name"],
                "email": user.get("email"),
                "role": "mentor"
            }

        # ====================================================
        # SECURITY
        # ====================================================

        elif role == "security":

            cursor.execute(
                """
                SELECT
                    id,
                    employee_id,
                    name,
                    email,
                    password_hash,
                    status
                FROM security_users
                WHERE employee_id = %s
                """,
                (username,)
            )

            user = cursor.fetchone()

            if not user:

                return jsonify({
                    "success": False,
                    "message":
                        "Security user not found."
                }), 401

            if user["status"] != "Active":

                return jsonify({
                    "success": False,
                    "message": "This security account is inactive."
                }), 403

            if not verify_password(
                password,
                user["password_hash"]
            ):

                return jsonify({
                    "success": False,
                    "message":
                        "Invalid password."
                }), 401

            user_data = {
                "id": user["id"],
                "username":
                    user["employee_id"],
                "name": user["name"],
                "email": user.get("email"),
                "role": "security"
            }

        # ====================================================
        # PARENT
        # ====================================================

        elif role == "parent":

            cursor.execute(
                """
                SELECT
                    id,
                    student_roll_number,
                    student_name,
                    name,
                    mobile_number,
                    relationship,
                    email,
                    password_hash,
                    status
                FROM parents
                WHERE student_roll_number = %s
                """,
                (username,)
            )

            user = cursor.fetchone()

            if not user:

                return jsonify({
                    "success": False,
                    "message":
                        "Parent account not found."
                }), 401

            if user["status"] != "Active":

                return jsonify({
                    "success": False,
                    "message": "This parent account is inactive."
                }), 403

            if not verify_password(
                password,
                user["password_hash"]
            ):

                return jsonify({
                    "success": False,
                    "message":
                        "Invalid password."
                }), 401

            user_data = {
                "id": user["id"],
                "username":
                    user["student_roll_number"],
                "name": user["name"],
                "student_name":
                    user["student_name"],
                "mobile_number":
                    mask_mobile_number(
                        user["mobile_number"]
                    ),
                "relationship":
                    user["relationship"],
                "email": user.get("email"),
                "role": "parent"
            }

        # ====================================================
        # ADMIN
        # ====================================================

        elif role == "admin":

            cursor.execute(
                """
                SELECT
                    id,
                    username,
                    name,
                    email,
                    password_hash,
                    status
                FROM admins
                WHERE username = %s
                """,
                (username,)
            )

            user = cursor.fetchone()

            if not user:

                return jsonify({
                    "success": False,
                    "message":
                        "Admin account not found."
                }), 401

            if user["status"] != "Active":

                return jsonify({
                    "success": False,
                    "message":
                        "This admin account is inactive."
                }), 403

            if not verify_password(
                password,
                user["password_hash"]
            ):

                return jsonify({
                    "success": False,
                    "message":
                        "Invalid password."
                }), 401

            user_data = {
                "id": user["id"],
                "username":
                    user["username"],
                "name":
                    user["name"],
                "email":
                    user["email"],
                "role": "admin"
            }

        token = generate_token()

        ACTIVE_TOKENS[token] = user_data

        return jsonify({
            "success": True,
            "message":
                "Login successful.",
            "token": token,
            "user": user_data
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/api/logout",
    methods=["POST"]
)
def logout():

    auth_header = request.headers.get(
        "Authorization",
        ""
    )

    if auth_header.startswith("Bearer "):

        token = auth_header.replace(
            "Bearer ",
            "",
            1
        ).strip()

        ACTIVE_TOKENS.pop(
            token,
            None
        )

    return jsonify({
        "success": True,
        "message":
            "Logged out successfully."
    })


# ============================================================
# CURRENT USER
# ============================================================

@app.route(
    "/api/me",
    methods=["GET"]
)
@login_required()
def current_user():

    return jsonify({
        "success": True,
        "user": get_auth_user()
    })


# ============================================================
# CREATE OUTPASS
# ============================================================

@app.route(
    "/api/outpasses",
    methods=["POST"]
)
@login_required("student")
def create_outpass():

    connection = None
    cursor = None

    try:

        data = request.get_json(
            silent=True
        )

        if not data:

            return jsonify({
                "success": False,
                "message":
                    "No data received."
            }), 400

        user = get_auth_user()

        roll_number = str(
            user["username"]
        ).strip()

        destination = str(
            data.get("destination", "")
        ).strip()

        outpass_date = str(
            data.get("outpass_date", "")
        ).strip()

        exit_time = str(
            data.get("exit_time", "")
        ).strip()

        return_date = str(
            data.get("return_date", "")
        ).strip()

        reason = str(
            data.get("reason", "")
        ).strip()

        if not all([
            destination,
            outpass_date,
            exit_time,
            return_date,
            reason
        ]):

            return jsonify({
                "success": False,
                "message":
                    "Please complete all required fields."
            }), 400

        try:

            parsed_outpass_date = datetime.strptime(
                outpass_date,
                "%Y-%m-%d"
            ).date()

            parsed_return_date = datetime.strptime(
                return_date,
                "%Y-%m-%d"
            ).date()

            datetime.strptime(
                exit_time,
                "%H:%M"
            )

        except ValueError:

            return jsonify({
                "success": False,
                "message":
                    "Invalid date or time format."
            }), 400

        if parsed_return_date < parsed_outpass_date:

            return jsonify({
                "success": False,
                "message":
                    "Return date cannot be before outpass date."
            }), 400

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                roll_number,
                name,
                department,
                year,
                email
            FROM students
            WHERE roll_number = %s
            """,
            (roll_number,)
        )

        student = cursor.fetchone()

        if not student:

            return jsonify({
                "success": False,
                "message":
                    "Student account not found."
            }), 404

        cursor.execute(
            """
            SELECT
                name,
                mobile_number,
                relationship,
                email
            FROM parents
            WHERE student_roll_number = %s
            """,
            (roll_number,)
        )

        parent = cursor.fetchone()

        if not parent:

            return jsonify({
                "success": False,
                "message":
                    "No registered parent found for this student."
            }), 404

        outpass_id = (
            "OP" +
            secrets.token_hex(4).upper()
        )

        otp = generate_parent_otp()

        otp_hash = hash_otp(otp)

        otp_expires_at = (
            datetime.now()
            + timedelta(
                minutes=OTP_EXPIRY_MINUTES
            )
        )

        cursor.execute(
            """
            INSERT INTO outpass_requests
            (
                outpass_id,
                student_name,
                roll_number,
                department,
                year,
                destination,
                outpass_date,
                exit_time,
                return_date,
                reason,
                parent_status,
                mentor_status,
                security_status,
                overall_status,
                parent_otp_hash,
                parent_otp_expires_at,
                parent_otp_attempts,
                parent_otp_sent_at
            )
            VALUES
            (
                %s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,
                %s,%s,%s,%s,
                %s,%s,%s,%s
            )
            """,
            (
                outpass_id,
                student["name"],
                student["roll_number"],
                student["department"],
                student["year"],
                destination,
                parsed_outpass_date,
                exit_time,
                parsed_return_date,
                reason,
                "Pending",
                "Pending",
                "Not Exited",
                "Waiting for Parent Approval",
                otp_hash,
                otp_expires_at,
                0,
                datetime.now()
            )
        )

        connection.commit()

        otp_subject = (
            f"Smart Outpass - Parent OTP - "
            f"{outpass_id}"
        )

        otp_body = (
            f"Dear {parent['name']},\n\n"
            f"A Smart Outpass request has been "
            f"created for {student['name']} "
            f"(Roll No: {student['roll_number']}).\n\n"
            f"Your parent approval OTP is: {otp}\n\n"
            f"This OTP expires in "
            f"{OTP_EXPIRY_MINUTES} minutes. "
            f"Do not share this OTP with anyone.\n\n"
            f"Smart Outpass"
        )

        email_success, email_error = send_email(
            parent.get("email"),
            otp_subject,
            otp_body
        )

        log_email_notification(
            "PARENT_OTP",
            parent.get("email"),
            parent.get("name"),
            roll_number,
            outpass_id,
            otp_subject,
            otp_body,
            "Sent"
            if email_success
            else "Failed",
            email_error
        )

        student_subject = (
            f"Smart Outpass - Request Submitted - "
            f"{outpass_id}"
        )

        student_body = (
            f"Dear {student['name']},\n\n"
            f"Your outpass request {outpass_id} has been submitted.\n"
            f"Destination: {destination}\n"
            f"Outpass date: {parsed_outpass_date}\n"
            f"Expected exit time: {exit_time}\n"
            f"Return date: {parsed_return_date}\n\n"
            f"Current status: Waiting for Parent Approval.\n"
            f"You will receive another email when the approval status changes.\n\n"
            f"Smart Outpass"
        )

        student_email_success, student_email_error = send_email(
            student.get("email"),
            student_subject,
            student_body
        )

        log_email_notification(
            "STUDENT_OUTPASS_SUBMITTED",
            student.get("email"),
            student.get("name"),
            roll_number,
            outpass_id,
            student_subject,
            student_body,
            "Sent"
            if student_email_success
            else "Failed",
            student_email_error
        )

        if (
            not email_success
            and not OTP_TEST_MODE
        ):

            return jsonify({
                "success": False,
                "message":
                    "Outpass was created, but the parent OTP email could not be sent.",
                "outpass_id":
                    outpass_id,
                "email_error":
                    email_error
            }), 503

        if OTP_TEST_MODE:

            print(
                "SMART OUTPASS TEST OTP:",
                outpass_id,
                otp
            )

        return jsonify({
            "success": True,
            "message":
                "Outpass submitted. OTP sent to the registered parent email.",
            "outpass_id":
                outpass_id,
            "parent_mobile":
                mask_mobile_number(
                    parent["mobile_number"]
                ),
            "parent_email":
                parent.get("email")
        }), 201

    except mysql.connector.Error as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# RESEND PARENT OTP
# ============================================================

@app.route(
    "/api/outpasses/<outpass_id>/parent-otp/resend",
    methods=["POST"]
)
@login_required("student")
def resend_parent_otp(outpass_id):

    connection = None
    cursor = None

    try:

        user = get_auth_user()
        roll_number = str(user["username"]).strip()

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                o.outpass_id,
                o.roll_number,
                o.student_name,
                o.parent_status,
                p.name AS parent_name,
                p.email AS parent_email
            FROM outpass_requests o
            LEFT JOIN parents p
                ON p.student_roll_number = o.roll_number
            WHERE o.outpass_id = %s
            """,
            (outpass_id,)
        )

        outpass = cursor.fetchone()

        if not outpass:
            return jsonify({
                "success": False,
                "message": "Outpass not found."
            }), 404

        if str(outpass["roll_number"]) != roll_number:
            return jsonify({
                "success": False,
                "message": "You cannot resend an OTP for another student's outpass."
            }), 403

        if outpass["parent_status"] != "Pending":
            return jsonify({
                "success": False,
                "message": "Parent approval is no longer pending for this outpass."
            }), 400

        if not outpass.get("parent_email"):
            return jsonify({
                "success": False,
                "message": "No parent email is registered for this student."
            }), 400

        otp = generate_parent_otp()
        otp_expires_at = datetime.now() + timedelta(
            minutes=OTP_EXPIRY_MINUTES
        )

        cursor.execute(
            """
            UPDATE outpass_requests
            SET
                parent_otp_hash = %s,
                parent_otp_expires_at = %s,
                parent_otp_attempts = 0,
                parent_otp_sent_at = %s
            WHERE outpass_id = %s
              AND roll_number = %s
              AND parent_status = 'Pending'
            """,
            (
                hash_otp(otp),
                otp_expires_at,
                datetime.now(),
                outpass_id,
                roll_number
            )
        )
        connection.commit()

        subject = f"Smart Outpass - Parent OTP - {outpass_id}"
        body = (
            f"Dear {outpass['parent_name'] or 'Parent'},\n\n"
            f"A new approval OTP was requested for outpass {outpass_id} "
            f"for {outpass['student_name']} (Roll No: {roll_number}).\n\n"
            f"Your parent approval OTP is: {otp}\n\n"
            f"This OTP expires in {OTP_EXPIRY_MINUTES} minutes. "
            f"Do not share this OTP with anyone.\n\n"
            f"Smart Outpass"
        )

        email_success, email_error = send_email(
            outpass["parent_email"],
            subject,
            body
        )

        log_email_notification(
            "PARENT_OTP",
            outpass["parent_email"],
            outpass.get("parent_name"),
            roll_number,
            outpass_id,
            subject,
            body,
            "Sent" if email_success else "Failed",
            email_error
        )

        if not email_success and not OTP_TEST_MODE:
            return jsonify({
                "success": False,
                "message": "The new parent OTP email could not be sent.",
                "email_error": email_error
            }), 503

        if OTP_TEST_MODE:
            print("SMART OUTPASS TEST OTP:", outpass_id, otp)

        return jsonify({
            "success": True,
            "message": "A new OTP was sent to the registered parent email."
        })

    except mysql.connector.Error as error:
        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message": f"Database error: {error}"
        }), 500

    except Exception as error:
        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message": f"Server error: {error}"
        }), 500

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# GET OUTPASSES
# ============================================================

@app.route(
    "/api/outpasses",
    methods=["GET"]
)
@login_required([
    "student",
    "parent",
    "mentor",
    "security"
])
def get_outpasses():

    connection = None
    cursor = None

    try:

        user = get_auth_user()

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        if user["role"] == "student":

            cursor.execute(
                """
                SELECT *
                FROM outpass_requests
                WHERE roll_number = %s
                ORDER BY submitted_at DESC
                """,
                (user["username"],)
            )

        elif user["role"] == "parent":

            cursor.execute(
                """
                SELECT *
                FROM outpass_requests
                WHERE roll_number = %s
                ORDER BY submitted_at DESC
                """,
                (user["username"],)
            )

        elif user["role"] == "mentor":

            cursor.execute(
                """
                SELECT *
                FROM outpass_requests
                ORDER BY submitted_at DESC
                """
            )

        else:

            cursor.execute(
                """
                SELECT *
                FROM outpass_requests
                ORDER BY submitted_at DESC
                """
            )

        requests_data = cursor.fetchall()

        for item in requests_data:
            serialize_datetime_fields(item)

        return jsonify({
            "success": True,
            "requests":
                requests_data
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# GET SINGLE OUTPASS
# ============================================================

@app.route(
    "/api/outpasses/<outpass_id>",
    methods=["GET"]
)
@login_required([
    "student",
    "parent",
    "mentor",
    "security"
])
def get_single_outpass(outpass_id):

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT *
            FROM outpass_requests
            WHERE outpass_id = %s
            """,
            (outpass_id,)
        )

        item = cursor.fetchone()

        if not item:

            return jsonify({
                "success": False,
                "message":
                    "Outpass not found."
            }), 404

        user = get_auth_user()

        if user["role"] in (
            "student",
            "parent"
        ):

            if str(
                user["username"]
            ) != str(
                item["roll_number"]
            ):

                return jsonify({
                    "success": False,
                    "message":
                        "You cannot access another student's outpass."
                }), 403

        elif user["role"] == "mentor":

            # Mentors can review any student outpass request.
            pass

        serialize_datetime_fields(item)

        return jsonify({
            "success": True,
            "request": item
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# PARENT APPROVAL
# ============================================================

@app.route(
    "/api/outpasses/<outpass_id>/parent-approve",
    methods=["POST"]
)
@login_required([
    "parent",
    "student"
])
def parent_approve(outpass_id):

    connection = None
    cursor = None

    try:

        data = request.get_json(
            silent=True
        ) or {}

        otp = str(
            data.get("otp", "")
        ).strip()

        if (
            not otp
            or len(otp) != 6
            or not otp.isdigit()
        ):

            return jsonify({
                "success": False,
                "message":
                    "Enter a valid 6-digit OTP."
            }), 400

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT *
            FROM outpass_requests
            WHERE outpass_id = %s
            FOR UPDATE
            """,
            (outpass_id,)
        )

        outpass = cursor.fetchone()

        if not outpass:

            return jsonify({
                "success": False,
                "message":
                    "Outpass not found."
            }), 404

        user = get_auth_user()

        if str(
            user["username"]
        ) != str(
            outpass["roll_number"]
        ):

            return jsonify({
                "success": False,
                "message":
                    "You cannot approve another student's outpass."
            }), 403

        if outpass["parent_status"] == "Approved":

            return jsonify({
                "success": False,
                "message":
                    "Parent approval is already completed."
            }), 400

        attempts = (
            outpass["parent_otp_attempts"]
            or 0
        )

        if attempts >= MAX_OTP_ATTEMPTS:

            return jsonify({
                "success": False,
                "message":
                    "Maximum OTP attempts exceeded."
            }), 429

        if not outpass[
            "parent_otp_expires_at"
        ]:

            return jsonify({
                "success": False,
                "message":
                    "OTP is not available."
            }), 400

        if datetime.now() > outpass[
            "parent_otp_expires_at"
        ]:

            return jsonify({
                "success": False,
                "message":
                    "OTP has expired."
            }), 400

        if not verify_otp(
            otp,
            outpass["parent_otp_hash"]
        ):

            cursor.execute(
                """
                UPDATE outpass_requests
                SET parent_otp_attempts =
                    parent_otp_attempts + 1
                WHERE outpass_id = %s
                """,
                (outpass_id,)
            )

            connection.commit()

            remaining = max(
                0,
                MAX_OTP_ATTEMPTS
                - (attempts + 1)
            )

            return jsonify({
                "success": False,
                "message":
                    f"Incorrect OTP. {remaining} attempts remaining."
            }), 400

        cursor.execute(
            """
            UPDATE outpass_requests
            SET
                parent_status = 'Approved',
                overall_status =
                    'Waiting for Mentor Approval',
                parent_approved_at = NOW(),
                parent_otp_verified_at = NOW()
            WHERE outpass_id = %s
            """,
            (outpass_id,)
        )

        connection.commit()

        notify_outpass(
            outpass_id,
            "PARENT_APPROVED",
            f"Smart Outpass - Parent Approval Completed - {outpass_id}",
            (
                f"Parent approval has been completed "
                f"for outpass {outpass_id} for "
                f"student {outpass['student_name']} "
                f"(Roll No: {outpass['roll_number']}).\n\n"
                f"The request is now waiting for mentor approval.\n\n"
                f"Smart Outpass"
            ),
            include_student=True,
            include_parent=False,
            include_mentors=True,
            include_security=False
        )

        return jsonify({
            "success": True,
            "message":
                "Parent approval completed successfully."
        })

    except mysql.connector.Error as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# MENTOR APPROVE
# ============================================================

@app.route(
    "/api/outpasses/<outpass_id>/mentor-approve",
    methods=["POST"]
)
@login_required("mentor")
def mentor_approve(outpass_id):

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT *
            FROM outpass_requests
            WHERE outpass_id = %s
            FOR UPDATE
            """,
            (outpass_id,)
        )

        outpass = cursor.fetchone()

        if not outpass:

            return jsonify({
                "success": False,
                "message":
                    "Outpass not found."
            }), 404

        mentor = get_auth_user()

        if outpass["parent_status"] != "Approved":

            return jsonify({
                "success": False,
                "message":
                    "Parent approval is required first."
            }), 400

        if outpass["mentor_status"] == "Approved":

            return jsonify({
                "success": False,
                "message":
                    "Outpass is already mentor approved."
            }), 400

        if outpass["mentor_status"] == "Rejected":

            return jsonify({
                "success": False,
                "message":
                    "This outpass has already been rejected."
            }), 400

        cursor.execute(
            """
            UPDATE outpass_requests
            SET
                mentor_status = 'Approved',
                mentor_approved_at = NOW(),
                mentor_rejection_reason = NULL,
                mentor_rejected_at = NULL,
                overall_status =
                    'Waiting for Security Approval'
            WHERE outpass_id = %s
            """,
            (outpass_id,)
        )

        connection.commit()

        notify_outpass(
            outpass_id,
            "MENTOR_APPROVED",
            f"Smart Outpass - Mentor Approved - {outpass_id}",
            (
                f"The mentor has approved outpass "
                f"{outpass_id} for "
                f"{outpass['student_name']} "
                f"(Roll No: {outpass['roll_number']}).\n\n"
                f"The request is now waiting for security verification.\n\n"
                f"Smart Outpass"
            ),
            include_student=True,
            include_parent=True,
            include_mentors=False,
            include_security=True
        )

        return jsonify({
            "success": True,
            "message":
                "Outpass approved by mentor."
        })

    except mysql.connector.Error as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# MENTOR REJECT
# ============================================================

@app.route(
    "/api/outpasses/<outpass_id>/mentor-reject",
    methods=["POST"]
)
@login_required("mentor")
def mentor_reject(outpass_id):

    connection = None
    cursor = None

    try:

        data = request.get_json(
            silent=True
        ) or {}

        reason = str(
            data.get("reason", "")
        ).strip()

        if not reason:

            return jsonify({
                "success": False,
                "message":
                    "Rejection reason is required."
            }), 400

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT *
            FROM outpass_requests
            WHERE outpass_id = %s
            FOR UPDATE
            """,
            (outpass_id,)
        )

        outpass = cursor.fetchone()

        if not outpass:

            return jsonify({
                "success": False,
                "message":
                    "Outpass not found."
            }), 404

        mentor = get_auth_user()

        if outpass["parent_status"] != "Approved":

            return jsonify({
                "success": False,
                "message":
                    "Parent approval is required first."
            }), 400

        if outpass["mentor_status"] == "Approved":

            return jsonify({
                "success": False,
                "message":
                    "Approved outpass cannot be rejected."
            }), 400

        cursor.execute(
            """
            UPDATE outpass_requests
            SET
                mentor_status = 'Rejected',
                mentor_rejection_reason = %s,
                mentor_rejected_at = NOW(),
                overall_status =
                    'Rejected by Mentor'
            WHERE outpass_id = %s
            """,
            (
                reason,
                outpass_id
            )
        )

        connection.commit()

        notify_outpass(
            outpass_id,
            "MENTOR_REJECTED",
            f"Smart Outpass - Mentor Rejected - {outpass_id}",
            (
                f"The mentor has rejected outpass "
                f"{outpass_id} for "
                f"{outpass['student_name']} "
                f"(Roll No: {outpass['roll_number']}).\n\n"
                f"Reason: {reason}\n\n"
                f"Smart Outpass"
            ),
            include_student=True,
            include_parent=True,
            include_mentors=False,
            include_security=False
        )

        return jsonify({
            "success": True,
            "message":
                "Outpass rejected by mentor."
        })

    except mysql.connector.Error as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# MENTOR DASHBOARD
# ============================================================

@app.route(
    "/api/mentor/dashboard",
    methods=["GET"]
)
@login_required("mentor")
def mentor_dashboard():

    connection = None
    cursor = None

    try:

        mentor = get_auth_user()

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE parent_status = 'Approved'
              AND mentor_status = 'Pending'
            """
        )

        pending = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE mentor_status = 'Approved'
            """
        )

        approved = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE mentor_status = 'Rejected'
            """
        )

        rejected = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            """
        )

        total = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT
                outpass_id,
                student_name,
                roll_number,
                department,
                year,
                destination,
                outpass_date,
                exit_time,
                return_date,
                reason,
                parent_status,
                mentor_status,
                security_status,
                overall_status,
                mentor_rejection_reason,
                mentor_approved_at,
                mentor_rejected_at,
                submitted_at
            FROM outpass_requests
            ORDER BY submitted_at DESC
            LIMIT 10
            """
        )

        recent_requests = cursor.fetchall()

        for item in recent_requests:
            serialize_datetime_fields(item)

        return jsonify({
            "success": True,
            "mentor": mentor,
            "statistics": {
                "pending": pending,
                "approved": approved,
                "rejected": rejected,
                "total": total
            },
            "recent_requests":
                recent_requests
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# SECURITY - GET OUTPASS
# ============================================================

@app.route(
    "/api/security/outpass/<outpass_id>",
    methods=["GET"]
)
@login_required("security")
def security_get_outpass(outpass_id):

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT *
            FROM outpass_requests
            WHERE outpass_id = %s
            """,
            (outpass_id,)
        )

        item = cursor.fetchone()

        if not item:

            return jsonify({
                "success": False,
                "message":
                    "Outpass not found."
            }), 404

        serialize_datetime_fields(item)

        return jsonify({
            "success": True,
            "outpass": item
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# SECURITY - EXIT
# ============================================================

@app.route(
    "/api/security/<outpass_id>/exit",
    methods=["POST"]
)
@login_required("security")
def security_allow_exit(outpass_id):

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        connection.start_transaction()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT *
            FROM outpass_requests
            WHERE outpass_id = %s
            FOR UPDATE
            """,
            (outpass_id,)
        )

        outpass = cursor.fetchone()

        if not outpass:

            connection.rollback()

            return jsonify({
                "success": False,
                "message":
                    "Outpass not found."
            }), 404

        if outpass["parent_status"] != "Approved":

            connection.rollback()

            return jsonify({
                "success": False,
                "message":
                    "Parent approval is incomplete."
            }), 400

        if outpass["mentor_status"] != "Approved":

            connection.rollback()

            return jsonify({
                "success": False,
                "message":
                    "Mentor approval is incomplete."
            }), 400

        if outpass["actual_exit_time"]:

            connection.rollback()

            return jsonify({
                "success": False,
                "message":
                    "Student has already exited."
            }), 400

        if outpass["actual_return_time"]:

            connection.rollback()

            return jsonify({
                "success": False,
                "message":
                    "This outpass is already completed."
            }), 400

        exit_timestamp = datetime.now()

        cursor.execute(
            """
            UPDATE outpass_requests
            SET
                actual_exit_time = %s,
                security_status = 'Outside',
                overall_status = 'Student Outside'
            WHERE outpass_id = %s
            """,
            (
                exit_timestamp,
                outpass_id
            )
        )

        connection.commit()

        notify_outpass(
            outpass_id,
            "SECURITY_EXIT",
            f"Smart Outpass - Exit Recorded - {outpass_id}",
            (
                f"Student {outpass['student_name']} "
                f"(Roll No: {outpass['roll_number']}) "
                f"has exited through security for "
                f"outpass {outpass_id}.\n\n"
                f"Exit time: "
                f"{exit_timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"Smart Outpass"
            ),
            include_student=True,
            include_parent=True,
            include_mentors=False,
            include_security=False
        )

        return jsonify({
            "success": True,
            "message":
                "Student exit recorded successfully.",
            "actual_exit_time":
                exit_timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
        })

    except mysql.connector.Error as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# SECURITY - RETURN
# ============================================================

@app.route(
    "/api/security/<outpass_id>/return",
    methods=["POST"]
)
@login_required("security")
def security_record_return(outpass_id):

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        connection.start_transaction()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT *
            FROM outpass_requests
            WHERE outpass_id = %s
            FOR UPDATE
            """,
            (outpass_id,)
        )

        outpass = cursor.fetchone()

        if not outpass:

            connection.rollback()

            return jsonify({
                "success": False,
                "message":
                    "Outpass not found."
            }), 404

        if not outpass["actual_exit_time"]:

            connection.rollback()

            return jsonify({
                "success": False,
                "message":
                    "Student has not been marked as exited."
            }), 400

        if outpass["actual_return_time"]:

            connection.rollback()

            return jsonify({
                "success": False,
                "message":
                    "Student return is already recorded."
            }), 400

        return_timestamp = datetime.now()

        cursor.execute(
            """
            UPDATE outpass_requests
            SET
                actual_return_time = %s,
                security_status = 'Returned',
                overall_status = 'Completed'
            WHERE outpass_id = %s
            """,
            (
                return_timestamp,
                outpass_id
            )
        )

        connection.commit()

        notify_outpass(
            outpass_id,
            "SECURITY_RETURN",
            f"Smart Outpass - Return Recorded - {outpass_id}",
            (
                f"Student {outpass['student_name']} "
                f"(Roll No: {outpass['roll_number']}) "
                f"has returned for outpass "
                f"{outpass_id}.\n\n"
                f"Return time: "
                f"{return_timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"Smart Outpass"
            ),
            include_student=True,
            include_parent=True,
            include_mentors=False,
            include_security=False
        )

        return jsonify({
            "success": True,
            "message":
                "Student return recorded successfully.",
            "actual_return_time":
                return_timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
        })

    except mysql.connector.Error as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# SECURITY EXIT RECORDS
# ============================================================

@app.route(
    "/api/security/exit-records",
    methods=["GET"]
)
@login_required("security")
def security_exit_records():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                outpass_id,
                student_name,
                roll_number,
                department,
                year,
                destination,
                outpass_date,
                exit_time,
                return_date,
                actual_exit_time,
                actual_return_time,
                parent_status,
                mentor_status,
                security_status,
                overall_status,
                submitted_at
            FROM outpass_requests
            WHERE actual_exit_time IS NOT NULL
            ORDER BY actual_exit_time DESC
            """
        )

        records = cursor.fetchall()

        for item in records:
            serialize_datetime_fields(item)

        return jsonify({
            "success": True,
            "records": records
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# SECURITY RETURN RECORDS
# ============================================================

@app.route(
    "/api/security/return-records",
    methods=["GET"]
)
@login_required("security")
def security_return_records():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                outpass_id,
                student_name,
                roll_number,
                department,
                year,
                destination,
                outpass_date,
                exit_time,
                return_date,
                actual_exit_time,
                actual_return_time,
                parent_status,
                mentor_status,
                security_status,
                overall_status,
                submitted_at
            FROM outpass_requests
            WHERE actual_return_time IS NOT NULL
            ORDER BY actual_return_time DESC
            """
        )

        records = cursor.fetchall()

        for item in records:
            serialize_datetime_fields(item)

        return jsonify({
            "success": True,
            "records": records
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# SECURITY DASHBOARD
# ============================================================

@app.route(
    "/api/security/dashboard",
    methods=["GET"]
)
@login_required("security")
def security_dashboard():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE
                parent_status = 'Approved'
                AND mentor_status = 'Approved'
                AND security_status = 'Not Exited'
            """
        )

        approved_outpasses = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE security_status = 'Outside'
            """
        )

        currently_outside = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE
                actual_return_time IS NOT NULL
                AND DATE(actual_return_time) = CURDATE()
            """
        )

        returned_today = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE
                parent_status = 'Approved'
                AND mentor_status = 'Approved'
                AND actual_exit_time IS NULL
                AND security_status = 'Not Exited'
            """
        )

        awaiting_verification = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            """
        )

        total = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE parent_status = 'Pending'
            """
        )

        parent_pending = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE
                parent_status = 'Approved'
                AND mentor_status = 'Pending'
            """
        )

        mentor_pending = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE security_status = 'Returned'
            """
        )

        returned = cursor.fetchone()["count"]

        return jsonify({
            "success": True,

            "approved_outpasses":
                approved_outpasses,

            "currently_outside":
                currently_outside,

            "returned_today":
                returned_today,

            "awaiting_verification":
                awaiting_verification,

            "statistics": {
                "total": total,
                "approved_outpasses":
                    approved_outpasses,
                "currently_outside":
                    currently_outside,
                "returned_today":
                    returned_today,
                "awaiting_verification":
                    awaiting_verification,
                "parent_pending":
                    parent_pending,
                "mentor_pending":
                    mentor_pending,
                "returned":
                    returned
            }
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# EMAIL NOTIFICATIONS
# ============================================================

@app.route(
    "/api/notifications",
    methods=["GET"]
)
@login_required([
    "student",
    "parent",
    "mentor",
    "security"
])
def get_notifications():

    connection = None
    cursor = None

    try:

        user = get_auth_user()

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        if user["role"] == "student":

            cursor.execute(
                """
                SELECT *
                FROM email_notifications
                WHERE recipient_email = (
                    SELECT email
                    FROM students
                    WHERE roll_number = %s
                )
                ORDER BY created_at DESC
                LIMIT 100
                """,
                (user["username"],)
            )

        elif user["role"] == "parent":

            cursor.execute(
                """
                SELECT *
                FROM email_notifications
                WHERE recipient_email = (
                    SELECT email
                    FROM parents
                    WHERE student_roll_number = %s
                )
                ORDER BY created_at DESC
                LIMIT 100
                """,
                (user["username"],)
            )

        elif user["role"] == "mentor":

            cursor.execute(
                """
                SELECT en.*
                FROM email_notifications en
                JOIN outpass_requests o
                    ON o.outpass_id = en.outpass_id
                WHERE o.department = %s
                ORDER BY en.created_at DESC
                LIMIT 100
                """,
                (user["department"],)
            )

        else:

            cursor.execute(
                """
                SELECT *
                FROM email_notifications
                ORDER BY created_at DESC
                LIMIT 100
                """
            )

        notifications = cursor.fetchall()

        for item in notifications:
            serialize_datetime_fields(item)

        return jsonify({
            "success": True,
            "notifications":
                notifications
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# ============================================================
# ADMIN SECTION
# ============================================================
# ============================================================


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route(
    "/api/admin/dashboard",
    methods=["GET"]
)
@login_required("admin")
def admin_dashboard():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        # ----------------------------------------------------
        # STUDENTS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM students
            """
        )

        total_students = (
            cursor.fetchone()["count"]
        )

        # ----------------------------------------------------
        # PARENTS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM parents
            """
        )

        total_parents = (
            cursor.fetchone()["count"]
        )

        # ----------------------------------------------------
        # MENTORS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM mentors
            """
        )

        total_mentors = (
            cursor.fetchone()["count"]
        )

        # ----------------------------------------------------
        # SECURITY USERS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM security_users
            """
        )

        total_security = (
            cursor.fetchone()["count"]
        )

        # ----------------------------------------------------
        # OUTPASSES
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            """
        )

        total_outpasses = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE parent_status = 'Pending'
            """
        )

        pending_parent = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE
                parent_status = 'Approved'
                AND mentor_status = 'Pending'
            """
        )

        pending_mentor = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE
                parent_status = 'Approved'
                AND mentor_status = 'Approved'
                AND actual_exit_time IS NULL
                AND security_status = 'Not Exited'
            """
        )

        waiting_security = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE security_status = 'Outside'
            """
        )

        currently_outside = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE security_status = 'Returned'
            """
        )

        completed = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE mentor_status = 'Rejected'
            """
        )

        rejected = (
            cursor.fetchone()["count"]
        )

        # ----------------------------------------------------
        # RECENT OUTPASSES
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                outpass_id,
                student_name,
                roll_number,
                department,
                destination,
                outpass_date,
                parent_status,
                mentor_status,
                security_status,
                overall_status,
                submitted_at
            FROM outpass_requests
            ORDER BY submitted_at DESC
            LIMIT 10
            """
        )

        recent_outpasses = (
            cursor.fetchall()
        )

        for item in recent_outpasses:
            serialize_datetime_fields(item)

        # ----------------------------------------------------
        # RECENT EMAIL NOTIFICATIONS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                id,
                notification_type,
                recipient_email,
                recipient_name,
                roll_number,
                outpass_id,
                subject,
                status,
                sent_at,
                created_at
            FROM email_notifications
            ORDER BY created_at DESC
            LIMIT 10
            """
        )

        recent_notifications = (
            cursor.fetchall()
        )

        for item in recent_notifications:
            serialize_datetime_fields(item)

        # ----------------------------------------------------
        # TODAY'S ACTIVITY FOR ADMIN DASHBOARD
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                outpass_id,
                student_name,
                roll_number,
                overall_status,
                submitted_at
            FROM outpass_requests
            WHERE DATE(submitted_at) = CURDATE()
            ORDER BY submitted_at DESC
            LIMIT 50
            """
        )

        today_activity_rows = cursor.fetchall()
        activities = []

        for row in today_activity_rows:
            activities.append({
                "title": f"Outpass {row['outpass_id']} submitted",
                "description": (
                    f"{row['student_name']} "
                    f"(Roll No: {row['roll_number']})"
                ),
                "status": row["overall_status"] or "Pending",
                "created_at": row["submitted_at"]
            })

        for item in activities:
            serialize_datetime_fields(item)

        # The admin dashboard frontend uses short, stable names.
        # Keep the existing detailed names as well for other pages.
        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE DATE(submitted_at) = CURDATE()
            """
        )

        today_outpasses = cursor.fetchone()["count"]

        return jsonify({
            "success": True,

            "statistics": {
                "students": total_students,
                "parents": total_parents,
                "mentors": total_mentors,
                "security_users": total_security,
                "today_outpasses": today_outpasses,
                "currently_outside": currently_outside,

                "total_students":
                    total_students,

                "total_parents":
                    total_parents,

                "total_mentors":
                    total_mentors,

                "total_security":
                    total_security,

                "total_users":
                    (
                        total_students
                        + total_parents
                        + total_mentors
                        + total_security
                    ),

                "total_outpasses":
                    total_outpasses,

                "pending_parent":
                    pending_parent,

                "pending_mentor":
                    pending_mentor,

                "waiting_security":
                    waiting_security,

                "currently_outside":
                    currently_outside,

                "completed":
                    completed,

                "rejected":
                    rejected
            },

            "recent_outpasses":
                recent_outpasses,

            "recent_notifications":
                recent_notifications,

            "activities": activities
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# ADMIN - ALL OUTPASSES
# ============================================================

@app.route(
    "/api/admin/outpasses",
    methods=["GET"]
)
@login_required("admin")
def admin_outpasses():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        status_filter = str(
            request.args.get(
                "status",
                ""
            )
        ).strip()

        search = str(
            request.args.get(
                "search",
                ""
            )
        ).strip()

        query = """
            SELECT
                outpass_id,
                student_name,
                roll_number,
                department,
                year,
                destination,
                outpass_date,
                exit_time,
                return_date,
                reason,
                parent_status,
                mentor_status,
                security_status,
                overall_status,
                parent_approved_at,
                mentor_approved_at,
                mentor_rejection_reason,
                mentor_rejected_at,
                actual_exit_time,
                actual_return_time,
                submitted_at
            FROM outpass_requests
            WHERE 1 = 1
        """

        params = []

        if status_filter:

            query += """
                AND overall_status = %s
            """

            params.append(
                status_filter
            )

        if search:

            query += """
                AND (
                    outpass_id LIKE %s
                    OR student_name LIKE %s
                    OR roll_number LIKE %s
                    OR department LIKE %s
                    OR destination LIKE %s
                )
            """

            search_value = (
                f"%{search}%"
            )

            params.extend([
                search_value,
                search_value,
                search_value,
                search_value,
                search_value
            ])

        query += """
            ORDER BY submitted_at DESC
        """

        cursor.execute(
            query,
            tuple(params)
        )

        records = cursor.fetchall()

        for item in records:
            serialize_datetime_fields(item)

        # ----------------------------------------------------
        # SUMMARY COUNTS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,

                SUM(
                    CASE
                        WHEN parent_status = 'Pending'
                        THEN 1 ELSE 0
                    END
                ) AS parent_pending,

                SUM(
                    CASE
                        WHEN parent_status = 'Approved'
                         AND mentor_status = 'Pending'
                        THEN 1 ELSE 0
                    END
                ) AS mentor_pending,

                SUM(
                    CASE
                        WHEN mentor_status = 'Rejected'
                        THEN 1 ELSE 0
                    END
                ) AS rejected,

                SUM(
                    CASE
                        WHEN security_status = 'Returned'
                        THEN 1 ELSE 0
                    END
                ) AS completed,

                SUM(
                    CASE
                        WHEN security_status = 'Outside'
                        THEN 1 ELSE 0
                    END
                ) AS outside

            FROM outpass_requests
            """
        )

        summary = cursor.fetchone()

        return jsonify({
            "success": True,
            "requests": records,
            "summary": {
                "total":
                    summary["total"] or 0,

                "parent_pending":
                    summary["parent_pending"] or 0,

                "mentor_pending":
                    summary["mentor_pending"] or 0,

                "rejected":
                    summary["rejected"] or 0,

                "completed":
                    summary["completed"] or 0,

                "outside":
                    summary["outside"] or 0
            }
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# ADMIN - SINGLE OUTPASS
# ============================================================

@app.route(
    "/api/admin/outpasses/<outpass_id>",
    methods=["GET"]
)
@login_required("admin")
def admin_single_outpass(outpass_id):

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT *
            FROM outpass_requests
            WHERE outpass_id = %s
            """,
            (outpass_id,)
        )

        item = cursor.fetchone()

        if not item:

            return jsonify({
                "success": False,
                "message":
                    "Outpass not found."
            }), 404

        serialize_datetime_fields(item)

        return jsonify({
            "success": True,
            "request": item
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# ADMIN - USERS
# ============================================================

@app.route(
    "/api/admin/users",
    methods=["GET"]
)
@login_required("admin")
def admin_users():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        role_filter = str(
            request.args.get(
                "role",
                ""
            )
        ).strip().lower()

        search = str(
            request.args.get(
                "search",
                ""
            )
        ).strip()

        users = []

        # ----------------------------------------------------
        # STUDENTS
        # ----------------------------------------------------

        if not role_filter or role_filter == "student":

            query = """
                SELECT
                    id,
                    roll_number AS username,
                    name,
                    email,
                    mobile_number,
                    department,
                    year,
                    'Student' AS role,
                    status,
                    created_at
                FROM students
                WHERE 1 = 1
            """

            params = []

            if search:

                query += """
                    AND (
                        name LIKE %s
                        OR roll_number LIKE %s
                        OR email LIKE %s
                            OR mobile_number LIKE %s
                        OR department LIKE %s
                    )
                """

                value = f"%{search}%"

                params.extend([
                    value,
                    value,
                    value,
                    value,
                    value
                ])

            query += """
                ORDER BY created_at DESC
            """

            cursor.execute(
                query,
                tuple(params)
            )

            rows = cursor.fetchall()

            users.extend(rows)

        # ----------------------------------------------------
        # PARENTS
        # ----------------------------------------------------

        if not role_filter or role_filter == "parent":

            query = """
                SELECT
                    id,
                    student_roll_number AS username,
                    name,
                    email,
                    relationship,
                    mobile_number,
                    'Parent' AS role,
                    status,
                    created_at
                FROM parents
                WHERE 1 = 1
            """

            params = []

            if search:

                query += """
                    AND (
                        name LIKE %s
                        OR student_roll_number LIKE %s
                        OR email LIKE %s
                        OR mobile_number LIKE %s
                    )
                """

                value = f"%{search}%"

                params.extend([
                    value,
                    value,
                    value,
                    value
                ])

            query += """
                ORDER BY created_at DESC
            """

            cursor.execute(
                query,
                tuple(params)
            )

            rows = cursor.fetchall()

            users.extend(rows)

        # ----------------------------------------------------
        # MENTORS
        # ----------------------------------------------------

        if not role_filter or role_filter == "mentor":

            query = """
                SELECT
                    id,
                    employee_id AS username,
                    name,
                    email,
                    department,
                    'Mentor' AS role,
                    status,
                    created_at
                FROM mentors
                WHERE 1 = 1
            """

            params = []

            if search:

                query += """
                    AND (
                        name LIKE %s
                        OR employee_id LIKE %s
                        OR email LIKE %s
                        OR department LIKE %s
                    )
                """

                value = f"%{search}%"

                params.extend([
                    value,
                    value,
                    value,
                    value
                ])

            query += """
                ORDER BY created_at DESC
            """

            cursor.execute(
                query,
                tuple(params)
            )

            rows = cursor.fetchall()

            users.extend(rows)

        # ----------------------------------------------------
        # SECURITY
        # ----------------------------------------------------

        if (
            not role_filter
            or role_filter == "security"
        ):

            query = """
                SELECT
                    id,
                    employee_id AS username,
                    name,
                    email,
                    'Security' AS role,
                    status,
                    created_at
                FROM security_users
                WHERE 1 = 1
            """

            params = []

            if search:

                query += """
                    AND (
                        name LIKE %s
                        OR employee_id LIKE %s
                        OR email LIKE %s
                    )
                """

                value = f"%{search}%"

                params.extend([
                    value,
                    value,
                    value
                ])

            query += """
                ORDER BY created_at DESC
            """

            cursor.execute(
                query,
                tuple(params)
            )

            rows = cursor.fetchall()

            users.extend(rows)

        # ----------------------------------------------------
        # ADMINS
        # ----------------------------------------------------

        if not role_filter or role_filter == "admin":

            query = """
                SELECT
                    id,
                    username,
                    name,
                    email,
                    'Admin' AS role,
                    status,
                    created_at
                FROM admins
                WHERE 1 = 1
            """

            params = []

            if search:

                query += """
                    AND (
                        name LIKE %s
                        OR username LIKE %s
                        OR email LIKE %s
                    )
                """

                value = f"%{search}%"

                params.extend([
                    value,
                    value,
                    value
                ])

            query += """
                ORDER BY created_at DESC
            """

            cursor.execute(
                query,
                tuple(params)
            )

            rows = cursor.fetchall()

            users.extend(rows)

        for item in users:
            serialize_datetime_fields(item)

        # ----------------------------------------------------
        # COUNTS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM students
            """
        )

        student_count = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM parents
            """
        )

        parent_count = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM mentors
            """
        )

        mentor_count = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM security_users
            """
        )

        security_count = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM admins
            """
        )

        admin_count = (
            cursor.fetchone()["count"]
        )

        return jsonify({
            "success": True,
            "users": users,
            "summary": {
                "students":
                    student_count,

                "parents":
                    parent_count,

                "mentors":
                    mentor_count,

                "security":
                    security_count,

                "admins":
                    admin_count,

                "total":
                    (
                        student_count
                        + parent_count
                        + mentor_count
                        + security_count
                        + admin_count
                    )
            }
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# ADMIN - ADD USER
# ============================================================

@app.route(
    "/api/admin/users",
    methods=["POST"]
)
@login_required("admin")
def admin_add_user():

    connection = None
    cursor = None

    try:

        data = request.get_json(
            silent=True
        ) or {}

        role = str(
            data.get("role", "")
        ).strip().lower()

        name = str(
            data.get("name", "")
        ).strip()

        email = str(
            data.get("email", "")
        ).strip()

        password = str(
            data.get("password", "")
        ).strip()

        username = str(
            data.get("username", "")
        ).strip()

        department = str(
            data.get("department", "")
        ).strip()

        year = str(
            data.get("year", "")
        ).strip()

        mobile_number = str(
            data.get("mobile_number", "")
        ).strip()

        relationship = str(
            data.get("relationship", "")
        ).strip()

        student_roll_number = str(
            data.get(
                "student_roll_number",
                username
            )
        ).strip()

        if not role or not name:

            return jsonify({
                "success": False,
                "message":
                    "Role and name are required."
            }), 400

        allowed_roles = {
            "student",
            "parent",
            "mentor",
            "security",
            "admin"
        }

        if role not in allowed_roles:

            return jsonify({
                "success": False,
                "message":
                    "Invalid user role."
            }), 400

        connection = get_db_connection()

        cursor = connection.cursor()

        password_hash = hash_password(
            password
            if password
            else {
                "student":
                    DEFAULT_STUDENT_PASSWORD,

                "parent":
                    DEFAULT_PARENT_PASSWORD,

                "mentor":
                    DEFAULT_MENTOR_PASSWORD,

                "security":
                    DEFAULT_SECURITY_PASSWORD,

                "admin":
                    DEFAULT_ADMIN_PASSWORD
            }[role]
        )

        # ----------------------------------------------------
        # STUDENT
        # ----------------------------------------------------

        if role == "student":

            if not username:

                return jsonify({
                    "success": False,
                    "message":
                        "Student roll number is required."
                }), 400

            if not department or not year:

                return jsonify({
                    "success": False,
                    "message":
                        "Student department and year are required."
                }), 400

            cursor.execute(
                """
                INSERT INTO students
                (
                    roll_number,
                    name,
                    department,
                    year,
                    email,
                    mobile_number,
                    password_hash
                )
                VALUES
                (
                    %s,%s,%s,%s,%s,%s,%s
                )
                """,
                (
                    username,
                    name,
                    department,
                    year,
                    email or None,
                    mobile_number or None,
                    password_hash
                )
            )

        # ----------------------------------------------------
        # PARENT
        # ----------------------------------------------------

        elif role == "parent":

            if not student_roll_number:

                return jsonify({
                    "success": False,
                    "message":
                        "Student roll number is required for parent."
                }), 400

            if not mobile_number:

                return jsonify({
                    "success": False,
                    "message":
                        "Parent mobile number is required."
                }), 400

            if not relationship:

                relationship = "Parent"

            cursor.execute(
                """
                SELECT name
                FROM students
                WHERE roll_number = %s
                """,
                (student_roll_number,)
            )

            student = cursor.fetchone()

            if not student:

                return jsonify({
                    "success": False,
                    "message":
                        "Student roll number does not exist."
                }), 400

            cursor.execute(
                """
                INSERT INTO parents
                (
                    student_roll_number,
                    student_name,
                    name,
                    mobile_number,
                    relationship,
                    email,
                    password_hash
                )
                VALUES
                (
                    %s,%s,%s,%s,%s,%s,%s
                )
                """,
                (
                    student_roll_number,
                    student[0],
                    name,
                    mobile_number,
                    relationship,
                    email or None,
                    password_hash
                )
            )

        # ----------------------------------------------------
        # MENTOR
        # ----------------------------------------------------

        elif role == "mentor":

            if not username or not department:

                return jsonify({
                    "success": False,
                    "message":
                        "Mentor employee ID and department are required."
                }), 400

            cursor.execute(
                """
                INSERT INTO mentors
                (
                    employee_id,
                    name,
                    department,
                    email,
                    password_hash
                )
                VALUES
                (
                    %s,%s,%s,%s,%s
                )
                """,
                (
                    username,
                    name,
                    department,
                    email or None,
                    password_hash
                )
            )

        # ----------------------------------------------------
        # SECURITY
        # ----------------------------------------------------

        elif role == "security":

            if not username:

                return jsonify({
                    "success": False,
                    "message":
                        "Security employee ID is required."
                }), 400

            cursor.execute(
                """
                INSERT INTO security_users
                (
                    employee_id,
                    name,
                    email,
                    password_hash
                )
                VALUES
                (
                    %s,%s,%s,%s
                )
                """,
                (
                    username,
                    name,
                    email or None,
                    password_hash
                )
            )

        # ----------------------------------------------------
        # ADMIN
        # ----------------------------------------------------

        elif role == "admin":

            if not username:

                return jsonify({
                    "success": False,
                    "message":
                        "Admin username is required."
                }), 400

            cursor.execute(
                """
                INSERT INTO admins
                (
                    username,
                    name,
                    email,
                    password_hash,
                    status
                )
                VALUES
                (
                    %s,%s,%s,%s,'Active'
                )
                """,
                (
                    username,
                    name,
                    email or None,
                    password_hash
                )
            )

        connection.commit()

        return jsonify({
            "success": True,
            "message":
                f"{role.title()} user created successfully."
        }), 201

    except mysql.connector.IntegrityError as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                "A user with the same username, roll number, employee ID, or parent/student relationship already exists.",
            "database_error":
                str(error)
        }), 409

    except mysql.connector.Error as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        if connection:
            connection.rollback()

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# ADMIN - USER DETAILS
# ============================================================

@app.route(
    "/api/admin/users/<role>/<int:user_id>",
    methods=["PUT"]
)
@login_required("admin")
def admin_update_user(role, user_id):

    connection = None
    cursor = None

    try:
        data = request.get_json(silent=True) or {}
        role = role.lower().strip()
        name = str(data.get("name", "")).strip()
        email = str(data.get("email", "")).strip()
        username = str(data.get("username", "")).strip()
        department = str(data.get("department", "")).strip()
        year = str(data.get("year", "")).strip()
        mobile_number = str(data.get("mobile_number", "")).strip()
        relationship = str(data.get("relationship", "")).strip() or "Parent"
        student_roll_number = str(data.get("student_roll_number", "")).strip()
        password = str(data.get("password", "")).strip()

        table_map = {
            "student": "students",
            "parent": "parents",
            "mentor": "mentors",
            "security": "security_users",
            "admin": "admins"
        }
        table = table_map.get(role)
        if not table:
            return jsonify({"success": False, "message": "Invalid user role."}), 400
        if not name:
            return jsonify({"success": False, "message": "Name is required."}), 400

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(f"SELECT id FROM `{table}` WHERE id = %s", (user_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "message": "User not found."}), 404

        if role == "student":
            if not username or not department or not year:
                return jsonify({"success": False, "message": "Student roll number, department and year are required."}), 400
            update_sql = "UPDATE students SET roll_number = %s, name = %s, department = %s, year = %s, email = %s, mobile_number = %s"
            values = [username, name, department, year, email or None, mobile_number or None]
        elif role == "parent":
            if not student_roll_number or not mobile_number:
                return jsonify({"success": False, "message": "Student roll number and parent mobile number are required."}), 400
            cursor.execute("SELECT name FROM students WHERE roll_number = %s", (student_roll_number,))
            student = cursor.fetchone()
            if not student:
                return jsonify({"success": False, "message": "Student roll number does not exist."}), 400
            update_sql = "UPDATE parents SET student_roll_number = %s, student_name = %s, name = %s, mobile_number = %s, relationship = %s, email = %s"
            values = [student_roll_number, student[0], name, mobile_number, relationship, email or None]
        elif role == "mentor":
            if not username or not department:
                return jsonify({"success": False, "message": "Mentor employee ID and department are required."}), 400
            update_sql = "UPDATE mentors SET employee_id = %s, name = %s, department = %s, email = %s"
            values = [username, name, department, email or None]
        elif role == "security":
            if not username:
                return jsonify({"success": False, "message": "Security employee ID is required."}), 400
            update_sql = "UPDATE security_users SET employee_id = %s, name = %s, email = %s"
            values = [username, name, email or None]
        else:
            if not username:
                return jsonify({"success": False, "message": "Admin username is required."}), 400
            update_sql = "UPDATE admins SET username = %s, name = %s, email = %s"
            values = [username, name, email or None]

        if password:
            update_sql += ", password_hash = %s"
            values.append(hash_password(password))
        update_sql += " WHERE id = %s"
        values.append(user_id)
        cursor.execute(update_sql, tuple(values))
        connection.commit()

        return jsonify({"success": True, "message": f"{role.title()} user updated successfully."})

    except mysql.connector.IntegrityError:
        if connection:
            connection.rollback()
        return jsonify({"success": False, "message": "A user with the same username, roll number, employee ID, or parent/student relationship already exists."}), 409
    except mysql.connector.Error as error:
        if connection:
            connection.rollback()
        return jsonify({"success": False, "message": f"Database error: {error}"}), 500
    except Exception as error:
        if connection:
            connection.rollback()
        return jsonify({"success": False, "message": f"Server error: {error}"}), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route(
    "/api/admin/users/<role>/<int:user_id>",
    methods=["GET"]
)
@login_required("admin")
def admin_user_details(
    role,
    user_id
):

    connection = None
    cursor = None

    try:

        role = role.lower().strip()

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        if role == "student":

            cursor.execute(
                """
                SELECT
                    id,
                    roll_number,
                    name,
                    department,
                    year,
                    email,
                    mobile_number,
                    status,
                    created_at
                FROM students
                WHERE id = %s
                """,
                (user_id,)
            )

        elif role == "parent":

            cursor.execute(
                """
                SELECT
                    id,
                    student_roll_number,
                    student_name,
                    name,
                    mobile_number,
                    relationship,
                    email,
                    status,
                    created_at
                FROM parents
                WHERE id = %s
                """,
                (user_id,)
            )

        elif role == "mentor":

            cursor.execute(
                """
                SELECT
                    id,
                    employee_id,
                    name,
                    department,
                    email,
                    status,
                    created_at
                FROM mentors
                WHERE id = %s
                """,
                (user_id,)
            )

        elif role == "security":

            cursor.execute(
                """
                SELECT
                    id,
                    employee_id,
                    name,
                    email,
                    status,
                    created_at
                FROM security_users
                WHERE id = %s
                """,
                (user_id,)
            )

        elif role == "admin":

            cursor.execute(
                """
                SELECT
                    id,
                    username,
                    name,
                    email,
                    status,
                    created_at
                FROM admins
                WHERE id = %s
                """,
                (user_id,)
            )

        else:

            return jsonify({
                "success": False,
                "message":
                    "Invalid user role."
            }), 400

        user = cursor.fetchone()

        if not user:

            return jsonify({
                "success": False,
                "message":
                    "User not found."
            }), 404

        serialize_datetime_fields(user)

        return jsonify({
            "success": True,
            "user": user
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# ADMIN - UPDATE USER STATUS
# ============================================================

@app.route(
    "/api/admin/users/<role>/<int:user_id>/status",
    methods=["PATCH"]
)
@login_required("admin")
def admin_update_user_status(role, user_id):

    connection = None
    cursor = None

    try:
        data = request.get_json(silent=True) or {}
        status = str(data.get("status", "")).strip().title()

        if status not in {"Active", "Inactive"}:
            return jsonify({
                "success": False,
                "message": "Status must be Active or Inactive."
            }), 400

        role = role.lower().strip()
        table_map = {
            "student": "students",
            "parent": "parents",
            "mentor": "mentors",
            "security": "security_users",
            "admin": "admins"
        }

        table = table_map.get(role)
        if not table:
            return jsonify({
                "success": False,
                "message": "Invalid user role."
            }), 400

        # Do not allow the currently logged-in admin to disable itself.
        current = get_auth_user()
        if role == "admin" and int(current["id"]) == int(user_id) and status == "Inactive":
            return jsonify({
                "success": False,
                "message": "You cannot deactivate the currently logged-in admin."
            }), 400

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            f"UPDATE `{table}` SET status = %s WHERE id = %s",
            (status, user_id)
        )

        if cursor.rowcount == 0:
            connection.rollback()
            return jsonify({
                "success": False,
                "message": "User not found."
            }), 404

        connection.commit()

        return jsonify({
            "success": True,
            "message": f"{role.title()} status updated to {status}.",
            "status": status
        })

    except mysql.connector.Error as error:
        if connection:
            connection.rollback()
        return jsonify({
            "success": False,
            "message": f"Database error: {error}"
        }), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ============================================================
# ADMIN REPORTS
# ============================================================

@app.route(
    "/api/admin/reports",
    methods=["GET"]
)
@login_required("admin")
def admin_reports():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        # ----------------------------------------------------
        # MAIN COUNTS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            """
        )

        total = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE mentor_status = 'Approved'
            """
        )

        mentor_approved = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE mentor_status = 'Rejected'
            """
        )

        mentor_rejected = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM outpass_requests
            WHERE security_status = 'Returned'
            """
        )

        completed = (
            cursor.fetchone()["count"]
        )

        # ----------------------------------------------------
        # APPROVAL PERCENTAGES
        # ----------------------------------------------------

        if total > 0:

            approved_percentage = round(
                (
                    mentor_approved
                    / total
                ) * 100
            )

            rejected_percentage = round(
                (
                    mentor_rejected
                    / total
                ) * 100
            )

            pending_percentage = max(
                0,
                100
                - approved_percentage
                - rejected_percentage
            )

        else:

            approved_percentage = 0
            rejected_percentage = 0
            pending_percentage = 0

        # ----------------------------------------------------
        # TODAY
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS count
            FROM outpass_requests
            WHERE DATE(submitted_at) = CURDATE()
            """
        )

        today_submitted = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT
                COUNT(*) AS count
            FROM outpass_requests
            WHERE
                actual_exit_time IS NOT NULL
                AND DATE(actual_exit_time) = CURDATE()
            """
        )

        today_exits = (
            cursor.fetchone()["count"]
        )

        cursor.execute(
            """
            SELECT
                COUNT(*) AS count
            FROM outpass_requests
            WHERE
                actual_return_time IS NOT NULL
                AND DATE(actual_return_time) = CURDATE()
            """
        )

        today_returns = (
            cursor.fetchone()["count"]
        )

        # ----------------------------------------------------
        # LAST 7 DAYS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                DATE(submitted_at) AS report_date,
                COUNT(*) AS submitted,
                SUM(
                    CASE
                        WHEN mentor_status = 'Approved'
                        THEN 1 ELSE 0
                    END
                ) AS approved,
                SUM(
                    CASE
                        WHEN mentor_status = 'Rejected'
                        THEN 1 ELSE 0
                    END
                ) AS rejected,
                SUM(
                    CASE
                        WHEN security_status = 'Returned'
                        THEN 1 ELSE 0
                    END
                ) AS returned
            FROM outpass_requests
            WHERE submitted_at >=
                DATE_SUB(
                    CURDATE(),
                    INTERVAL 6 DAY
                )
            GROUP BY DATE(submitted_at)
            ORDER BY report_date ASC
            """
        )

        daily_rows = cursor.fetchall()

        for item in daily_rows:
            serialize_datetime_fields(item)

        # ----------------------------------------------------
        # TODAY'S RECORDS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                outpass_id,
                student_name,
                roll_number,
                department,
                destination,
                outpass_date,
                parent_status,
                mentor_status,
                security_status,
                overall_status,
                submitted_at,
                actual_exit_time,
                actual_return_time
            FROM outpass_requests
            WHERE DATE(submitted_at) = CURDATE()
            ORDER BY submitted_at DESC
            """
        )

        today_records = (
            cursor.fetchall()
        )

        for item in today_records:
            serialize_datetime_fields(item)

        # ----------------------------------------------------
        # EMAIL STATISTICS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(
                    CASE
                        WHEN status = 'Sent'
                        THEN 1 ELSE 0
                    END
                ) AS sent,
                SUM(
                    CASE
                        WHEN status = 'Failed'
                        THEN 1 ELSE 0
                    END
                ) AS failed
            FROM email_notifications
            """
        )

        email_summary = (
            cursor.fetchone()
        )

        # ----------------------------------------------------
        # EMAIL BY TYPE
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                notification_type,
                COUNT(*) AS count
            FROM email_notifications
            GROUP BY notification_type
            ORDER BY count DESC
            """
        )

        email_by_type = (
            cursor.fetchall()
        )

        return jsonify({
            "success": True,

            "summary": {
                "total":
                    total,

                "mentor_approved":
                    mentor_approved,

                "mentor_rejected":
                    mentor_rejected,

                "completed":
                    completed,

                "approved_percentage":
                    approved_percentage,

                "rejected_percentage":
                    rejected_percentage,

                "pending_percentage":
                    pending_percentage
            },

            "today": {
                "submitted":
                    today_submitted,

                "exits":
                    today_exits,

                "returns":
                    today_returns
            },

            "daily_activity":
                daily_rows,

            "today_records":
                today_records,

            "email_summary": {
                "total":
                    email_summary["total"]
                    or 0,

                "sent":
                    email_summary["sent"]
                    or 0,

                "failed":
                    email_summary["failed"]
                    or 0
            },

            "email_by_type":
                email_by_type
        })

    except mysql.connector.Error as error:

        return jsonify({
            "success": False,
            "message":
                f"Database error: {error}"
        }), 500

    except Exception as error:

        return jsonify({
            "success": False,
            "message":
                f"Server error: {error}"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health_check():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor()

        cursor.execute(
            "SELECT 1"
        )

        cursor.fetchone()

        return jsonify({
            "success": True,
            "status": "healthy",
            "database": "connected"
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "status": "unhealthy",
            "database": "disconnected",
            "message": str(error)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# APPLICATION STARTUP
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("SMART OUTPASS BACKEND")
    print("=" * 60)
    print(
        "Server : http://127.0.0.1:5000"
    )
    print(
        "Database : smart_outpass"
    )
    print(
        "OTP TEST MODE :",
        OTP_TEST_MODE
    )
    print(
        "SMTP CONFIGURED :",
        _email_configured()
    )
    print("=" * 60)

    ensure_database_compatibility()

    print()
    print("DEMO LOGIN ACCOUNTS")
    print("-" * 60)
    print(
        "Student  -> Username: 1   "
        "Password: Student@123"
    )
    print(
        "Parent   -> Username: 1   "
        "Password: Parent@123"
    )
    print(
        "Mentor   -> Username: 11  "
        "Password: Mentor@123"
    )
    print(
        "Security -> Username: 111 "
        "Password: Security@123"
    )
    print(
        f"Admin    -> Username: {DEFAULT_ADMIN_USERNAME} "
        f"Password: {DEFAULT_ADMIN_PASSWORD}"
    )
    print("-" * 60)
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
