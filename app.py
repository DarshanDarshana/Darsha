import os
import io
import json
import base64
import random
import qrcode
import mysql.connector

from datetime import datetime, timezone
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import firebase_admin
from firebase_admin import credentials, firestore
from twilio.rest import Client
from flask_babelplus import Babel, gettext as _
from dotenv import load_dotenv

# Load local env vars
load_dotenv("database.env")

# Flask setup
app = Flask(__name__, static_folder="static")
app.secret_key = os.environ["FLASK_SECRET_KEY"]

# Babel (i18n)
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'
babel = Babel(app)



@babel.localeselector
def get_locale():
    return session.get('language', 'en')

@app.route("/change_language", methods=["POST"])
def change_language():
    lang = request.form.get("language")
    if lang:
        session["language"] = lang
        flash(_("Language updated successfully."), "success")
    else:
        flash(_("Please select a language."), "danger")
    return redirect(url_for("settings"))

# Decode Firebase credentials from FIREBASE_CREDENTIALS (base64 JSON)
fb_b64 = os.getenv("FIREBASE_CREDENTIALS")
if not fb_b64:
    raise RuntimeError("FIREBASE_CREDENTIALS environment variable not set")
fb_json = base64.b64decode(fb_b64)
fb_dict = json.loads(fb_json)
cred = credentials.Certificate(fb_dict)
firebase_admin.initialize_app(cred)
firestore_db = firestore.client()

# --------------------------
# MySQL Connection Helper
# --------------------------
def get_mysql_cursor():
    conn = mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASSWORD", "root"),
        database=os.getenv("MYSQL_DATABASE", "hope_pay")
    )
    return conn, conn.cursor(dictionary=True)

# --------------------------
# Initialize Firebase Firestore
# --------------------------
fb_b64 = os.getenv("FIREBASE_CREDENTIALS")
if fb_b64:
    # Production: decode the base64 JSON from env var
    fb_json = base64.b64decode(fb_b64)
    fb_dict = json.loads(fb_json)
    cred = credentials.Certificate(fb_dict)
else:
    # Development: fall back to your local service‑account file
    # Make sure this filename matches exactly what’s in your project root
    local_path = "firebase_b64.txt"
    cred = credentials.Certificate(local_path)

firebase_admin.initialize_app(cred)
firestore_db = firestore.client()

# --------------------------
# Helper: Convert Firestore Timestamp -> String
# --------------------------
def convert_firestore_ts(ts):
    return ts.strftime("%b %d, %I:%M %p - Settled") if ts else "N/A"

# --------------------------
# Helper: Get User Balance
# --------------------------
def get_user_balance(username):
    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT balance FROM users WHERE username=%s", (username,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row["balance"] if row and "balance" in row else 0

# --------------------------
# Helper: Get User Info (username, profile_pic, and phone)
# --------------------------
def get_user_info(username):
    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT username, profile_pic, phone FROM users WHERE username=%s", (username,))
    info = cursor.fetchone()
    cursor.close()
    conn.close()
    return info

# --------------------------
# Helper: Get User Phone
# --------------------------
def get_user_phone(username):
    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT phone FROM users WHERE username=%s", (username,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row["phone"] if row and "phone" in row else None

# --------------------------
# Helper: Generate Unique Card Number
# --------------------------
def generate_unique_card_number():
    while True:
        number = "".join([str(random.randint(0, 9)) for _ in range(16)])
        formatted = " ".join([number[i:i + 4] for i in range(0, 16, 4)])
        conn, cursor = get_mysql_cursor()
        cursor.execute("SELECT * FROM users WHERE card_number=%s", (formatted,))
        exists = cursor.fetchone()
        cursor.close()
        conn.close()
        if not exists:
            return formatted

# --------------------------
# Twilio SMS Sending Helper
# --------------------------
def send_sms(phone, text):
    client = Client(
        os.environ["TWILIO_ACCOUNT_SID"],
        os.environ["TWILIO_AUTH_TOKEN"]
    )
    try:
        msg = client.messages.create(body=text,
                                     from_=os.environ["TWILIO_PHONE"],
                                     to=phone)
        return msg.sid
    except:
        return None

# --------------------------
# Routes
# --------------------------
@app.route("/")
def index():
    return redirect(url_for("login"))

# --- Registration for Parents with Phone Verification ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        parent_email = request.form.get("parent_email").strip()
        phone = request.form.get("phone").strip()

        if not username or not password or not confirm_password or not parent_email or not phone:
            flash(_("Please fill in all the fields."), "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash(_("Passwords do not match!"), "danger")
            return redirect(url_for("register"))

        conn, cursor = get_mysql_cursor()
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        if cursor.fetchone():
            flash(_("Username already exists!"), "danger")
            cursor.close()
            conn.close()
            return redirect(url_for("register"))
        cursor.close()
        conn.close()

        otp = str(random.randint(100000, 999999))
        try:
            sms_sid = send_sms(phone, f"Your OTP for HOPE PAY registration is: {otp}")
            print(f"SMS sent, SID: {sms_sid}")
        except Exception as e:
            print("Error sending SMS:", e)
            flash(_("Failed to send verification code. Please try again."), "danger")
            return redirect(url_for("register"))

        session["reg_data"] = {
            "username": username,
            "password": password,  # Will hash after verification
            "parent_email": parent_email,
            "phone": phone
        }
        session["reg_otp"] = otp

        flash(_("A verification code has been sent to your phone. Please verify to complete registration."), "info")
        return redirect(url_for("verify_registration"))
    return render_template("register.html")

# --- Verify Registration ---
@app.route("/verify_registration", methods=["GET", "POST"])
def verify_registration():
    if "reg_data" not in session or "reg_otp" not in session:
        flash(_("Registration session expired. Please register again."), "danger")
        return redirect(url_for("register"))
    if request.method == "POST":
        entered_otp = request.form.get("otp").strip()
        if entered_otp == session["reg_otp"]:
            reg_data = session["reg_data"]
            hashed_pw = generate_password_hash(reg_data["password"])
            card_number = generate_unique_card_number()
            conn, cursor = get_mysql_cursor()
            cursor.execute("""
                INSERT INTO users (username, password, balance, role, parent_email, phone, card_number)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (reg_data["username"], hashed_pw, 100.0, 'parent', reg_data["parent_email"], reg_data["phone"], card_number))
            conn.commit()
            cursor.close()
            conn.close()
            session.pop("reg_data", None)
            session.pop("reg_otp", None)
            flash(_("Registration successful. You can now log in."), "success")
            return redirect(url_for("login"))
        else:
            flash(_("Invalid verification code. Please try again."), "danger")
            return redirect(url_for("verify_registration"))
    return render_template("verify_registration.html")

# --- Login ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        selected_role = request.form["role"]  # 'parent' or 'child'
        conn, cursor = get_mysql_cursor()
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user and check_password_hash(user["password"], password):
            if user["role"] != selected_role:
                flash(_("Invalid credentials."), "danger")
                return redirect(url_for("login"))
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["card_number"] = user.get("card_number", "**** **** **** 0000")
            flash(_("Logged in successfully!"), "success")
            return redirect(url_for("dashboard"))
        else:
            flash(_("Invalid credentials."), "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

# --- Logout ---
@app.route("/logout")
def logout():
    session.clear()
    flash(_("Logged out successfully."), "info")
    return redirect(url_for("login"))

# --- Dashboard ---
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    balance = get_user_balance(session["username"])
    current_user = session["username"]

    sent_docs = firestore_db.collection("transactions").where("sender", "==", current_user).stream()
    received_docs = firestore_db.collection("transactions").where("recipient", "==", current_user).stream()

    daily_totals = defaultdict(float)
    def aggregate_transactions(docs):
        for doc in docs:
            tx = doc.to_dict()
            ts = tx.get("timestamp")
            if ts:
                date_str = ts.strftime("%Y-%m-%d")
                daily_totals[date_str] += tx.get("amount", 0)
    aggregate_transactions(sent_docs)
    aggregate_transactions(received_docs)

    sorted_dates = sorted(daily_totals.keys())
    chart_labels = sorted_dates
    chart_data = [daily_totals[date] for date in sorted_dates]

    return render_template("dashboard.html", balance=balance, chart_labels=chart_labels, chart_data=chart_data)

# --- Pay Endpoint (with Transaction Categorization) ---
@app.route("/pay", methods=["GET", "POST"])
def pay():
    if "username" not in session:
        return redirect(url_for("login"))
    current_user = session["username"]

    # Check if user's PIN is set
    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT pin FROM users WHERE username=%s", (current_user,))
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()
    pin_set = user_data and user_data.get("pin") is not None

    if request.method == "GET":
        balance = get_user_balance(current_user)
        return render_template("pay.html", balance=balance, pin_set=pin_set)

    # For POST, enforce that a PIN is set (should not happen if the GET check worked)
    if not pin_set:
        flash(_("No PIN set for your account. Please set a PIN in settings."), "danger")
        return redirect(url_for("settings"))

    recipient = request.form["recipient"]
    amount_str = request.form["amount"]
    category = request.form.get("category", "Uncategorized")
    entered_pin = request.form.get("pin")

    try:
        amount = float(amount_str)
    except ValueError:
        flash(_("Invalid amount entered. Please enter a valid number."), "danger")
        return redirect(url_for("pay"))

    if not entered_pin:
        flash(_("Please enter your PIN to confirm the payment."), "danger")
        return redirect(url_for("pay"))

    # Retrieve stored PIN from the database
    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT pin FROM users WHERE username=%s", (current_user,))
    user_data = cursor.fetchone()
    if not user_data or user_data.get("pin") is None:
        flash(_("No PIN set for your account. Please set a PIN in settings."), "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("settings"))

    stored_pin = user_data["pin"]
    if entered_pin != stored_pin:
        flash(_("Incorrect PIN. Please try again."), "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("pay"))

    # Proceed with payment processing if the PIN is correct
    cursor.execute("SELECT * FROM users WHERE username=%s", (current_user,))
    sender_data = cursor.fetchone()
    if not sender_data:
        flash(_("Sender not found!"), "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("pay"))
    sender_balance = float(sender_data["balance"])

    cursor.execute("SELECT * FROM users WHERE username=%s", (recipient,))
    recipient_data = cursor.fetchone()
    if not recipient_data:
        flash(_("Recipient does not exist!"), "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("pay"))

    if sender_balance < amount:
        transaction_status = "failed_insufficient_funds"
        flash(_("Insufficient balance!"), "danger")
    else:
        transaction_status = "completed"
        new_sender_balance = sender_balance - amount
        cursor.execute("UPDATE users SET balance=%s WHERE username=%s", (new_sender_balance, current_user))
        conn.commit()
        recipient_balance = float(recipient_data["balance"])
        new_recipient_balance = recipient_balance + amount
        cursor.execute("UPDATE users SET balance=%s WHERE username=%s", (new_recipient_balance, recipient))
        conn.commit()
        flash(_("Payment successful!"), "success")

    transaction_data = {
        "sender": current_user,
        "recipient": recipient,
        "amount": amount,
        "timestamp": firestore.SERVER_TIMESTAMP,
        "status": transaction_status,
        "category": category
    }
    firestore_db.collection("transactions").add(transaction_data)
    cursor.close()
    conn.close()

    parent_phone = get_user_phone(current_user)
    if parent_phone:
        sms_message = f"Transaction Alert: You have sent {amount} to {recipient}."
        send_sms(parent_phone, sms_message)

    return redirect(url_for("pay"))

# --- History ---
@app.route("/history")
def history():
    if "username" not in session:
        return redirect(url_for("login"))
    current_user = session["username"]
    sent_docs = firestore_db.collection("transactions").where("sender", "==", current_user).stream()
    received_docs = firestore_db.collection("transactions").where("recipient", "==", current_user).stream()
    transactions = []
    for doc in sent_docs:
        data = doc.to_dict()
        data["type"] = "Sent"
        data["doc_id"] = doc.id
        data["timestamp_str"] = convert_firestore_ts(data.get("timestamp"))
        data["sender_info"] = get_user_info(data["sender"])
        data["recipient_info"] = get_user_info(data["recipient"])
        transactions.append(data)
    for doc in received_docs:
        data = doc.to_dict()
        data["type"] = "Received"
        data["doc_id"] = doc.id
        data["timestamp_str"] = convert_firestore_ts(data.get("timestamp"))
        data["sender_info"] = get_user_info(data["sender"])
        data["recipient_info"] = get_user_info(data["recipient"])
        transactions.append(data)

    def to_naive(dt):
        if dt is None:
            return datetime.min
        return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt

    transactions.sort(key=lambda t: to_naive(t.get("timestamp")), reverse=True)
    return render_template("history.html", transactions=transactions)

# --- Receipt (Transaction Details) ---
@app.route("/receipt/<doc_id>")
def receipt(doc_id):
    if "username" not in session:
        return redirect(url_for("login"))
    doc = firestore_db.collection("transactions").document(doc_id).get()
    if not doc.exists:
        flash(_("Transaction not found."), "danger")
        return redirect(url_for("history"))
    tx = doc.to_dict()
    current_time = datetime.now(timezone.utc).strftime("%b %d, %I:%M %p")
    return render_template("receipt.html",
                           sender=tx.get("sender", "N/A"),
                           recipient=tx.get("recipient", "N/A"),
                           amount=tx.get("amount", "N/A"),
                           category=tx.get("category", "Uncategorized"),
                           current_time=current_time)

# --- Create Child Form ---
@app.route("/create_child_form")
def create_child_form():
    if "username" not in session or session.get("role") != "parent":
        flash(_("Unauthorized."), "danger")
        return redirect(url_for("login"))
    return render_template("create_child_form.html")

# --- Create Child (by Parent) ---
@app.route("/create_child", methods=["POST"])
def create_child():
    if "username" not in session or session.get("role") != "parent":
        flash(_("Unauthorized"), "danger")
        return redirect(url_for("login"))
    child_username = request.form["child_username"]
    child_password = request.form["child_password"]
    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT * FROM users WHERE username=%s", (child_username,))
    if cursor.fetchone():
        flash(_("Child username already exists!"), "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("kid_safety"))
    hashed_pw = generate_password_hash(child_password)
    parent_user = session["username"]
    cursor.execute("""
        INSERT INTO users (username, password, balance, role, parent_username, daily_limit)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (child_username, hashed_pw, 0.0, 'child', parent_user, 0.0))
    conn.commit()
    cursor.close()
    conn.close()
    flash(_("Child account created successfully!"), "success")
    return redirect(url_for("kid_safety"))

# --- Set Child Limit and Confirmation Email ---
@app.route("/set_child_limit", methods=["POST"])
def set_child_limit():
    if "username" not in session or session.get("role") != "parent":
        flash(_("Unauthorized."), "danger")
        return redirect(url_for("login"))
    child_username = request.form["child_username"]
    new_limit_str = request.form["new_limit"]
    new_confirmation_email = request.form.get("confirmation_email")
    try:
        new_limit = float(new_limit_str)
    except ValueError:
        flash(_("Invalid limit amount."), "danger")
        return redirect(url_for("kid_safety", child_username=child_username))
    conn, cursor = get_mysql_cursor()
    cursor.execute("""
        UPDATE users 
        SET daily_limit=%s, confirmation_email=%s
        WHERE username=%s AND role='child' AND parent_username=%s
    """, (new_limit, new_confirmation_email, child_username, session["username"]))
    conn.commit()
    cursor.close()
    conn.close()
    flash(_("Daily limit and confirmation email updated!"), "success")
    return redirect(url_for("kid_safety", child_username=child_username))

# --- Kid Safety: View Child Accounts and Details ---
@app.route("/kid_safety")
def kid_safety():
    if "username" not in session or session.get("role") != "parent":
        flash(_("Unauthorized."), "danger")
        return redirect(url_for("login"))
    parent_user = session["username"]
    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT username FROM users WHERE role='child' AND parent_username=%s", (parent_user,))
    child_accounts = cursor.fetchall()
    cursor.close()
    conn.close()
    child_username = request.args.get("child_username")
    selected_child_balance = None
    selected_child_transactions = None
    selected_child_limit = None
    selected_confirmation_email = None
    if child_username:
        conn, cursor = get_mysql_cursor()
        cursor.execute("""
            SELECT balance, daily_limit, confirmation_email
            FROM users
            WHERE username=%s AND role='child' AND parent_username=%s
        """, (child_username, parent_user))
        child_row = cursor.fetchone()
        cursor.close()
        conn.close()
        if not child_row:
            flash(_("Child account not found or not yours."), "danger")
            return redirect(url_for("kid_safety"))
        selected_child_balance = float(child_row["balance"])
        selected_child_limit = float(child_row["daily_limit"])
        selected_confirmation_email = child_row.get("confirmation_email") or ""
        child_sent = firestore_db.collection("transactions").where("sender", "==", child_username).stream()
        child_received = firestore_db.collection("transactions").where("recipient", "==", child_username).stream()
        all_transactions = []
        for doc in child_sent:
            data = doc.to_dict()
            data["type"] = "Sent"
            data["doc_id"] = doc.id
            data["timestamp_str"] = convert_firestore_ts(data.get("timestamp"))
            all_transactions.append(data)
        for doc in child_received:
            data = doc.to_dict()
            data["type"] = "Received"
            data["doc_id"] = doc.id
            data["timestamp_str"] = convert_firestore_ts(data.get("timestamp"))
            all_transactions.append(data)
        all_transactions.sort(key=lambda t: t.get("timestamp").timestamp() if t.get("timestamp") else datetime.min,
                              reverse=True)
        selected_child_transactions = all_transactions[:5]
    return render_template(
        "kid_safety.html",
        child_accounts=child_accounts,
        child_username=child_username,
        child_balance=selected_child_balance,
        child_limit=selected_child_limit,
        confirmation_email=selected_confirmation_email,
        child_transactions=selected_child_transactions
    )

# --- Confirm Payment Endpoint ---
@app.route("/confirm_payment")
def confirm_payment():
    child = request.args.get("child")
    recipient = request.args.get("recipient")
    amount_str = request.args.get("amount")
    try:
        amount = float(amount_str)
    except:
        flash(_("Invalid amount."), "danger")
        return render_template("confirmation.html", status=_("Invalid amount"), transaction_id="", amount="",
                               confirmed_by="", confirmed_at="")
    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT * FROM users WHERE username=%s AND role='child'", (child,))
    child_data = cursor.fetchone()
    if not child_data:
        flash(_("Child account not found."), "danger")
        cursor.close()
        conn.close()
        return render_template("confirmation.html", status=_("Child not found"), transaction_id="", amount="",
                               confirmed_by="", confirmed_at="")
    cursor.execute("SELECT * FROM users WHERE username=%s", (recipient,))
    recipient_data = cursor.fetchone()
    if not recipient_data:
        flash(_("Recipient not found."), "danger")
        cursor.close()
        conn.close()
        return render_template("confirmation.html", status=_("Recipient not found"), transaction_id="", amount="",
                               confirmed_by="", confirmed_at="")
    new_child_balance = float(child_data["balance"]) - amount
    cursor.execute("UPDATE users SET balance=%s WHERE username=%s", (new_child_balance, child))
    conn.commit()
    new_recipient_balance = float(recipient_data["balance"]) + amount
    cursor.execute("UPDATE users SET balance=%s WHERE username=%s", (new_recipient_balance, recipient))
    conn.commit()
    transaction_data = {
        "sender": child,
        "recipient": recipient,
        "amount": amount,
        "timestamp": firestore.SERVER_TIMESTAMP,
        "status": "approved"
    }
    doc_ref = firestore_db.collection("transactions").add(transaction_data)[1]
    transaction_id = doc_ref.id
    cursor.close()
    conn.close()
    current_time = datetime.now(timezone.utc).strftime("%b %d, %I:%M %p")

    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT parent_username FROM users WHERE username=%s AND role='child'", (child,))
    parent_row = cursor.fetchone()
    cursor.close()
    conn.close()
    if parent_row and parent_row.get("parent_username"):
        parent_phone = get_user_phone(parent_row["parent_username"])
        if parent_phone:
            sms_message = f"Transaction Alert: Your child ({child}) has sent {amount} to {recipient}."
            send_sms(parent_phone, sms_message)

    return render_template("confirmation.html",
                           status=_("Payment Processed Successfully"),
                           transaction_id=transaction_id,
                           amount=amount_str,
                           confirmed_by=_("Parent"),
                           confirmed_at=current_time)

# --- Reject Payment Endpoint ---
@app.route("/reject_payment")
def reject_payment():
    child = request.args.get("child")
    recipient = request.args.get("recipient")
    amount_str = request.args.get("amount")
    try:
        amount = float(amount_str)
    except:
        flash(_("Invalid amount."), "danger")
        return render_template("confirmation.html", status=_("Invalid amount"), transaction_id="", amount="",
                               confirmed_by="", confirmed_at="")
    transaction_data = {
        "sender": child,
        "recipient": recipient,
        "amount": amount,
        "timestamp": firestore.SERVER_TIMESTAMP,
        "status": "rejected"
    }
    doc_ref = firestore_db.collection("transactions").add(transaction_data)[1]
    transaction_id = doc_ref.id
    current_time = datetime.now(timezone.utc).strftime("%b %d, %I:%M %p")

    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT parent_username FROM users WHERE username=%s AND role='child'", (child,))
    parent_row = cursor.fetchone()
    cursor.close()
    conn.close()
    if parent_row and parent_row.get("parent_username"):
        parent_phone = get_user_phone(parent_row["parent_username"])
        if parent_phone:
            sms_message = f"Transaction Alert: A transaction of {amount} from your child ({child}) to {recipient} has been rejected."
            send_sms(parent_phone, sms_message)

    return render_template("confirmation.html",
                           status=_("Payment Rejected"),
                           transaction_id=transaction_id,
                           amount=amount_str,
                           confirmed_by=_("Parent"),
                           confirmed_at=current_time)

# --- QR Code Page ---
@app.route("/qrcode")
def generate_qrcode():
    if "username" not in session:
        return redirect(url_for("login"))
    qr_data = f"User: {session['username']}"
    qr_obj = qrcode.QRCode(version=1, box_size=10, border=5)
    qr_obj.add_data(qr_data)
    qr_obj.make(fit=True)
    img = qr_obj.make_image(fill="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return render_template("qrcode.html", qr_code=img_base64)

# --- About ---
@app.route("/about")
def about():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("about.html")

# --- Help Us ---
@app.route("/helpus")
def helpus():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("helpus.html")

# --- Settings ---
@app.route("/settings")
def settings():
    if "username" not in session:
        return redirect(url_for("login"))
    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT pin FROM users WHERE username=%s", (session["username"],))
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()
    pin_set = user_data and user_data.get("pin") is not None
    return render_template("settings.html", pin_set=pin_set)

# --- Set PIN ---
@app.route("/settings", methods=["POST"])
def set_pin():
    if "username" not in session:
        return redirect(url_for("login"))
    pin = request.form.get("pin")
    confirm_pin = request.form.get("confirm_pin")
    if not pin or not confirm_pin:
        flash(_("Please fill in all fields."), "danger")
        return redirect(url_for("settings"))
    if pin != confirm_pin:
        flash(_("PINs do not match. Please try again."), "danger")
        return redirect(url_for("settings"))
    conn, cursor = get_mysql_cursor()
    cursor.execute("UPDATE users SET pin=%s WHERE username=%s", (pin, session["username"]))
    conn.commit()
    cursor.close()
    conn.close()
    flash(_("Your PIN has been updated successfully."), "success")
    return redirect(url_for("settings"))

# --- Edit Profile ---
@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "username" not in session:
        return redirect(url_for("login"))
    conn, cursor = get_mysql_cursor()
    if request.method == "POST":
        bio = request.form.get("bio", "")
        profile_pic = request.files.get("profile_pic")
        if profile_pic and profile_pic.filename:
            os.makedirs("static/uploads", exist_ok=True)
            filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join("static", "uploads", filename))
            cursor.execute("""
                UPDATE users 
                SET profile_pic=%s, bio=%s 
                WHERE username=%s
            """, (filename, bio, session["username"]))
        else:
            cursor.execute("""
                UPDATE users 
                SET bio=%s 
                WHERE username=%s
            """, (bio, session["username"]))
        conn.commit()
        flash(_("Profile updated!"), "success")
        return redirect(url_for("profile"))
    cursor.execute("SELECT profile_pic, bio FROM users WHERE username=%s", (session["username"],))
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template("edit_profile.html", user_data=user_data)

# --- Profile Page ---
@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect(url_for("login"))
    conn, cursor = get_mysql_cursor()
    cursor.execute("SELECT profile_pic, bio FROM users WHERE username=%s", (session["username"],))
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template("profile.html", user_data=user_data)

# --- Download Transactions (Last 5 as PDF) ---
@app.route("/download_transactions")
def download_transactions():
    child = request.args.get("child_username")
    if not child:
        flash(_("No child selected."), "danger")
        return redirect(url_for("kid_safety"))

    sent = firestore_db.collection("transactions")\
        .where("sender","==",child).stream()
    rec  = firestore_db.collection("transactions")\
        .where("recipient","==",child).stream()

    txs = []
    for doc in sent:
        d = doc.to_dict()
        d["type"] = "Sent"
        d["timestamp_str"] = convert_firestore_ts(d.get("timestamp"))
        txs.append(d)
    for doc in rec:
        d = doc.to_dict()
        d["type"] = "Received"
        d["timestamp_str"] = convert_firestore_ts(d.get("timestamp"))
        txs.append(d)

    txs.sort(key=lambda t: t.get("timestamp").timestamp() if t.get("timestamp") else datetime.min,
             reverse=True)

    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    w, h = letter
    top, bottom = 50, 50
    y = h - top
    line_h = 20
    extra = 30

    for i, tx in enumerate(txs, 1):
        block_h = 30 + 7*line_h + extra
        if y - block_h < bottom:
            pdf.showPage()
            y = h - top

        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(50, y, f"Transaction {i}")
        y -= 30
        pdf.setFont("Helvetica", 12)
        for fld in ("type","sender","recipient","amount","timestamp_str","status","category"):
            pdf.drawString(50, y, f"{fld.title()}: {tx.get(fld, 'N/A')}")
            y -= line_h
        y -= extra

    pdf.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f"{child}_transactions.pdf",
                     mimetype="application/pdf")



@app.route("/send_verification_code_for_pin", methods=["POST"])
def send_verification_code_for_pin():
    if "username" not in session:
        return jsonify(success=False, message=_("Not logged in.")), 403

    conn, cur = get_mysql_cursor()
    cur.execute("SELECT phone FROM users WHERE username=%s",
                (session["username"],))
    row = cur.fetchone()
    cur.close(); conn.close()

    if not row or not row.get("phone"):
        return jsonify(success=False, message=_("No phone on file.")), 400

    otp = str(random.randint(100000, 999999))
    session["pin_otp"] = otp

    if not send_sms(row["phone"], _("Your PIN code is: ") + otp):
        return jsonify(success=False, message=_("SMS send failed.")), 500

    return jsonify(success=True, message=_("Verification code sent.")), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
