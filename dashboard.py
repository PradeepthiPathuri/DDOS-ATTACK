import os
import csv
import random
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask, render_template, redirect, url_for, session, request, abort, flash, jsonify
from detector import detect_ddos
import packet_capture

from flask_dance.contrib.google import make_google_blueprint, google
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

LOG_FILE = "data/traffic_log.csv"

# ================= GOOGLE OAUTH =================
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.getenv("GOOGLE_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.getenv("GOOGLE_CLIENT_SECRET")

google_bp = make_google_blueprint(
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_to="post_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

# ================= MAIL CONFIG =================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")

mail = Mail(app)

# ================= GLOBAL STATE =================
capture_status = "Stopped"
suspicious_ips = []
blocked_ips = set()
otp_store = {}

@app.before_request
def block_malicious_ips():
    if request.remote_addr in blocked_ips:
        abort(403)

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    try:
        msg = Message("Your Login OTP",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"Your verification code is: {otp}"
        mail.send(msg)
    except Exception as e:
        print("Email error:", e)

def send_alert_email(email, ips):
    if not email or not ips:
        return
    try:
        msg = Message("⚠️ DDoS Attack Alert",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = "Suspicious IPs detected:\n" + "\n".join(ips)
        mail.send(msg)
    except Exception as e:
        print("Alert email error:", e)

@app.route("/")
def landing():
    return render_template("first.html")

@app.route("/login-page")
def login_page():
    return redirect(url_for("google.login"))

@app.route("/post_login")
def post_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return redirect(url_for("google.login"))

    email = resp.json()["email"]
    session["user_email"] = email

    if not session.get("otp_verified"):
        otp = generate_otp()
        otp_store[email] = otp
        send_otp_email(email, otp)
        return redirect(url_for("verify_otp"))

    return redirect(url_for("home"))

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        email = session.get("user_email")
        entered_otp = request.form.get("otp")

        if otp_store.get(email) == entered_otp:
            session["otp_verified"] = True
            otp_store.pop(email, None)
            flash("OTP verified successfully")
            return redirect(url_for("home"))
        else:
            flash("Invalid OTP")

    return render_template("otp.html")

@app.route("/home")
def home():
    if not google.authorized or not session.get("otp_verified"):
        return redirect(url_for("post_login"))

    return render_template("index.html",
                           status=capture_status,
                           attackers=suspicious_ips,
                           blocked=blocked_ips)

@app.route("/start")
def start():
    global capture_status
    packet_capture.start_sniffing()
    capture_status = "Running"
    return redirect(url_for("home"))

@app.route("/stop")
def stop():
    global capture_status
    packet_capture.stop_sniffing()
    capture_status = "Stopped"
    return redirect(url_for("home"))

@app.route("/detect")
def detect():
    global suspicious_ips, blocked_ips
    suspicious_ips = detect_ddos()
    blocked_ips.update(suspicious_ips)
    send_alert_email(session.get("user_email"), suspicious_ips)
    return redirect(url_for("home"))

@app.route("/api/suspicious-stats")
def suspicious_stats():
    counts = {}
    try:
        with open(LOG_FILE) as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) > 1:
                    counts[row[1]] = counts.get(row[1], 0) + 1
    except:
        pass

    return jsonify(dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]))

@app.route("/monitor")
def monitor():
    return render_template("monitor.html")

@app.route("/packets")
def packets():
    packets_data = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            reader = csv.reader(f)
            next(reader, None)

            for row in reader:
                if len(row) >= 5:
                    packets_data.append({
                        "timestamp": row[0],
                        "src_ip": row[1],
                        "dst_ip": row[2],
                        "protocol": row[3],
                        "ttl": row[4]
                    })

    return render_template("packets.html", packets=packets_data)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
