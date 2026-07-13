from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from config import Config
from extensions import db

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

from models import User, AuditLog

with app.app_context():
    db.create_all()


# =====================================================
# AUDIT LOG FUNCTION
# =====================================================

def write_log(username, action, status):
    log = AuditLog(
        username=username,
        action=action,
        status=status
    )

    db.session.add(log)
    db.session.commit()


# =====================================================
# HOME
# =====================================================

@app.route("/")
def home():
    return render_template("index.html")


# =====================================================
# REGISTER
# =====================================================
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password or not confirm_password:
            flash("All fields are required!", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters long!", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered!", "danger")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        write_log(username, "Registration", "Success")

        flash("Registration Successful! Please Login.", "success")

        return redirect(url_for("login"))

    return render_template("register.html")
# =====================================================
# LOGIN
# =====================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and Password are required!", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Invalid Email or Password!", "danger")
            return redirect(url_for("login"))

        # Account Locked
        if user.locked_until and user.locked_until > datetime.utcnow():

            write_log(user.username, "Login", "Blocked")

            flash(f"Account Locked until {user.locked_until}", "danger")
            return redirect(url_for("login"))

        # Password Correct
        if check_password_hash(user.password, password):

            user.failed_attempts = 0
            user.locked_until = None

            db.session.commit()

            write_log(user.username, "Login", "Success")

            # Save user information in session
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role.strip()

            return redirect(url_for("dashboard"))

        # Password Wrong
        user.failed_attempts += 1

        if user.failed_attempts >= 5:

            user.locked_until = datetime.utcnow() + timedelta(minutes=15)

            db.session.commit()

            write_log(user.username, "Account Locked", "Locked")

            flash("Account Locked for 15 Minutes!", "danger")
            return redirect(url_for("login"))

        db.session.commit()

        remaining = 5 - user.failed_attempts

        write_log(user.username, "Login", "Failed")

        flash(f"Invalid Password! {remaining} attempt(s) remaining.", "warning")
        return redirect(url_for("login"))

    return render_template("login.html")


# =====================================================
# DASHBOARD
# =====================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    # User deleted from database
    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=user.username,
        email=user.email,
        role=user.role
    )
# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
def logout():

    username = session.get("username", "Unknown User")

    write_log(username, "Logout", "Success")

    session.clear()

    flash("Logged out successfully.", "success")

    return redirect(url_for("home")) 


# =====================================================
# ADMIN DASHBOARD
# =====================================================

@app.route("/admin")
def admin():

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Always get latest user from database
    current_user = User.query.get(session["user_id"])

    if not current_user:
        session.clear()
        return redirect(url_for("login"))

    # Only Admin can access
    if current_user.role.strip() != "Admin":
        return "Access Denied!"

    users = User.query.order_by(User.id).all()

    logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).all()

    return render_template(
        "admin.html",
        users=users,
        logs=logs
    )


# =====================================================
# UNLOCK ACCOUNT
# =====================================================

@app.route("/unlock/<int:user_id>")
def unlock(user_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user = User.query.get(session["user_id"])

    if not current_user:
        session.clear()
        return redirect(url_for("login"))

    if current_user.role.strip() != "Admin":
        return "Access Denied!"

    user = User.query.get_or_404(user_id)

    user.failed_attempts = 0
    user.locked_until = None

    db.session.commit()

    write_log(current_user.username, f"Unlocked {user.username}", "Success")
    flash(f"{user.username}'s account has been unlocked successfully.", "success")
    return redirect(url_for("admin"))


# =====================================================
# RUN APPLICATION
# =====================================================

if __name__ == "__main__":
    app.run(debug=True)