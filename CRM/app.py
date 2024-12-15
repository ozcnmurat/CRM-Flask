from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.google import make_google_blueprint, google
from passlib.hash import bcrypt

app = Flask(__name__)
app.secret_key = "gizli_bir_anahtar"
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:root@localhost/master:5432"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Kullanıcı modeli
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password = db.Column(db.String(200), nullable=True)
    is_google_user = db.Column(db.Boolean, default=False)

# Google OAuth
google_bp = make_google_blueprint(
    client_id="GOOGLE_CLIENT_ID",
    client_secret="GOOGLE_CLIENT_SECRET",
    scope=["profile", "email"],
    redirect_to="google_login_callback"
)
app.register_blueprint(google_bp, url_prefix="/login")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.verify(password, user.password):
            session["user"] = {"name": user.username, "email": user.email}
            return redirect(url_for("dashboard"))
        flash("Geçersiz kullanıcı adı veya şifre", "error")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        phone = request.form.get("phone")
        user = User.query.filter_by(email=email).first()
        if not user:
            if not password:  # Google kullanıcıları için şifre kontrolü
                new_user = User(username=username, email=email, phone=phone, is_google_user=True)
            else:
                hashed_password = bcrypt.hash(password)
                new_user = User(username=username, password=hashed_password, email=email, phone=phone)
            db.session.add(new_user)
            db.session.commit()
            flash("Kayıt başarılı!", "success")
            return redirect(url_for("login"))
        flash("Bu email zaten kayıtlı", "error")
    return render_template("register.html")

@app.route("/register/google")
def register_google():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        user_info = resp.json()
        email = user_info.get("email")
        user = User.query.filter_by(email=email).first()
        if not user:
            new_user = User(username=user_info.get("name"), email=email, is_google_user=True)
            db.session.add(new_user)
            db.session.commit()
            flash("Google hesabınızla başarıyla kayıt oldunuz!", "success")
        else:
            flash("Bu email zaten kayıtlı.", "error")
        session["user"] = {"name": user_info.get("name"), "email": email}
        return redirect(url_for("dashboard"))
    flash("Google ile giriş yapılamadı.", "error")
    return redirect(url_for("register"))

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Veritabanı tablolarını oluştur
    app.run(debug=True)
