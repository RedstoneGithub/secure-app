from flask import Flask, render_template

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-change-this-later"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login")
def login():
    return "<h1>Login page coming soon</h1>"


@app.route("/register")
def register():
    return "<h1>Register page coming soon</h1>"


@app.route("/dashboard")
def dashboard():
    return "<h1>Dashboard coming soon</h1>"


if __name__ == "__main__":
    app.run(debug=True)