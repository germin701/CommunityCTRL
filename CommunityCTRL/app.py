from flask import Flask, render_template, g
import sqlite3

app = Flask(__name__)


# Helper function to get a database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('instance/database.db')
    return db


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')


@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot_password.html')


if __name__ == '__main__':
    app.run(debug=True)
