from flask import Flask, render_template, g, request, redirect, url_for, flash
import sqlite3

app = Flask(__name__)
app.secret_key = 'ger123min987'


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


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        cursor = get_db().cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        result = cursor.fetchone()
        if result:
            return redirect(url_for('verification_reset_password'))
        else:
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('forgot_password'))
    flash('Please enter your email address to reset password.', 'info')
    return render_template('forgot_password.html')


@app.route('/verification')
def verification_reset_password():
    return render_template('verification_reset_password.html')


if __name__ == '__main__':
    app.run(debug=True)
