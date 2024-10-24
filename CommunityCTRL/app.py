from flask import Flask, render_template, g, request, redirect, url_for, flash, session
import sqlite3
from datetime import date

app = Flask(__name__)
app.secret_key = 'ger123min987'


# Helper function to get a database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('instance/database.db')
    return db


@app.route('/')
def landing():
    return render_template('index.html')


@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')


@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        cursor = get_db().cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        if user and user[5] == password:
            session['user_id'] = user[0]
            session['role'] = user[7]
            if user[7] == 1:
                return redirect(url_for('admin_home'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))
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


@app.route('/home')
def home():
    cursor = get_db().cursor()
    cursor.execute("SELECT u.*, r.role FROM users u, roles r WHERE u.role_id=r.role_id AND user_id=?",
                   (session['user_id'],))
    user = cursor.fetchone()
    return render_template('home.html', user=user)


@app.route('/admin_home')
def admin_home():
    cursor = get_db().cursor()
    cursor.execute("SELECT u.*, r.role FROM users u, roles r WHERE u.role_id=r.role_id AND user_id=?",
                   (session['user_id'],))
    user = cursor.fetchone()
    return render_template('admin_home.html', user=user)


@app.route('/create_announcement')
def create_announcement():
    return render_template('create_announcement.html')


@app.route('/visitor')
def visitor():
    return render_template('visitor.html')


@app.route('/admin_visitor')
def admin_visitor():
    return render_template('admin_visitor.html')


@app.route('/visitor_detail')
def visitor_detail():
    return render_template('visitor_detail.html')


@app.route('/edit_visitor')
def edit_visitor():
    # Example list of existing vehicles fetched from the database
    vehicles = [
        {"type": "Car", "number": "XYZ 1234"},
        {"type": "Motorcycle", "number": "ABC 5678"}
    ]

    return render_template('edit_visitor.html', vehicles=vehicles)


@app.route('/new_visitor')
def new_visitor():
    return render_template('new_visitor.html')


@app.route('/admin_new_visitor')
def admin_new_visitor():
    return render_template('admin_new_visitor.html')


@app.route('/invitation_list')
def invitation_list():
    return render_template('invitation_list.html')


@app.route('/admin_invitation_list')
def admin_invitation_list():
    return render_template('admin_invitation_list.html')


@app.route('/invitation_detail')
def invitation_detail():
    return render_template('invitation_detail.html')


@app.route('/admin_invitation_detail')
def admin_invitation_detail():
    return render_template('admin_invitation_detail.html')


@app.route('/edit_invitation')
def edit_invitation():
    current_date = date.today().isoformat()
    original_date = '2024-11-15'
    vehicle = 'Motorcycle PPP 1234'
    reason = 'renovation'
    return render_template('edit_invitation.html', current_date=current_date, original_date=original_date,
                           vehicle=vehicle, reason=reason)


@app.route('/admin_edit_invitation')
def admin_edit_invitation():
    current_date = date.today().isoformat()
    original_date = '2024-11-15'
    vehicle = 'Motorcycle PPP 1234'
    reason = 'renovation'
    return render_template('admin_edit_invitation.html', current_date=current_date, original_date=original_date,
                           vehicle=vehicle, reason=reason)


@app.route('/new_invite')
def new_invite():
    current_date = date.today().isoformat()
    return render_template('new_invite.html', current_date=current_date)


@app.route('/admin_new_invite')
def admin_new_invite():
    current_date = date.today().isoformat()
    return render_template('admin_new_invite.html', current_date=current_date)


@app.route('/blacklist')
def blacklist():
    return render_template('blacklist.html')


@app.route('/admin_blacklist')
def admin_blacklist():
    return render_template('admin_blacklist.html')


@app.route('/add_blacklist')
def add_blacklist():
    return render_template('add_blacklist.html')


@app.route('/admin_add_blacklist')
def admin_add_blacklist():
    return render_template('admin_add_blacklist.html')


@app.route('/staff')
def staff():
    return render_template('staff.html')


@app.route('/admin_staff')
def admin_staff():
    return render_template('admin_staff.html')


@app.route('/new_staff')
def new_staff():
    return render_template('new_staff.html')


@app.route('/edit_staff')
def edit_staff():
    return render_template('edit_staff.html')


if __name__ == '__main__':
    app.run(debug=True)
