from flask import Flask, render_template, g, request, redirect, url_for, flash, session
import sqlite3
from datetime import date, datetime, timedelta
from flask_mail import Mail, Message
import secrets
import re
import base64

app = Flask(__name__)
app.secret_key = 'ger123min987'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'communityctrl.service@gmail.com'
app.config['MAIL_PASSWORD'] = 'wdgy mzsq imhp nyea'
app.config['MAIL_DEFAULT_SENDER'] = 'communityctrl.service@gmail.com'
mail = Mail(app)


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('instance/database.db')
    return db


@app.before_request
def check_session_expiration():
    # Skip static files and public pages
    if request.endpoint in ['static'] + ['landing', 'login', 'forgot_password', 'privacy_policy', 'terms_of_service']:
        return

    # Validation for password reset pages (email session)
    if request.endpoint in ['verification', 'reset_password']:
        if 'email' not in session:
            flash('Session expired. Please try again.', 'error')
            return redirect(url_for('login'))

    # Validation for all other authenticated pages (user_id session)
    elif 'user_id' not in session:
        flash('Session expired. Please try again.', 'error')
        return redirect(url_for('login'))


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
            if user[7] == 1:
                session['role'] = 'Admin'
                return redirect(url_for('admin_home'))
            else:
                if user[7] == 2:
                    session['role'] = 'Owner'
                    cursor.execute("SELECT unit_id FROM units WHERE user_id=?", (session['user_id'],))
                    session['unit'] = cursor.fetchone()[0]
                else:
                    session['role'] = 'Tenant'
                    cursor.execute("SELECT unit_id FROM unit_tenants WHERE user_id=?", (session['user_id'],))
                    session['unit'] = cursor.fetchone()[0]
                return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if not session.get('initial'):
        flash('Please enter your email address to reset password.', 'info')
        session['initial'] = True
    if request.method == 'POST':
        email = request.form['email']
        cursor = get_db().cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        result = cursor.fetchone()
        if result:
            # Generate a secure OTP and set expiration time (2 minutes)
            otp = secrets.randbelow(900000) + 100000
            otp_expiration = datetime.now() + timedelta(minutes=2)
            session['otp'] = str(otp)
            session['otp_expiration'] = otp_expiration.strftime('%Y-%m-%d %H:%M:%S')
            session['email'] = email

            # Send OTP email
            msg = Message('OTP for password reset', recipients=[email])
            msg.body = f'Hello, \n\nYour OTP code is {otp}. \nPlease enter it to reset your password.\n\nThanks!'
            mail.send(msg)
            return redirect(url_for('verification'))  # Redirect to OTP verification
        else:
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


@app.route('/verification', methods=['GET', 'POST'])
def verification():
    if not session.get('otp_sent'):
        flash('An OTP has been sent to your email address.', 'info')
        session['otp_sent'] = True
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        otp = session.get('otp')
        otp_expiration = session.get('otp_expiration')

        # Verify if OTP exists and is still valid
        if otp and otp_expiration:
            otp_expiration_time = datetime.strptime(otp_expiration, '%Y-%m-%d %H:%M:%S')
            if datetime.now() > otp_expiration_time:
                session.clear()
                session['initial'] = True
                flash('OTP has expired. Please request a new one.', 'error')
                return redirect(url_for('forgot_password'))

            # Verify OTP
            if user_otp == otp:
                return redirect(url_for('reset_password'))
            else:
                flash('Invalid OTP. Please try again.', 'error')
                return redirect(url_for('verification'))

    return render_template('verification.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('email')
    if session.get('otp_sent'):
        flash('OTP verified! You can now reset your password.', 'info')
        session.pop('otp_sent', None)

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')
        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('reset_password'))

        # Define password policy
        password_policy = {
            'min_length': 8,
            'digit': r'[0-9]',
            'special_char': r'[!@#$%^&*(),.?":{}|<>]'
        }

        # Check if password meets policy
        if len(new_password) < password_policy['min_length']:
            flash('Password must be at least 8 characters long.', 'error')
            return redirect(url_for('reset_password'))
        if not re.search(password_policy['digit'], new_password):
            flash('Password must contain at least one digit.', 'error')
            return redirect(url_for('reset_password'))
        if not re.search(password_policy['special_char'], new_password):
            flash('Password must contain at least one special character.', 'error')
            return redirect(url_for('reset_password'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=? WHERE email=?", (new_password, email))
        conn.commit()
        session.clear()
        return '''
            <script>
                alert("Password has been reset successfully!");
                window.location.href = "{}";
            </script>
            '''.format(url_for('login'))

    return render_template('reset_password.html')


@app.route('/home')
def home():
    return render_template('home.html', role=session['role'])


@app.route('/admin_home')
def admin_home():
    return render_template('admin_home.html', role=session['role'])


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/profile')
def profile():
    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM users WHERE user_id=?", (session['user_id'],))
    user = cursor.fetchone()
    profile_pic = None
    if user[8]:
        profile_pic = 'data:image/jpeg;base64,' + base64.b64encode(user[8]).decode('utf-8')
    return render_template('profile.html', user=user, role=session['role'], currentProfilePic=profile_pic)


@app.route('/upload_profile_pic', methods=['POST'])
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        return '''
            <script>
                alert("No file selected!");
                window.location.href = "{}";
            </script>
            '''.format(url_for('profile'))

    file = request.files['profile_pic']
    if file.filename == '':
        return '''
            <script>
                alert("No file selected!");
                window.location.href = "{}";
            </script>
            '''.format(url_for('profile'))

    if file:
        image_data = file.read()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET picture = ? WHERE user_id = ?", (image_data, session['user_id']))
        conn.commit()
        return '''
            <script>
                alert("Profile picture updated successfully!");
                window.location.href = "{}";
            </script>
            '''.format(url_for('profile'))


@app.route('/save_phone', methods=['POST'])
def save_phone():
    new_phone = request.form['new-phone']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET phone = ? WHERE user_id = ?", (new_phone, session['user_id']))
    conn.commit()
    cursor.execute("SELECT * FROM users WHERE user_id=?", (session['user_id'],))
    user = cursor.fetchone()
    return render_template('profile.html', user=user, role=session['role'],
                           alert_message="Phone number updated successfully!")


@app.route('/send_otp')
def send_otp():
    email = request.args.get('email')
    # Generate a secure OTP and set expiration time (2 minutes)
    otp = secrets.randbelow(900000) + 100000
    otp_expiration = datetime.now() + timedelta(minutes=2)
    session['otp'] = str(otp)
    session['otp_expiration'] = otp_expiration.strftime('%Y-%m-%d %H:%M:%S')
    session['email'] = email

    # Send OTP email
    msg = Message('OTP for password reset', recipients=[email])
    msg.body = f'Hello, \n\nYour OTP code is {otp}. \nPlease enter it to reset your password.\n\nThanks!'
    mail.send(msg)
    return '''
        <script>
            alert("An OTP has been sent to your email address.");
            window.history.back();
        </script>
        '''


@app.route('/save_email', methods=['POST'])
def save_email():
    conn = get_db()
    cursor = conn.cursor()
    user_otp = request.form.get('otp')
    otp = session.get('otp')
    otp_expiration = session.get('otp_expiration')

    # Verify if OTP exists and is still valid
    if otp and otp_expiration:
        otp_expiration_time = datetime.strptime(otp_expiration, '%Y-%m-%d %H:%M:%S')
        if datetime.now() > otp_expiration_time:
            session.pop('otp', None)
            session.pop('otp_expiration', None)
            session.pop('email', None)
            return '''
                <script>
                    alert("OTP has expired. Please request a new one.");
                    window.history.back();
                </script>
                '''

        # Verify OTP
        if user_otp == otp:
            cursor.execute("UPDATE users SET email = ? WHERE user_id = ?", (session['email'], session['user_id']))
            conn.commit()
            session.pop('otp', None)
            session.pop('otp_expiration', None)
            session.pop('email', None)
            cursor.execute("SELECT * FROM users WHERE user_id=?", (session['user_id'],))
            user = cursor.fetchone()
            return render_template('profile.html', user=user, role=session['role'],
                                   alert_message="OTP verified! Email updated successfully!")
        else:
            flash('Invalid OTP. Please try again.', 'error')
            return '''
                <script>
                    alert("Invalid OTP. Please try again.");
                    window.history.back();
                </script>
                '''


@app.route('/save_password', methods=['POST'])
def save_password():
    current_password = request.form['current-password']
    new_password = request.form['new-password']
    confirm_password = request.form['confirm-new-password']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id=?", (session['user_id'],))
    user = cursor.fetchone()
    if user[5] != current_password:
        return '''
            <script>
                alert("Incorrect current password!");
                window.history.back();
            </script>
            '''
    elif new_password != confirm_password:
        return '''
            <script>
                alert("New passwords do not match!");
                window.history.back();
            </script>
            '''
    else:
        # Define password policy
        password_policy = {
            'min_length': 8,
            'digit': r'[0-9]',
            'special_char': r'[!@#$%^&*(),.?":{}|<>]'
        }

        # Check if password meets policy
        if len(new_password) < password_policy['min_length']:
            return '''
                <script>
                    alert("Password must be at least 8 characters long.");
                    window.history.back();
                </script>
                '''
        elif not re.search(password_policy['digit'], new_password):
            return '''
                <script>
                    alert("Password must contain at least one digit.");
                    window.history.back();
                </script>
                '''
        elif not re.search(password_policy['special_char'], new_password):
            return '''
                <script>
                    alert("Password must contain at least one special character.");
                    window.history.back();
                </script>
                '''
        else:
            cursor.execute("UPDATE users SET password = ? WHERE user_id = ?", (new_password, session['user_id']))
            conn.commit()
            return render_template('profile.html', user=user, role=session['role'],
                                   alert_message="Password updated successfully!")


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


@app.route('/resignee')
def resignee():
    # Example list of existing vehicles fetched from the database
    vehicles = [
        {"type": "Car", "number": "XYZ 1234"},
        {"type": "Motorcycle", "number": "ABC 5678"}
    ]

    return render_template('resignee.html', vehicles=vehicles)


@app.route('/unit')
def unit():
    # Example list of existing vehicles fetched from the database
    vehicles = [
        {"type": "Car", "number": "XYZ 1234"},
        {"type": "Motorcycle", "number": "ABC 5678"}
    ]

    return render_template('unit.html', vehicles=vehicles)


if __name__ == '__main__':
    app.run(debug=True)
