from flask import Flask, render_template, g, request, redirect, url_for, flash, session, jsonify, abort, Response
import sqlite3
from datetime import date, datetime, timedelta
from flask_mail import Mail, Message
import secrets
import re
import base64
import imghdr
from markupsafe import Markup, escape
import cv2
import time
from paddleocr import PaddleOCR

app = Flask(__name__)
app.secret_key = 'ger123min987'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'communityctrl.service@gmail.com'
app.config['MAIL_PASSWORD'] = 'wdgy mzsq imhp nyea'
app.config['MAIL_DEFAULT_SENDER'] = 'communityctrl.service@gmail.com'
mail = Mail(app)

# Threshold and Setting for LPR model
CONFIDENCE_THRESHOLD = 0.95
NMS_THRESHOLD = 0.4
COLORS = [(0, 255, 255), (0, 255, 0), (255, 255, 0), (255, 0, 0)]
detected_plates = {}


def nl2br(value):
    # Escape any HTML and replace newlines with <br> tags
    escaped_value = escape(value).replace('\n', Markup('<br>'))
    return Markup(escaped_value)


# Register the filter
app.jinja_env.filters['nl2br'] = nl2br


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('instance/database.db')
    return db


@app.before_request
def check_session_expiration():
    # Skip static files and public pages
    if request.endpoint in ['static'] + ['landing', 'login', 'forgot_password', 'privacy_policy', 'terms_of_service',
                                         'register']:
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
        cursor.execute("SELECT * FROM users WHERE email=? AND status=1", (email,))
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
        cursor.execute("SELECT * FROM users WHERE email=? AND status=1", (email,))
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
            return redirect(url_for('verification'))
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
    cursor = get_db().cursor()

    # Get announcement list
    cursor.execute("SELECT * FROM announcement WHERE status=1")
    announcements_data = cursor.fetchall()

    # Convert the fetched data to a list of dictionaries with Base64 encoding for images
    announcements_list = []
    for row in announcements_data:
        picture_data = None
        if row[3]:
            # Detect image type
            image_type = imghdr.what(None, h=row[3])

            # Check if image type is valid and encode it to Base64
            if image_type in ['jpg', 'jpeg', 'png']:
                picture_data = f"data:image/{image_type};base64," + base64.b64encode(row[3]).decode('utf-8')

        # Append announcement dictionary to the list
        announcements_list.append({
            'announcement_id': row[0],
            'title': row[1],
            'detail': row[2],
            'picture': picture_data,
            'status': row[4]
        })

    return render_template('home.html', announcements=announcements_list, role=session['role'])


@app.route('/admin_home')
def admin_home():
    cursor = get_db().cursor()

    # Get announcement list
    cursor.execute("SELECT * FROM announcement")
    announcements_data = cursor.fetchall()

    # Convert the fetched data to a list of dictionaries with Base64 encoding for images
    announcements_list = []
    for row in announcements_data:
        picture_data = None
        if row[3]:
            # Detect image type
            image_type = imghdr.what(None, h=row[3])

            # Check if image type is valid and encode it to Base64
            if image_type in ['jpg', 'jpeg', 'png']:
                picture_data = f"data:image/{image_type};base64," + base64.b64encode(row[3]).decode('utf-8')

        # Append announcement dictionary to the list
        announcements_list.append({
            'announcement_id': row[0],
            'title': row[1],
            'detail': row[2],
            'picture': picture_data,
            'status': row[4]
        })

    return render_template('admin_home.html', announcements=announcements_list, role=session['role'])


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/profile')
def profile():
    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM users WHERE user_id=?", (session['user_id'],))
    user = cursor.fetchone()

    # Convert BLOB to Base64 for the profile picture
    profile_pic = None
    if user[8]:
        # Detect image type
        image_type = imghdr.what(None, h=user[8])

        # Check if image type is valid
        if image_type in ['jpg', 'jpeg', 'png']:
            profile_pic = f"data:image/{image_type};base64," + base64.b64encode(user[8]).decode('utf-8')

    return render_template('profile.html', user=user, role=session['role'], currentProfilePic=profile_pic)


@app.route('/upload_profile_pic', methods=['POST'])
def upload_profile_pic():
    allowed_extensions = {'jpg', 'jpeg', 'png'}
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

    if file.filename.split('.')[-1].lower() not in allowed_extensions:
        return '''
            <script>
                alert("Invalid file type! Please upload jpg, jpeg, or png.");
                window.location.href = "{}";
            </script>
            '''.format(url_for('profile'))

    if file.mimetype not in ['image/jpeg', 'image/png']:
        return '''
            <script>
                alert("Invalid file type! Please upload a valid image.");
                window.location.href = "{}";
            </script>
            '''.format(url_for('profile'))

    if file:
        image_data = file.read()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET picture=? WHERE user_id=?", (image_data, session['user_id']))
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
    # Validate contains only digits and length is 10/11
    if not re.match(r'^\d{10,11}$', new_phone):
        return '''
            <script>
                alert("Please enter a valid phone and only digits are allowed.");
                window.history.back();
            </script>
            '''
    else:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET phone=? WHERE user_id=?", (new_phone, session['user_id']))
        conn.commit()
        cursor.execute("SELECT * FROM users WHERE user_id=?", (session['user_id'],))
        user = cursor.fetchone()

        # Convert BLOB to Base64 for the profile picture
        profile_picture = None
        if user[8]:
            # Detect image type
            image_type = imghdr.what(None, h=user[8])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                profile_picture = f"data:image/{image_type};base64," + base64.b64encode(user[8]).decode('utf-8')

        return render_template('profile.html', user=user, role=session['role'], currentProfilePic=profile_picture,
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
    msg = Message('OTP for new email verification', recipients=[email])
    msg.body = f'Hello, \n\nYour OTP code is {otp}. \nPlease enter it to change your email.\n\nThanks!'
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
            cursor.execute("UPDATE users SET email=? WHERE user_id=?", (session['email'], session['user_id']))
            conn.commit()
            session.pop('otp', None)
            session.pop('otp_expiration', None)
            session.pop('email', None)
            cursor.execute("SELECT * FROM users WHERE user_id=?", (session['user_id'],))
            user = cursor.fetchone()

            # Convert BLOB to Base64 for the profile picture
            profile_picture = None
            if user[8]:
                # Detect image type
                image_type = imghdr.what(None, h=user[8])

                # Check if image type is valid
                if image_type in ['jpg', 'jpeg', 'png']:
                    profile_picture = f"data:image/{image_type};base64," + base64.b64encode(user[8]).decode('utf-8')

            return render_template('profile.html', user=user, role=session['role'], currentProfilePic=profile_picture,
                                   alert_message="OTP verified! Email updated successfully!")
        else:
            return '''
                <script>
                    alert("Invalid OTP. Please try again.");
                    window.history.back();
                </script>
                '''

    else:
        return '''
            <script>
                alert("OTP is not exist. Please get a new OTP.");
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
            cursor.execute("UPDATE users SET password=? WHERE user_id=?", (new_password, session['user_id']))
            conn.commit()

            # Convert BLOB to Base64 for the profile picture
            profile_picture = None
            if user[8]:
                # Detect image type
                image_type = imghdr.what(None, h=user[8])

                # Check if image type is valid
                if image_type in ['jpg', 'jpeg', 'png']:
                    profile_picture = f"data:image/{image_type};base64," + base64.b64encode(user[8]).decode('utf-8')

            return render_template('profile.html', user=user, role=session['role'], currentProfilePic=profile_picture,
                                   alert_message="Password updated successfully!")


def validate_image(file):
    allowed_extensions = {'jpg', 'jpeg', 'png'}
    if file.filename == '':
        return "No file selected!"

    if file.filename.split('.')[-1].lower() not in allowed_extensions:
        return "Invalid file type! Please upload jpg, jpeg, or png."

    if file.mimetype not in ['image/jpeg', 'image/png']:
        return "Invalid file type! Please upload a valid image."

    return None


@app.route('/create_announcement', methods=['GET', 'POST'])
def create_announcement():
    if request.method == 'POST':
        title = request.form['title']
        detail = request.form['content']
        picture = request.files.get('announcement_pic')
        status = 0 if 'hide_from_owner_tenant' in request.form else 1

        # Validate and process picture
        if picture and picture.filename:
            error = validate_image(picture)
            if error:
                return f'''
                    <script>
                        alert("{error}");
                        window.location.href = "{url_for('create_announcement')}";
                    </script>
                    '''

            # Read the picture as binary for database storage
            picture_data = picture.read()

        else:
            picture_data = None

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO announcement (title, detail, picture, status) VALUES (?, ?, ?, ?)",
                       (title, detail, picture_data, status))
        conn.commit()

        return '''
            <script>
                alert("Announcement created successfully!");
                window.location.href = "{}";
            </script>
            '''.format(url_for('admin_home'))

    return render_template('create_announcement.html')


@app.route('/edit_announcement/<announcement_id>', methods=['GET', 'POST'])
def edit_announcement(announcement_id):
    conn = get_db()
    cursor = conn.cursor()
    if request.method == 'POST':
        title = request.form['title']
        detail = request.form['content']
        picture = request.files.get('announcement_pic')
        status = 0 if 'hide_from_owner_tenant' in request.form else 1

        # Validate and process picture
        picture_data = None
        if picture and picture.filename:
            error = validate_image(picture)
            if error:
                return f'''
                    <script>
                        alert("{error}");
                        window.location.href = "{url_for('edit_announcement', announcement_id=announcement_id)}";
                    </script>
                    '''

            # Read the picture as binary for database storage
            picture_data = picture.read()

        # Check if a new picture was provided
        if picture_data:
            cursor.execute("UPDATE announcement SET title=?, detail=?, picture=?, status=? WHERE announcement_id=?",
                           (title, detail, picture_data, status, announcement_id))

        else:
            cursor.execute("UPDATE announcement SET title=?, detail=?, status=? WHERE announcement_id=?",
                           (title, detail, status, announcement_id))
        conn.commit()

        return '''
            <script>
                alert("Announcement updated successfully!");
                window.location.href = "{}";
            </script>
            '''.format(url_for('admin_home'))

    # Get announcement details
    cursor.execute("SELECT * FROM announcement WHERE announcement_id=?", (announcement_id,))
    announcement = cursor.fetchone()

    # Convert BLOB to Base64 for the announcement picture
    announcement_picture = None
    if announcement[3]:
        # Detect image type
        image_type = imghdr.what(None, h=announcement[3])

        # Check if image type is valid
        if image_type in ['jpg', 'jpeg', 'png']:
            announcement_picture = (f"data:image/{image_type};base64," + base64.b64encode(announcement[3])
                                    .decode('utf-8'))

    return render_template('edit_announcement.html', announcement=announcement,
                           announcement_picture=announcement_picture)


@app.route('/delete_announcement/<announcement_id>', methods=['POST'])
def delete_announcement(announcement_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM announcement WHERE announcement_id=?", (announcement_id,))
    conn.commit()
    return jsonify({"message": "Announcement deleted successfully!"})


@app.route('/visitor')
def visitor():
    cursor = get_db().cursor()

    # Get visitor list
    cursor.execute("""
        SELECT v.visitor_id, v.name, v.picture, i.invitation_id, i.date, i.visitor_vehicle_id, vv.vehicle_number, 
        vt.type,
        CASE
            WHEN h.arrive_time IS NOT NULL AND h.exit_time IS NOT NULL THEN 'Visited'
            WHEN h.arrive_time IS NOT NULL AND h.exit_time IS NULL THEN 'Visiting'
            ELSE NULL
        END AS status
        FROM visitors v
        LEFT JOIN invitations i ON v.visitor_id=i.visitor_id
        AND i.date=(SELECT MAX(date) FROM invitations WHERE visitor_id=v.visitor_id AND status=0)
        LEFT JOIN visit_history h ON i.invitation_id=h.invitation_id
        LEFT JOIN visitor_vehicles vv ON i.visitor_vehicle_id=vv.visitor_vehicle_id
        LEFT JOIN vehicle_types vt ON vv.type_id=vt.type_id
        WHERE v.status=1 AND v.unit_id=?
        """, (session['unit'],))
    visitor_list = cursor.fetchall()

    # Process visitors to convert profile pictures to Base64
    visitors_list = []
    for visitors in visitor_list:
        # Convert BLOB to Base64 for the profile picture
        profile_picture = None
        if visitors[2]:
            # Detect image type
            image_type = imghdr.what(None, h=visitors[2])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                profile_picture = f"data:image/{image_type};base64," + base64.b64encode(visitors[2]).decode('utf-8')

        # Create a dictionary for the visitor with the Base64-encoded picture
        visitor_data = {"visitor_id": visitors[0], "name": visitors[1], "picture": profile_picture,
                        "invitation_id": visitors[3], "date": visitors[4], "vehicle_id": visitors[5],
                        "vehicle": f"{visitors[7]} ({visitors[6]})" if visitors[6] and visitors[7] else "None",
                        "status": visitors[8]}
        visitors_list.append(visitor_data)

    return render_template('visitor.html', role=session['role'], visitors_list=visitors_list)


@app.route('/admin_visitor')
def admin_visitor():
    cursor = get_db().cursor()

    # Get visitor list
    cursor.execute("""
        SELECT v.visitor_id, v.name, v.picture, i.invitation_id, i.date, i.visitor_vehicle_id, vv.vehicle_number, 
        vt.type, v.unit_id, v.ic,
        CASE
            WHEN h.arrive_time IS NOT NULL AND h.exit_time IS NOT NULL THEN 'Visited'
            WHEN h.arrive_time IS NOT NULL AND h.exit_time IS NULL THEN 'Visiting'
            ELSE NULL
        END AS status
        FROM visitors v
        LEFT JOIN invitations i ON v.visitor_id=i.visitor_id
        AND i.date=(SELECT MAX(date) FROM invitations WHERE visitor_id=v.visitor_id AND status=0)
        LEFT JOIN visit_history h ON i.invitation_id=h.invitation_id
        LEFT JOIN visitor_vehicles vv ON i.visitor_vehicle_id=vv.visitor_vehicle_id
        LEFT JOIN vehicle_types vt ON vv.type_id=vt.type_id
        WHERE v.status=1
        """)
    visitor_list = cursor.fetchall()

    # Process visitors to convert profile pictures to Base64
    visitors_list = []
    for visitors in visitor_list:
        # Convert BLOB to Base64 for the profile picture
        profile_picture = None
        if visitors[2]:
            # Detect image type
            image_type = imghdr.what(None, h=visitors[2])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                profile_picture = f"data:image/{image_type};base64," + base64.b64encode(visitors[2]).decode('utf-8')

        # Create a dictionary for the visitor with the Base64-encoded picture
        visitor_data = {"visitor_id": visitors[0], "name": visitors[1], "picture": profile_picture,
                        "invitation_id": visitors[3], "date": visitors[4], "vehicle_id": visitors[5],
                        "vehicle": f"{visitors[7]} ({visitors[6]})" if visitors[6] and visitors[7] else "None",
                        "status": visitors[10], "unit": visitors[8], "ic": visitors[9]}
        visitors_list.append(visitor_data)

    return render_template('admin_visitor.html', visitors_list=visitors_list)


@app.route('/visitor_detail/<visitor_id>')
def visitor_detail(visitor_id):
    cursor = get_db().cursor()

    # Get visitor info
    cursor.execute("SELECT name, gender, ic, email, phone, unit_id, picture FROM visitors WHERE status=1 AND "
                   "visitor_id=?", (visitor_id,))
    visitor_info = cursor.fetchone()

    # Convert BLOB to Base64 for the visitor picture
    visitor_picture = None
    if visitor_info[6]:
        # Detect image type
        image_type = imghdr.what(None, h=visitor_info[6])

        # Check if image type is valid
        if image_type in ['jpg', 'jpeg', 'png']:
            visitor_picture = (f"data:image/{image_type};base64," + base64.b64encode(visitor_info[6]).decode('utf-8'))

    # Get visit history
    cursor.execute("""
        SELECT t.type, v.vehicle_number, i.unit_id, i.date, h.arrive_time, h.exit_time, u.name
        FROM visit_history h
        LEFT JOIN invitations i ON h.invitation_id=i.invitation_id
        LEFT JOIN visitor_vehicles v ON i.visitor_vehicle_id=v.visitor_vehicle_id
        LEFT JOIN vehicle_types t ON v.type_id=t.type_id
        LEFT JOIN users u ON i.user_id=u.user_id
        WHERE i.visitor_id=?
        """, (visitor_id,))
    visit_history_list = cursor.fetchall()

    return render_template('visitor_detail.html', role=session['role'], visitor_info=visitor_info,
                           visitor_picture=visitor_picture, visit_history_list=visit_history_list)


@app.route('/edit_visitor/<visitor_id>', methods=['GET', 'POST'])
def edit_visitor(visitor_id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        picture = request.files.get('visitor-pic')
        phone = request.form['phone']
        email = request.form['email']
        new_vehicle_types = request.form.getlist('newVehicleType[]')
        new_vehicle_numbers = request.form.getlist('newVehicleNumber[]')

        # Validate and process picture
        picture_data = None
        if picture and picture.filename:
            error = validate_image(picture)
            if error:
                return f'''
                    <script>
                        alert("{error}");
                        window.location.href = "{url_for('edit_visitor', visitor_id=visitor_id)}";
                    </script>
                    '''

            # Read the picture as binary for database storage
            picture_data = picture.read()

        # Validate contains only digits and length is 10/11
        if not re.match(r'^\d{10,11}$', phone):
            return f'''
                <script>
                    alert("Please enter a valid phone and only digits are allowed.");
                    window.location.href = "{url_for('edit_visitor', visitor_id=visitor_id)}";
                </script>
                '''

        else:
            # Update visitor details
            if picture_data:
                cursor.execute("UPDATE visitors SET phone=?, email=?, picture=? WHERE visitor_id=?",
                               (phone, email, picture_data, visitor_id))
            else:
                cursor.execute("UPDATE visitors SET phone=?, email=? WHERE visitor_id=?", (phone, email, visitor_id))
            conn.commit()

            # Add visitor vehicle details
            if not new_vehicle_types:
                pass
            else:
                # Insert new vehicles into the database
                for vehicle_type, vehicle_number in zip(new_vehicle_types, new_vehicle_numbers):
                    if vehicle_type and vehicle_number:
                        if vehicle_type == 'Car':
                            vehicle_id = 1
                        else:
                            vehicle_id = 2

                        # Check if the vehicle already exists for the current user
                        cursor.execute("SELECT visitor_vehicle_id FROM visitor_vehicles WHERE type_id=? AND "
                                       "vehicle_number=? AND visitor_id=?", (vehicle_id, vehicle_number, visitor_id))
                        existing_vehicle = cursor.fetchone()
                        if existing_vehicle is not None:
                            existing_vehicle_id = existing_vehicle[0]
                            cursor.execute("UPDATE visitor_vehicles SET status=1 WHERE user_vehicle_id=?",
                                           (existing_vehicle_id,))
                        else:
                            cursor.execute("INSERT INTO visitor_vehicles (type_id, vehicle_number, visitor_id, "
                                           "status) VALUES (?, ?, ?, 1)", (vehicle_id, vehicle_number, visitor_id))
                        conn.commit()
            return '''
                <script>
                    alert("Visitor updated successfully!");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('admin_visitor'))

    # Get visitor info
    cursor.execute("SELECT visitor_id, name, gender, ic, email, phone, picture FROM visitors WHERE status=1 AND "
                   "visitor_id=?", (visitor_id,))
    visitor_info = cursor.fetchone()

    # Convert BLOB to Base64 for the visitor picture
    visitor_picture = None
    if visitor_info[6]:
        # Detect image type
        image_type = imghdr.what(None, h=visitor_info[6])

        # Check if image type is valid
        if image_type in ['jpg', 'jpeg', 'png']:
            visitor_picture = (f"data:image/{image_type};base64," + base64.b64encode(visitor_info[6]).decode('utf-8'))

    # Get visitor vehicles
    cursor.execute("SELECT t.type, v.vehicle_number FROM visitor_vehicles v, vehicle_types t WHERE v.type_id=t.type_id "
                   "AND v.status=1 AND v.visitor_id=?", (visitor_id,))
    visitor_vehicles = cursor.fetchall()

    return render_template('edit_visitor.html', role=session['role'], visitor_info=visitor_info,
                           currentProfilePic=visitor_picture, visitor_vehicles=visitor_vehicles)


@app.route('/block-visitor/<visitor_id>', methods=['POST'])
def block_visitor(visitor_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE visitors SET status=0 WHERE visitor_id=?", (visitor_id,))
    cursor.execute("UPDATE visitor_vehicles SET status=0 WHERE visitor_id=?", (visitor_id,))
    cursor.execute("UPDATE invitations SET status=0 WHERE visitor_id=?", (visitor_id,))
    conn.commit()
    return jsonify({"message": "Visitor blocked successfully."})


@app.route('/unblock-visitor/<visitor_id>', methods=['POST'])
def unblock_visitor(visitor_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE visitors SET status=1 WHERE visitor_id=?", (visitor_id,))
    cursor.execute("UPDATE visitor_vehicles SET status=1 WHERE visitor_id=?", (visitor_id,))
    conn.commit()
    return jsonify({"message": "Visitor unblocked successfully."})


@app.route('/new_visitor', methods=['GET', 'POST'])
def new_visitor():
    if request.method == 'POST':
        picture = request.files.get('visitor-pic')
        name = request.form['name']
        email = request.form['email']
        gender = request.form['gender']
        ic = request.form['ic']
        phone = request.form['phone']
        new_vehicle_types = request.form.getlist('newVehicleType[]')
        new_vehicle_numbers = request.form.getlist('newVehicleNumber[]')

        # Validate and process picture
        if picture and picture.filename:
            error = validate_image(picture)
            if error:
                return f'''
                    <script>
                        alert("{error}");
                        window.location.href = "{url_for('new_visitor')}";
                    </script>
                    '''

            # Read the picture as binary for database storage
            picture_data = picture.read()

        else:
            picture_data = None

        # Validate contains only digits and length is 12
        if not re.match(r'^\d{12}$', ic):
            return '''
                <script>
                    alert("Please enter a valid ic and only digits are allowed.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('new_visitor'))

        # Validate contains only digits and length is 10/11
        elif not re.match(r'^\d{10,11}$', phone):
            return '''
                <script>
                    alert("Please enter a valid phone and only digits are allowed.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('new_visitor'))

        else:
            conn = get_db()
            cursor = conn.cursor()

            # Add new visitor
            cursor.execute("INSERT INTO visitors (name, gender, ic, email, phone, unit_id, picture, status)"
                           " VALUES (?, ?, ?, ?, ?, ?, ?, 1)", (name, gender, ic, email, phone, session['unit'],
                                                                picture_data))
            conn.commit()

            # Get new visitor_id
            cursor.execute("SELECT visitor_id FROM visitors WHERE ic=? AND status=1 AND unit_id=?",
                           (ic, session['unit']))
            visitor_id = cursor.fetchone()[0]

            # Add visitor vehicle details
            if not new_vehicle_types:
                pass
            else:
                # Insert new vehicles into the database
                for vehicle_type, vehicle_number in zip(new_vehicle_types, new_vehicle_numbers):
                    if vehicle_type and vehicle_number:
                        if vehicle_type == 'Car':
                            vehicle_id = 1
                        else:
                            vehicle_id = 2
                        cursor.execute("INSERT INTO visitor_vehicles (type_id, vehicle_number, visitor_id, "
                                       "status) VALUES (?, ?, ?, 1)", (vehicle_id, vehicle_number, visitor_id))
                        conn.commit()
            return '''
                <script>
                    alert("New visitor created successfully!");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('visitor'))

    return render_template('new_visitor.html', role=session['role'])


@app.route('/admin_new_visitor', methods=['GET', 'POST'])
def admin_new_visitor():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        picture = request.files.get('visitor-pic')
        name = request.form['name']
        email = request.form['email']
        gender = request.form['gender']
        unit_num = request.form['unit']
        ic = request.form['ic']
        phone = request.form['phone']
        new_vehicle_types = request.form.getlist('newVehicleType[]')
        new_vehicle_numbers = request.form.getlist('newVehicleNumber[]')

        # Validate and process picture
        if picture and picture.filename:
            error = validate_image(picture)
            if error:
                return f'''
                    <script>
                        alert("{error}");
                        window.location.href = "{url_for('admin_new_visitor')}";
                    </script>
                    '''

            # Read the picture as binary for database storage
            picture_data = picture.read()

        else:
            picture_data = None

        # Validate contains only digits and length is 12
        if not re.match(r'^\d{12}$', ic):
            return '''
                <script>
                    alert("Please enter a valid ic and only digits are allowed.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('admin_new_visitor'))

        # Validate contains only digits and length is 10/11
        elif not re.match(r'^\d{10,11}$', phone):
            return '''
                <script>
                    alert("Please enter a valid phone and only digits are allowed.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('admin_new_visitor'))

        else:
            # Add new visitor
            cursor.execute("INSERT INTO visitors (name, gender, ic, email, phone, unit_id, picture, status)"
                           " VALUES (?, ?, ?, ?, ?, ?, ?, 1)", (name, gender, ic, email, phone, unit_num, picture_data))
            conn.commit()

            # Get new visitor_id
            cursor.execute("SELECT visitor_id FROM visitors WHERE ic=? AND status=1 AND unit_id=?", (ic, unit_num))
            visitor_id = cursor.fetchone()[0]

            # Add visitor vehicle details
            if not new_vehicle_types:
                pass
            else:
                # Insert new vehicles into the database
                for vehicle_type, vehicle_number in zip(new_vehicle_types, new_vehicle_numbers):
                    if vehicle_type and vehicle_number:
                        if vehicle_type == 'Car':
                            vehicle_id = 1
                        else:
                            vehicle_id = 2
                        cursor.execute("INSERT INTO visitor_vehicles (type_id, vehicle_number, visitor_id, status) "
                                       "VALUES (?, ?, ?, 1)", (vehicle_id, vehicle_number, visitor_id))
                        conn.commit()
            return '''
                <script>
                    alert("New visitor created successfully!");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('admin_visitor'))

    # Get unit list
    cursor.execute("SELECT unit_id FROM units")
    unit_list = cursor.fetchall()

    return render_template('admin_new_visitor.html', unit_list=unit_list)


@app.route('/invitation_list')
def invitation_list():
    cursor = get_db().cursor()

    # Get invitation list
    cursor.execute("""
        SELECT v.visitor_id, v.name, v.picture, i.invitation_id, i.date, i.visitor_vehicle_id, vv.vehicle_number, 
        vt.type
        FROM visitors v
        INNER JOIN invitations i ON v.visitor_id=i.visitor_id
        LEFT JOIN visitor_vehicles vv ON i.visitor_vehicle_id=vv.visitor_vehicle_id
        LEFT JOIN vehicle_types vt ON vv.type_id=vt.type_id
        WHERE v.status=1 AND i.status=1 AND v.unit_id=?
        """, (session['unit'],))
    invitation_lists = cursor.fetchall()

    # Process visitors to convert profile pictures to Base64
    invitations = []
    for invitation in invitation_lists:
        # Convert BLOB to Base64 for the profile picture
        profile_picture = None
        if invitation[2]:
            # Detect image type
            image_type = imghdr.what(None, h=invitation[2])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                profile_picture = f"data:image/{image_type};base64," + base64.b64encode(invitation[2]).decode('utf-8')

        # Create a dictionary for the invitation with the Base64-encoded picture
        invitation_data = {"visitor_id": invitation[0], "name": invitation[1], "picture": profile_picture,
                           "invitation_id": invitation[3], "date": invitation[4], "vehicle_id": invitation[5],
                           "vehicle": f"{invitation[7]} ({invitation[6]})" if invitation[6] and invitation[7] else
                           "None"}
        invitations.append(invitation_data)

    return render_template('invitation_list.html', role=session['role'], invitations=invitations)


@app.route('/admin_invitation_list')
def admin_invitation_list():
    cursor = get_db().cursor()

    # Get invitation list
    cursor.execute("""
            SELECT v.visitor_id, v.name, v.picture, i.invitation_id, i.date, i.visitor_vehicle_id, vv.vehicle_number, 
            vt.type, v.unit_id
            FROM visitors v
            INNER JOIN invitations i ON v.visitor_id=i.visitor_id
            LEFT JOIN visitor_vehicles vv ON i.visitor_vehicle_id=vv.visitor_vehicle_id
            LEFT JOIN vehicle_types vt ON vv.type_id=vt.type_id
            WHERE v.status=1 AND i.status=1
            """)
    invitation_lists = cursor.fetchall()

    # Process visitors to convert profile pictures to Base64
    invitations = []
    for invitation in invitation_lists:
        # Convert BLOB to Base64 for the profile picture
        profile_picture = None
        if invitation[2]:
            # Detect image type
            image_type = imghdr.what(None, h=invitation[2])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                profile_picture = f"data:image/{image_type};base64," + base64.b64encode(invitation[2]).decode('utf-8')

        # Create a dictionary for the invitation with the Base64-encoded picture
        invitation_data = {"visitor_id": invitation[0], "name": invitation[1], "picture": profile_picture,
                           "invitation_id": invitation[3], "date": invitation[4], "vehicle_id": invitation[5],
                           "vehicle": f"{invitation[7]} ({invitation[6]})" if invitation[6] and invitation[7] else
                           "None", "unit_num": invitation[8]}
        invitations.append(invitation_data)

    return render_template('admin_invitation_list.html', invitations=invitations)


@app.route('/invitation_detail/<invitation_id>')
def invitation_detail(invitation_id):
    cursor = get_db().cursor()

    # Get invitation details
    cursor.execute("SELECT v.name, v.gender, v.ic, v.email, v.phone, v.picture, i.date, vv.vehicle_number, "
                   "vt.type, u.name, i.reason FROM invitations i, visitors v, visitor_vehicles vv, vehicle_types vt, "
                   "users u WHERE i.visitor_id=v.visitor_id AND i.visitor_vehicle_id=vv.visitor_vehicle_id AND "
                   "vv.type_id=vt.type_id AND i.user_id=u.user_id AND i.invitation_id=?", (invitation_id,))
    invitation_info = cursor.fetchone()

    # Convert BLOB to Base64 for the profile picture
    profile_picture = None
    if invitation_info[5]:
        # Detect image type
        image_type = imghdr.what(None, h=invitation_info[5])

        # Check if image type is valid
        if image_type in ['jpg', 'jpeg', 'png']:
            profile_picture = f"data:image/{image_type};base64," + base64.b64encode(invitation_info[5]).decode('utf-8')

    return render_template('invitation_detail.html', role=session['role'], profile_picture=profile_picture,
                           invitation_info=invitation_info)


@app.route('/admin_invitation_detail/<invitation_id>')
def admin_invitation_detail(invitation_id):
    cursor = get_db().cursor()

    # Get invitation details
    cursor.execute("SELECT v.name, v.gender, v.ic, v.email, v.phone, v.picture, i.date, vv.vehicle_number, "
                   "vt.type, u.name, i.reason, i.unit_id FROM invitations i, visitors v, visitor_vehicles vv, "
                   "vehicle_types vt, users u WHERE i.visitor_id=v.visitor_id AND "
                   "i.visitor_vehicle_id=vv.visitor_vehicle_id AND vv.type_id=vt.type_id AND i.user_id=u.user_id AND "
                   "i.invitation_id=?", (invitation_id,))
    invitation_info = cursor.fetchone()

    # Convert BLOB to Base64 for the profile picture
    profile_picture = None
    if invitation_info[5]:
        # Detect image type
        image_type = imghdr.what(None, h=invitation_info[5])

        # Check if image type is valid
        if image_type in ['jpg', 'jpeg', 'png']:
            profile_picture = f"data:image/{image_type};base64," + base64.b64encode(invitation_info[5]).decode('utf-8')

    return render_template('admin_invitation_detail.html', profile_picture=profile_picture,
                           invitation_info=invitation_info)


@app.route('/edit_invitation/<invitation_id>', methods=['GET', 'POST'])
def edit_invitation(invitation_id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        vehicle_value = request.form['vehicle']
        iso_date = request.form['date-picker']
        reason = request.form['reason']

        # Extract type and vehicle number
        type_part, vehicle_number_part = vehicle_value.split('(', 1)
        vehicle_type = type_part.strip()
        vehicle_number = vehicle_number_part.strip(' )')

        # Convert the ISO format date to DD-MM-YYYY format
        formatted_date = datetime.strptime(iso_date, '%Y-%m-%d').strftime('%d-%m-%Y')

        # Get vehicle id
        if vehicle_type == 'Car':
            type_id = 1
        else:
            type_id = 2
        cursor.execute("SELECT visitor_vehicle_id FROM visitor_vehicles WHERE type_id=? AND vehicle_number=?",
                       (type_id, vehicle_number))
        vehicle_id = cursor.fetchone()[0]

        # Update database
        cursor.execute("UPDATE invitations SET visitor_vehicle_id=?, date=?, reason=? WHERE invitation_id=?",
                       (vehicle_id, formatted_date, reason, invitation_id))
        conn.commit()

        return '''
            <script>
                alert("Invitation updated successfully.");
                window.location.href = "{}";
            </script>
            '''.format(url_for('invitation_list'))

    # Get current date
    current_date = date.today().isoformat()

    # Get invitation details
    cursor.execute("SELECT v.name, v.gender, v.ic, v.email, v.phone, v.picture, i.date, vv.vehicle_number, "
                   "vt.type, u.name, i.reason, i.visitor_id, i.invitation_id FROM invitations i, visitors v, "
                   "visitor_vehicles vv, vehicle_types vt, users u WHERE i.visitor_id=v.visitor_id AND "
                   "i.visitor_vehicle_id=vv.visitor_vehicle_id AND vv.type_id=vt.type_id AND i.user_id=u.user_id AND "
                   "i.invitation_id=?", (invitation_id,))
    invitation_info = cursor.fetchone()

    # Convert BLOB to Base64 for the profile picture
    profile_picture = None
    if invitation_info[5]:
        # Detect image type
        image_type = imghdr.what(None, h=invitation_info[5])

        # Check if image type is valid
        if image_type in ['jpg', 'jpeg', 'png']:
            profile_picture = f"data:image/{image_type};base64," + base64.b64encode(invitation_info[5]).decode(
                'utf-8')

    # Convert to ISO format
    date_object = datetime.strptime(invitation_info[6], '%d-%m-%Y')
    original_date = date_object.strftime('%Y-%m-%d')

    # Get visitor's vehicles
    cursor.execute("SELECT vt.type, vv.vehicle_number FROM visitor_vehicles vv, vehicle_types vt WHERE "
                   "vv.type_id=vt.type_id AND vv.visitor_id=?", (invitation_info[11],))
    vehicles = cursor.fetchall()

    # Process visitor's vehicles data
    vehicle = []
    for v in vehicles:
        # Create a dictionary for combine vehicle type and number
        vehicle_data = {"vehicle": f"{v[0]} ({v[1]})"}
        vehicle.append(vehicle_data)

    # Get current vehicle
    current_vehicle = f"{invitation_info[8]} ({invitation_info[7]})"

    return render_template('edit_invitation.html', role=session['role'], current_date=current_date,
                           profile_picture=profile_picture, original_date=original_date, vehicle=vehicle,
                           current_vehicle=current_vehicle, invitation_info=invitation_info)


@app.route('/admin_edit_invitation/<invitation_id>', methods=['GET', 'POST'])
def admin_edit_invitation(invitation_id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        vehicle_value = request.form['vehicle']
        iso_date = request.form['date-picker']
        reason = request.form['reason']

        # Extract type and vehicle number
        type_part, vehicle_number_part = vehicle_value.split('(', 1)
        vehicle_type = type_part.strip()
        vehicle_number = vehicle_number_part.strip(' )')

        # Convert the ISO format date to DD-MM-YYYY format
        formatted_date = datetime.strptime(iso_date, '%Y-%m-%d').strftime('%d-%m-%Y')

        # Get vehicle id
        if vehicle_type == 'Car':
            type_id = 1
        else:
            type_id = 2
        cursor.execute("SELECT visitor_vehicle_id FROM visitor_vehicles WHERE type_id=? AND vehicle_number=?",
                       (type_id, vehicle_number))
        vehicle_id = cursor.fetchone()[0]

        # Update database
        cursor.execute("UPDATE invitations SET visitor_vehicle_id=?, date=?, reason=? WHERE invitation_id=?",
                       (vehicle_id, formatted_date, reason, invitation_id))
        conn.commit()

        return '''
            <script>
                alert("Invitation updated successfully.");
                window.location.href = "{}";
            </script>
            '''.format(url_for('admin_invitation_list'))

    # Get current date
    current_date = date.today().isoformat()

    # Get invitation details
    cursor.execute("SELECT v.name, v.gender, v.ic, v.email, v.phone, v.picture, i.date, vv.vehicle_number, "
                   "vt.type, u.name, i.reason, i.visitor_id, i.unit_id, i.invitation_id FROM invitations i, visitors v,"
                   " visitor_vehicles vv, vehicle_types vt, users u WHERE i.visitor_id=v.visitor_id AND "
                   "i.visitor_vehicle_id=vv.visitor_vehicle_id AND vv.type_id=vt.type_id AND i.user_id=u.user_id AND "
                   "i.invitation_id=?", (invitation_id,))
    invitation_info = cursor.fetchone()

    # Convert BLOB to Base64 for the profile picture
    profile_picture = None
    if invitation_info[5]:
        # Detect image type
        image_type = imghdr.what(None, h=invitation_info[5])

        # Check if image type is valid
        if image_type in ['jpg', 'jpeg', 'png']:
            profile_picture = f"data:image/{image_type};base64," + base64.b64encode(invitation_info[5]).decode(
                'utf-8')

    # Convert to ISO format
    date_object = datetime.strptime(invitation_info[6], '%d-%m-%Y')
    original_date = date_object.strftime('%Y-%m-%d')

    # Get visitor's vehicles
    cursor.execute("SELECT vt.type, vv.vehicle_number FROM visitor_vehicles vv, vehicle_types vt WHERE "
                   "vv.type_id=vt.type_id AND vv.visitor_id=?", (invitation_info[11],))
    vehicles = cursor.fetchall()

    # Process visitor's vehicles data
    vehicle = []
    for v in vehicles:
        # Create a dictionary for combine vehicle type and number
        vehicle_data = {"vehicle": f"{v[0]} ({v[1]})"}
        vehicle.append(vehicle_data)

    # Get current vehicle
    current_vehicle = f"{invitation_info[8]} ({invitation_info[7]})"

    return render_template('admin_edit_invitation.html', current_date=current_date,
                           profile_picture=profile_picture, original_date=original_date, vehicle=vehicle,
                           current_vehicle=current_vehicle, invitation_info=invitation_info)


@app.route('/cancel-invitation/<invitation_id>', methods=['POST'])
def cancel_invitation(invitation_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE invitations SET status=0 WHERE invitation_id=?", (invitation_id,))
    conn.commit()
    return jsonify({"message": "Invitation cancelled successfully."})


@app.route('/get_vehicles/<visitor_id>')
def get_vehicles(visitor_id):
    conn = get_db()
    cursor = conn.cursor()

    # Get vehicles associated with the visitor
    cursor.execute("SELECT vv.visitor_vehicle_id, vt.type || ' (' || vv.vehicle_number || ')' AS vehicle FROM "
                   "visitor_vehicles vv, vehicle_types vt WHERE vv.type_id=vt.type_id AND vv.status=1 AND "
                   "vv.visitor_id=?", (visitor_id,))
    vehicles = cursor.fetchall()
    vehicle_data = [{"id": row[0], "vehicle": row[1]} for row in vehicles]

    return jsonify(vehicle_data)


@app.route('/new_invite', methods=['GET', 'POST'])
def new_invite():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        visitor_id = request.form['visitor']
        name = request.form['name']
        email = request.form['email']
        gender = request.form['gender']
        ic = request.form['ic']
        phone = request.form['phone']
        vehicle = request.form['vehicle']
        vehicle_type = request.form['vehicle-type']
        vehicle_number = request.form['vehicle-number']
        iso_date = request.form['date-picker']
        reason = request.form['reason']

        # Convert the ISO format date to DD-MM-YYYY format
        formatted_date = datetime.strptime(iso_date, '%Y-%m-%d').strftime('%d-%m-%Y')

        if visitor_id == 'new_visitor':
            # Validate contains only digits and length is 12
            if not re.match(r'^\d{12}$', ic):
                return '''
                    <script>
                        alert("Please enter a valid ic and only digits are allowed.");
                        window.location.href = "{}";
                    </script>
                    '''.format(url_for('new_invite'))

            # Validate contains only digits and length is 10/11
            elif not re.match(r'^\d{10,11}$', phone):
                return '''
                    <script>
                        alert("Please enter a valid phone and only digits are allowed.");
                        window.location.href = "{}";
                    </script>
                    '''.format(url_for('new_invite'))

            else:
                # Add new visitor
                cursor.execute("INSERT INTO visitors (name, gender, ic, email, phone, unit_id, status) VALUES (?,"
                               " ?, ?, ?, ?, ?, 1)", (name, gender, ic, email, phone, session['unit']))
                conn.commit()

                # Get new visitor_id
                cursor.execute("SELECT visitor_id FROM visitors WHERE ic=? AND status=1 AND unit_id=?",
                               (ic, session['unit']))
                visitor_id = cursor.fetchone()[0]

                # Insert new vehicles into the database
                if vehicle_type == 'Car':
                    vehicle_id = 1
                else:
                    vehicle_id = 2
                cursor.execute("INSERT INTO visitor_vehicles (type_id, vehicle_number, visitor_id, status) VALUES"
                               " (?, ?, ?, 1)", (vehicle_id, vehicle_number, visitor_id))
                conn.commit()

                # Get new vehicle_id
                cursor.execute("SELECT visitor_vehicle_id FROM visitor_vehicles WHERE type_id=? AND "
                               "vehicle_number=? AND visitor_id=? AND status=1", (vehicle_id, vehicle_number,
                                                                                  visitor_id))
                visitor_vehicle_id = cursor.fetchone()[0]

                # Insert new invitation details
                cursor.execute("INSERT INTO invitations (visitor_id, visitor_vehicle_id, date, reason, user_id, unit_id"
                               ", status) VALUES (?, ?, ?, ?, ?, ?, 1)", (visitor_id, visitor_vehicle_id,
                                                                          formatted_date, reason, session['user_id'],
                                                                          session['unit']))
                conn.commit()

                return '''
                    <script>
                        alert("Invitation created successfully!");
                        window.location.href = "{}";
                    </script>
                    '''.format(url_for('invitation_list'))

        else:
            if vehicle == 'new_vehicle':
                # Insert new vehicles into the database
                if vehicle_type == 'Car':
                    vehicle_id = 1
                else:
                    vehicle_id = 2
                cursor.execute("INSERT INTO visitor_vehicles (type_id, vehicle_number, visitor_id, status) VALUES"
                               " (?, ?, ?, 1)", (vehicle_id, vehicle_number, visitor_id))
                conn.commit()

                # Get new vehicle_id
                cursor.execute("SELECT visitor_vehicle_id FROM visitor_vehicles WHERE type_id=? AND "
                               "vehicle_number=? AND visitor_id=? AND status=1", (vehicle_id, vehicle_number,
                                                                                  visitor_id))
                visitor_vehicle_id = cursor.fetchone()[0]

                # Insert new invitation details
                cursor.execute("INSERT INTO invitations (visitor_id, visitor_vehicle_id, date, reason, user_id, unit_id"
                               ", status) VALUES (?, ?, ?, ?, ?, ?, 1)", (visitor_id, visitor_vehicle_id,
                                                                          formatted_date, reason, session['user_id'],
                                                                          session['unit']))
                conn.commit()

            else:
                # Insert new invitation details
                cursor.execute("INSERT INTO invitations (visitor_id, visitor_vehicle_id, date, reason, user_id, unit_id"
                               ", status) VALUES (?, ?, ?, ?, ?, ?, 1)", (visitor_id, vehicle, formatted_date, reason,
                                                                          session['user_id'], session['unit']))
                conn.commit()

            return '''
                <script>
                    alert("Invitation created successfully!");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('invitation_list'))

    # Get current date
    current_date = date.today().isoformat()

    # Get visitor
    cursor.execute("SELECT visitor_id, name FROM visitors WHERE status=1 AND unit_id=?", (session['unit'],))
    visitors = cursor.fetchall()

    return render_template('new_invite.html', current_date=current_date, visitors=visitors)


@app.route('/get_visitors/<unit_id>')
def get_visitors(unit_id):
    conn = get_db()
    cursor = conn.cursor()

    # Get visitors associated with the unit
    cursor.execute("SELECT visitor_id, name FROM visitors WHERE status=1 AND unit_id=?", (unit_id,))
    visitors = cursor.fetchall()
    visitor_list = [{"id": row[0], "name": row[1]} for row in visitors]

    return jsonify(visitor_list)


@app.route('/admin_new_invite', methods=['GET', 'POST'])
def admin_new_invite():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        unit_id = request.form['unit']
        visitor_id = request.form['visitor']
        name = request.form['name']
        email = request.form['email']
        gender = request.form['gender']
        ic = request.form['ic']
        phone = request.form['phone']
        vehicle = request.form['vehicle']
        vehicle_type = request.form['vehicle-type']
        vehicle_number = request.form['vehicle-number']
        iso_date = request.form['date-picker']
        reason = request.form['reason']

        # Convert the ISO format date to DD-MM-YYYY format
        formatted_date = datetime.strptime(iso_date, '%Y-%m-%d').strftime('%d-%m-%Y')

        if visitor_id == 'new_visitor':
            # Validate contains only digits and length is 12
            if not re.match(r'^\d{12}$', ic):
                return '''
                    <script>
                        alert("Please enter a valid ic and only digits are allowed.");
                        window.location.href = "{}";
                    </script>
                    '''.format(url_for('admin_new_invite'))

            # Validate contains only digits and length is 10/11
            elif not re.match(r'^\d{10,11}$', phone):
                return '''
                    <script>
                        alert("Please enter a valid phone and only digits are allowed.");
                        window.location.href = "{}";
                    </script>
                    '''.format(url_for('admin_new_invite'))

            else:
                # Add new visitor
                cursor.execute("INSERT INTO visitors (name, gender, ic, email, phone, unit_id, status) VALUES (?,"
                               " ?, ?, ?, ?, ?, 1)", (name, gender, ic, email, phone, unit_id))
                conn.commit()

                # Get new visitor_id
                cursor.execute("SELECT visitor_id FROM visitors WHERE ic=? AND status=1 AND unit_id=?", (ic, unit_id))
                visitor_id = cursor.fetchone()[0]

                # Insert new vehicles into the database
                if vehicle_type == 'Car':
                    vehicle_id = 1
                else:
                    vehicle_id = 2
                cursor.execute("INSERT INTO visitor_vehicles (type_id, vehicle_number, visitor_id, status) VALUES"
                               " (?, ?, ?, 1)", (vehicle_id, vehicle_number, visitor_id))
                conn.commit()

                # Get new vehicle_id
                cursor.execute("SELECT visitor_vehicle_id FROM visitor_vehicles WHERE type_id=? AND "
                               "vehicle_number=? AND visitor_id=? AND status=1", (vehicle_id, vehicle_number,
                                                                                  visitor_id))
                visitor_vehicle_id = cursor.fetchone()[0]

                # Insert new invitation details
                cursor.execute("INSERT INTO invitations (visitor_id, visitor_vehicle_id, date, reason, user_id, unit_id"
                               ", status) VALUES (?, ?, ?, ?, ?, ?, 1)", (visitor_id, visitor_vehicle_id,
                                                                          formatted_date, reason, session['user_id'],
                                                                          unit_id))
                conn.commit()

                return '''
                    <script>
                        alert("Invitation created successfully!");
                        window.location.href = "{}";
                    </script>
                    '''.format(url_for('admin_invitation_list'))

        else:
            if vehicle == 'new_vehicle':
                # Insert new vehicles into the database
                if vehicle_type == 'Car':
                    vehicle_id = 1
                else:
                    vehicle_id = 2
                cursor.execute("INSERT INTO visitor_vehicles (type_id, vehicle_number, visitor_id, status) VALUES"
                               " (?, ?, ?, 1)", (vehicle_id, vehicle_number, visitor_id))
                conn.commit()

                # Get new vehicle_id
                cursor.execute("SELECT visitor_vehicle_id FROM visitor_vehicles WHERE type_id=? AND "
                               "vehicle_number=? AND visitor_id=? AND status=1", (vehicle_id, vehicle_number,
                                                                                  visitor_id))
                visitor_vehicle_id = cursor.fetchone()[0]

                # Insert new invitation details
                cursor.execute("INSERT INTO invitations (visitor_id, visitor_vehicle_id, date, reason, user_id, unit_id"
                               ", status) VALUES (?, ?, ?, ?, ?, ?, 1)", (visitor_id, visitor_vehicle_id,
                                                                          formatted_date, reason, session['user_id'],
                                                                          unit_id))
                conn.commit()

            else:
                # Insert new invitation details
                cursor.execute("INSERT INTO invitations (visitor_id, visitor_vehicle_id, date, reason, user_id, unit_id"
                               ", status) VALUES (?, ?, ?, ?, ?, ?, 1)", (visitor_id, vehicle, formatted_date, reason,
                                                                          session['user_id'], unit_id))
                conn.commit()

            return '''
                <script>
                    alert("Invitation created successfully!");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('admin_invitation_list'))

    # Get current date
    current_date = date.today().isoformat()

    # Get unit list
    cursor.execute("SELECT unit_id FROM units")
    units = cursor.fetchall()

    return render_template('admin_new_invite.html', current_date=current_date, units=units)


@app.route('/blacklist')
def blacklist():
    cursor = get_db().cursor()

    # Get blacklist
    cursor.execute("SELECT visitor_id, name, gender, ic, picture FROM visitors WHERE status=0 AND unit_id=?",
                   (session['unit'],))
    blacklists_data = cursor.fetchall()

    # Process blacklist to convert profile pictures to Base64
    blacklists = []
    for blacklist_data in blacklists_data:
        # Convert BLOB to Base64 for the profile picture
        profile_picture = None
        if blacklist_data[4]:
            # Detect image type
            image_type = imghdr.what(None, h=blacklist_data[4])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                profile_picture = (f"data:image/{image_type};base64," + base64.b64encode(blacklist_data[4])
                                   .decode('utf-8'))

        # Create a dictionary for the blacklist with the Base64-encoded picture
        data = {"visitor_id": blacklist_data[0], "name": blacklist_data[1], "gender": blacklist_data[2],
                "ic": blacklist_data[3], "profile_picture": profile_picture}
        blacklists.append(data)

    return render_template('blacklist.html', role=session['role'], blacklists=blacklists)


@app.route('/admin_blacklist')
def admin_blacklist():
    cursor = get_db().cursor()

    # Get blacklist
    cursor.execute("SELECT visitor_id, name, gender, ic, picture, unit_id FROM visitors WHERE status=0")
    blacklists_data = cursor.fetchall()

    # Process blacklist to convert profile pictures to Base64
    blacklists = []
    for blacklist_data in blacklists_data:
        # Convert BLOB to Base64 for the profile picture
        profile_picture = None
        if blacklist_data[4]:
            # Detect image type
            image_type = imghdr.what(None, h=blacklist_data[4])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                profile_picture = (f"data:image/{image_type};base64," + base64.b64encode(blacklist_data[4])
                                   .decode('utf-8'))

        # Create a dictionary for the blacklist with the Base64-encoded picture
        data = {"visitor_id": blacklist_data[0], "name": blacklist_data[1], "gender": blacklist_data[2],
                "ic": blacklist_data[3], "profile_picture": profile_picture, "unit": blacklist_data[5]}
        blacklists.append(data)

    return render_template('admin_blacklist.html', blacklists=blacklists)


@app.route('/add_blacklist', methods=['GET', 'POST'])
def add_blacklist():
    if request.method == 'POST':
        picture = request.files.get('visitor-pic')
        name = request.form['name']
        gender = request.form['gender']
        ic = request.form['ic']

        # Validate and process picture
        if picture and picture.filename:
            error = validate_image(picture)
            if error:
                return f'''
                    <script>
                        alert("{error}");
                        window.location.href = "{url_for('add_blacklist')}";
                    </script>
                    '''

            # Read the picture as binary for database storage
            picture_data = picture.read()

        else:
            picture_data = None

        # Validate contains only digits and length is 12
        if not re.match(r'^\d{12}$', ic):
            return '''
                <script>
                    alert("Please enter a valid ic and only digits are allowed.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('add_blacklist'))

        else:
            conn = get_db()
            cursor = conn.cursor()

            # Add new blacklisted visitor
            cursor.execute("INSERT INTO visitors (name, gender, ic, unit_id, picture, status) VALUES (?, ?, ?, ?,"
                           " ?, 0)", (name, gender, ic, session['unit'], picture_data))
            conn.commit()

            return '''
                <script>
                    alert("New blacklisted visitor added successfully!");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('blacklist'))

    return render_template('add_blacklist.html', role=session['role'])


@app.route('/admin_add_blacklist', methods=['GET', 'POST'])
def admin_add_blacklist():
    cursor = get_db().cursor()

    if request.method == 'POST':
        picture = request.files.get('visitor-pic')
        name = request.form['name']
        gender = request.form['gender']
        ic = request.form['ic']
        unit_num = request.form['unit']

        # Validate and process picture
        if picture and picture.filename:
            error = validate_image(picture)
            if error:
                return f'''
                    <script>
                        alert("{error}");
                        window.location.href = "{url_for('admin_add_blacklist')}";
                    </script>
                    '''

            # Read the picture as binary for database storage
            picture_data = picture.read()

        else:
            picture_data = None

        # Validate contains only digits and length is 12
        if not re.match(r'^\d{12}$', ic):
            return '''
                <script>
                    alert("Please enter a valid ic and only digits are allowed.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('admin_add_blacklist'))

        else:
            conn = get_db()
            cursor = conn.cursor()

            # Add new blacklisted visitor
            cursor.execute("INSERT INTO visitors (name, gender, ic, unit_id, picture, status) VALUES (?, ?, ?, ?,"
                           " ?, 0)", (name, gender, ic, unit_num, picture_data))
            conn.commit()

            return '''
                <script>
                    alert("New blacklisted visitor added successfully!");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('admin_blacklist'))

    # Get unit list
    cursor.execute("SELECT unit_id FROM units")
    unit_list = cursor.fetchall()

    return render_template('admin_add_blacklist.html', unit_list=unit_list)


@app.route('/security_footage')
def security_footage():
    return render_template('security_footage.html')


def generate_video_feed(video_source, gate):
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()

        # Reset the dictionary
        detected_plates.clear()

        # Load YOLO model
        net = cv2.dnn.readNet("darknet/yolov4-obj_best.weights", "darknet/cfg/yolov4-obj.cfg")
        net.setPreferableBackend(cv2.dnn.DNN_BACKEND_CUDA)
        net.setPreferableTarget(cv2.dnn.DNN_TARGET_CUDA_FP16)

        # Initialize Detection Model
        model = cv2.dnn.DetectionModel(net)
        model.setInputParams(size=(416, 416), scale=1 / 255, swapRB=True)

        # Initialize PaddleOCR model
        ocr_model = PaddleOCR(lang='en')

        # Start video capture
        cap = cv2.VideoCapture(video_source)

        # Get mask
        mask = cv2.imread("static/asset/mask.png")

        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            if gate == 'entry':
                # Retrieve the allowed plates and valid dates before each frame processing
                cursor.execute("SELECT i.invitation_id, vv.vehicle_number, i.date FROM invitations i, "
                               "visitor_vehicles vv WHERE i.visitor_vehicle_id=vv.visitor_vehicle_id AND i.status=1 AND"
                               " i.date=?", (datetime.now().strftime('%d-%m-%Y'),))
            else:
                cursor.execute("SELECT i.invitation_id, vv.vehicle_number, i.date FROM invitations i, "
                               "visitor_vehicles vv WHERE i.visitor_vehicle_id=vv.visitor_vehicle_id AND i.status=0 AND"
                               " i.date=?", (datetime.now().strftime('%d-%m-%Y'),))
            data = cursor.fetchall()
            allowed_plates = [(row[0], re.sub(r'[\s,-.]', '', row[1]), row[2]) for row in data]

            # Apply mask to the frame
            region = cv2.bitwise_and(frame, mask)

            # Perform detection
            start = time.time()
            classes, scores, boxes = model.detect(region, CONFIDENCE_THRESHOLD, NMS_THRESHOLD)
            end = time.time()

            # Get current datetime
            full_timestamp = time.strftime('%d-%m-%Y %H:%M:%S')
            current_date, current_time = full_timestamp.split(' ')

            # Process detections
            for (classID, score, box) in zip(classes, scores, boxes):
                color = (0, 255, 255)
                cv2.rectangle(frame, box, color, 2)

                # Extract the region specified by the bounding box
                x, y, w, h = box
                region = frame[y:y + h, x:x + w]

                # Perform OCR on the detected region
                result = ocr_model.ocr(region)

                # Extract recognized text
                if result[0] is not None:
                    for line in result:
                        recognized_text, confidence_text = line[-1][1]

                        # Standardize plate text by removing spaces, commas, hyphens, and dots
                        standardized_plate = re.sub(r'[\s,-.]', '', recognized_text)

                        label = "%s : %.2f, %.2f" % (standardized_plate, score * 100, confidence_text * 100)
                        cv2.putText(frame, label, (box[0], box[1] - 5), cv2.FONT_HERSHEY_SIMPLEX, 1, color, 2)

                        # Check if detected plate matches an allowed plate with valid date
                        for invitation_id, db_plate, db_date in allowed_plates:
                            if standardized_plate == db_plate:
                                # Update the database with the detection timestamp
                                if gate == 'entry':
                                    cursor.execute("UPDATE invitations SET status=0 WHERE invitation_id=?",
                                                   (invitation_id,))
                                    cursor.execute("INSERT INTO visit_history (invitation_id, arrive_time) VALUES"
                                                   " (?, ?)", (invitation_id, current_time))
                                else:
                                    cursor.execute("UPDATE visit_history SET exit_time=? WHERE invitation_id=?",
                                                   (current_time, invitation_id))
                                conn.commit()

                        # Store only if this standardized plate hasn't been detected yet
                        if standardized_plate not in detected_plates:
                            detected_plates[standardized_plate] = current_time

            # Calculates and displays the frames per second (FPS)
            fps_text = "FPS: %.2f " % (1 / (end - start))

            # Define background color and rectangle coordinates
            background_color = (0, 0, 0)
            fps_rect = (50, 40, 200, 40)
            time_rect = (50, 80, 390, 40)

            # Draw rectangles for FPS and Time background
            cv2.rectangle(frame, (fps_rect[0], fps_rect[1]), (fps_rect[0] + fps_rect[2], fps_rect[1] + fps_rect[3]),
                          background_color, -1)
            cv2.rectangle(frame, (time_rect[0], time_rect[1]), (time_rect[0] + time_rect[2], time_rect[1] +
                                                                time_rect[3]), background_color, -1)

            # Overlay the FPS and current time text on top of the rectangles
            cv2.putText(frame, fps_text, (60, 70), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 140, 255), 2)
            cv2.putText(frame, full_timestamp, (60, 110), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 140, 255), 2)

            # Encode the frame for streaming
            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')


@app.route('/lpr_stream')
def lpr_stream():
    # Use the same video for demo purpose
    video_source = 'static/asset/video4.mov'
    gate = request.args.get('gate')
    return Response(generate_video_feed(video_source, gate), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/get_detected_plates')
def get_detected_plates():
    return jsonify(detected_plates)


@app.route('/staff')
def staff():
    cursor = get_db().cursor()
    cursor.execute("SELECT u.user_id, u.name, s.position, s.phone, u.email, u.picture FROM staffs s, users u WHERE "
                   "u.user_id=s.user_id AND u.status=1")
    staff_lists = cursor.fetchall()

    # Process staffs to convert profile pictures to Base64
    staff_list = []
    for staffs in staff_lists:
        # Convert BLOB to Base64 for the profile picture
        profile_picture = None
        if staffs[5]:
            # Detect image type
            image_type = imghdr.what(None, h=staffs[5])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                profile_picture = f"data:image/{image_type};base64," + base64.b64encode(staffs[5]).decode('utf-8')

        # Create a dictionary for the staff with the Base64-encoded picture
        staff_data = {"user_id": staffs[0], "name": staffs[1], "position": staffs[2], "phone": staffs[3],
                      "email": staffs[4], "profile_picture": profile_picture}
        staff_list.append(staff_data)
    return render_template('staff.html', role=session['role'], staffs=staff_list)


@app.route('/admin_staff')
def admin_staff():
    cursor = get_db().cursor()
    cursor.execute("SELECT u.user_id, u.name, s.position, s.phone, u.email, u.picture, u.status FROM staffs s, users u "
                   "WHERE u.user_id=s.user_id")
    staff_lists = cursor.fetchall()

    # Process staffs to convert profile pictures to Base64
    staff_list = []
    for staffs in staff_lists:
        # Convert BLOB to Base64 for the profile picture
        profile_picture = None
        if staffs[5]:
            # Detect image type
            image_type = imghdr.what(None, h=staffs[5])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                profile_picture = f"data:image/{image_type};base64," + base64.b64encode(staffs[5]).decode('utf-8')

        # Create a dictionary for the staff with the Base64-encoded picture
        staff_data = {"user_id": staffs[0], "name": staffs[1], "position": staffs[2], "phone": staffs[3],
                      "email": staffs[4], "profile_picture": profile_picture, "status": staffs[6]}
        staff_list.append(staff_data)
    return render_template('admin_staff.html', staffs=staff_list)


@app.route('/new_staff', methods=['GET', 'POST'])
def new_staff():
    if request.method == 'POST':
        picture = request.files.get('staff-pic')
        name = request.form['name']
        position = request.form['position']
        email = request.form['email']
        gender = request.form['gender']
        ic = request.form['ic']
        office_number = request.form['office-phone']
        personal_number = request.form['personal-phone']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        new_vehicle_types = request.form.getlist('newVehicleType[]')
        new_vehicle_numbers = request.form.getlist('newVehicleNumber[]')

        # Validate and process picture
        if picture and picture.filename:
            error = validate_image(picture)
            if error:
                return f'''
                    <script>
                        alert("{error}");
                        window.location.href = "{url_for('new_staff')}";
                    </script>
                    '''

            # Read the picture as binary for database storage
            picture_data = picture.read()

        else:
            picture_data = None

        # Define password policy
        password_policy = {
            'min_length': 8,
            'digit': r'[0-9]',
            'special_char': r'[!@#$%^&*(),.?":{}|<>]'
        }

        if password != confirm_password:
            return '''
                <script>
                    alert("Passwords do not match. Please try again.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('new_staff'))

        # Check if password meets policy
        elif len(password) < password_policy['min_length']:
            return '''
                <script>
                    alert("Password must be at least 8 characters long.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('new_staff'))
        elif not re.search(password_policy['digit'], password):
            return '''
                <script>
                    alert("Password must contain at least one digit.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('new_staff'))
        elif not re.search(password_policy['special_char'], password):
            return '''
                <script>
                    alert("Password must contain at least one special character.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('new_staff'))

        # Validate contains only digits and length is 12
        elif not re.match(r'^\d{12}$', ic):
            return '''
                <script>
                    alert("Please enter a valid ic and only digits are allowed.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('new_staff'))

        # Validate contains only digits and length is 9
        elif not re.match(r'^\d{9}$', office_number):
            return '''
                <script>
                    alert("Please enter a valid office phone and only digits are allowed.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('new_staff'))

        # Validate contains only digits and length is 10/11
        elif not re.match(r'^\d{10,11}$', personal_number):
            return '''
                <script>
                    alert("Please enter a valid phone and only digits are allowed.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('new_staff'))

        else:
            conn = get_db()
            cursor = conn.cursor()

            # Add new staff account
            cursor.execute("INSERT INTO users (name, gender, ic, email, password, phone, role_id, picture, status)"
                           " VALUES (?, ?, ?, ?, ?, ?, 1, ?, 1)", (name, gender, ic, email, password, personal_number,
                                                                   picture_data))
            conn.commit()

            # Get new staff user_id
            cursor.execute("SELECT user_id FROM users WHERE ic=? AND role_id=1 AND status=1", (ic,))
            staff_user_id = cursor.fetchone()[0]

            # Add new staff
            cursor.execute("INSERT INTO staffs (user_id, phone, position) VALUES (?, ?, ?)", (staff_user_id,
                                                                                              office_number, position))
            conn.commit()

            # Add staff vehicle details
            if not new_vehicle_types:
                pass
            else:
                # Insert new vehicles into the database
                for vehicle_type, vehicle_number in zip(new_vehicle_types, new_vehicle_numbers):
                    if vehicle_type and vehicle_number:
                        if vehicle_type == 'Car':
                            vehicle_id = 1
                        else:
                            vehicle_id = 2
                        cursor.execute("INSERT INTO user_vehicles (type_id, vehicle_number, user_id, status) "
                                       "VALUES (?, ?, ?, 1)", (vehicle_id, vehicle_number, staff_user_id))
                        conn.commit()
            return '''
                <script>
                    alert("New staff account created successfully!");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('admin_staff'))

    return render_template('new_staff.html')


@app.route('/edit_staff/<staff_id>', methods=['GET', 'POST'])
def edit_staff(staff_id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        picture = request.files.get('staff-pic')
        position = request.form['position']
        email = request.form['email']
        office_number = request.form['office-phone']
        personal_number = request.form['personal-phone']
        new_vehicle_types = request.form.getlist('newVehicleType[]')
        new_vehicle_numbers = request.form.getlist('newVehicleNumber[]')

        # Validate and process picture
        if picture and picture.filename:
            error = validate_image(picture)
            if error:
                return f'''
                    <script>
                        alert("{error}");
                        window.location.href = "{url_for('edit_staff', staff_id=staff_id)}";
                    </script>
                    '''

            # Read the picture as binary for database storage
            picture_data = picture.read()

        else:
            picture_data = None

        # Validate contains only digits and length is 9
        if not re.match(r'^\d{9}$', office_number):
            return f'''
                <script>
                    alert("Please enter a valid office phone and only digits are allowed.");
                    window.location.href = "{url_for('edit_staff', staff_id=staff_id)}";
                </script>
                '''

        # Validate contains only digits and length is 10/11
        elif not re.match(r'^\d{10,11}$', personal_number):
            return f'''
                <script>
                    alert("Please enter a valid phone and only digits are allowed.");
                    window.location.href = "{url_for('edit_staff', staff_id=staff_id)}";
                </script>
                '''

        else:
            # Update staff details
            if picture_data:
                cursor.execute("UPDATE users SET email=?, phone=?, picture=? WHERE user_id=?",
                               (email, personal_number, picture_data, staff_id))
            else:
                cursor.execute("UPDATE users SET email=?, phone=? WHERE user_id=?", (email, personal_number, staff_id))

            cursor.execute("UPDATE staffs SET phone=?, position=? WHERE user_id=?", (office_number, position, staff_id))
            conn.commit()

            # Add staff vehicle details
            if not new_vehicle_types:
                pass
            else:
                # Insert new vehicles into the database
                for vehicle_type, vehicle_number in zip(new_vehicle_types, new_vehicle_numbers):
                    if vehicle_type and vehicle_number:
                        if vehicle_type == 'Car':
                            vehicle_id = 1
                        else:
                            vehicle_id = 2

                        # Check if the vehicle already exists for the current user
                        cursor.execute("SELECT user_vehicle_id FROM user_vehicles WHERE type_id=? AND "
                                       "vehicle_number=? AND user_id=?", (vehicle_id, vehicle_number, staff_id))
                        existing_vehicle = cursor.fetchone()
                        if existing_vehicle is not None:
                            existing_vehicle_id = existing_vehicle[0]
                            cursor.execute("UPDATE user_vehicles SET status=1 WHERE user_vehicle_id=?",
                                           (existing_vehicle_id,))
                        else:
                            cursor.execute("INSERT INTO user_vehicles (type_id, vehicle_number, user_id, status) "
                                           "VALUES (?, ?, ?, 1)", (vehicle_id, vehicle_number, staff_id))
                        conn.commit()
            return '''
                <script>
                    alert("Staff updated successfully!");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('admin_staff'))

    # Get staff details
    cursor.execute("SELECT u.user_id, u.name, u.gender, u.ic, u.email, u.phone, u.picture, s.staff_id, s.phone, "
                   "s.position FROM staffs s, users u WHERE u.user_id=s.user_id AND u.status=1 AND u.user_id=?",
                   (staff_id,))
    staff_details = cursor.fetchone()

    # Convert BLOB to Base64 for the staff picture
    staff_picture = None
    if staff_details[6]:
        # Detect image type
        image_type = imghdr.what(None, h=staff_details[6])

        # Check if image type is valid
        if image_type in ['jpg', 'jpeg', 'png']:
            staff_picture = (f"data:image/{image_type};base64," + base64.b64encode(staff_details[6]).decode('utf-8'))

    # Get staff vehicles details
    cursor.execute("SELECT t.type, v.vehicle_number FROM user_vehicles v, vehicle_types t WHERE t.type_id = "
                   "v.type_id AND v.status=1 AND v.user_id=?", (staff_id,))
    staff_vehicles = cursor.fetchall()

    return render_template('edit_staff.html', staff_details=staff_details, currentProfilePic=staff_picture,
                           staff_vehicles=staff_vehicles)


@app.route('/resignee/<staff_id>')
def resignee(staff_id):
    conn = get_db()
    cursor = conn.cursor()

    # Get resigned staff details
    cursor.execute("SELECT u.user_id, u.name, u.gender, u.ic, u.email, u.phone, u.picture, s.staff_id, s.position "
                   "FROM staffs s, users u WHERE u.user_id=s.user_id AND u.status=0 AND u.user_id=?", (staff_id,))
    staff_details = cursor.fetchone()

    # Convert BLOB to Base64 for the staff picture
    staff_picture = None
    if staff_details[6]:
        # Detect image type
        image_type = imghdr.what(None, h=staff_details[6])

        # Check if image type is valid
        if image_type in ['jpg', 'jpeg', 'png']:
            staff_picture = (f"data:image/{image_type};base64," + base64.b64encode(staff_details[6]).decode('utf-8'))

    # Get staff vehicles details
    cursor.execute("SELECT t.type, v.vehicle_number FROM user_vehicles v, vehicle_types t WHERE t.type_id = "
                   "v.type_id AND v.user_id=?", (staff_id,))
    staff_vehicles = cursor.fetchall()

    return render_template('resignee.html', staff_details=staff_details, staff_picture=staff_picture,
                           staff_vehicles=staff_vehicles)


@app.route('/remove-staff/<user_id>', methods=['POST'])
def remove_staff(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status=0 WHERE user_id=?", (user_id,))
    cursor.execute("UPDATE user_vehicles SET status=0 WHERE user_id=?", (user_id,))
    conn.commit()
    return jsonify({"message": "Staff removed successfully."})


@app.route('/unit', methods=['GET', 'POST'])
def unit():
    conn = get_db()
    cursor = conn.cursor()
    if session['role'] == 'Owner':
        if request.method == 'POST':
            new_vehicle_types = request.form.getlist('newVehicleType[]')
            new_vehicle_numbers = request.form.getlist('newVehicleNumber[]')
            if not new_vehicle_types:
                pass
            else:
                # Insert new vehicles into the database
                for vehicle_type, vehicle_number in zip(new_vehicle_types, new_vehicle_numbers):
                    if vehicle_type and vehicle_number:
                        if vehicle_type == 'Car':
                            vehicle_id = 1
                        else:
                            vehicle_id = 2

                        # Check if the vehicle already exists for the current user
                        cursor.execute("SELECT user_vehicle_id FROM user_vehicles WHERE type_id=? AND "
                                       "vehicle_number=? AND user_id=?", (vehicle_id, vehicle_number,
                                                                          session['user_id']))
                        existing_vehicle = cursor.fetchone()
                        if existing_vehicle is not None:
                            existing_vehicle_id = existing_vehicle[0]
                            cursor.execute("UPDATE user_vehicles SET status=1 WHERE user_vehicle_id=?",
                                           (existing_vehicle_id,))
                        else:
                            cursor.execute("INSERT INTO user_vehicles (type_id, vehicle_number, user_id, status) "
                                           "VALUES (?, ?, ?, 1)", (vehicle_id, vehicle_number, session['user_id']))
                        conn.commit()

                return '''
                    <script>
                        alert("Vehicle added successfully!");
                        window.location.href = "{}";
                    </script>
                    '''.format(url_for('unit'))

        # Get unit id
        cursor.execute("SELECT unit_id FROM units WHERE user_id=?", (session['user_id'],))
        unit_num = cursor.fetchone()[0]

        # Get owner details
        cursor.execute("SELECT * FROM users WHERE user_id=?", (session['user_id'],))
        user = cursor.fetchone()

        # Convert BLOB to Base64 for the profile picture
        profile_picture = None
        if user[8]:
            # Detect image type
            image_type = imghdr.what(None, h=user[8])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                profile_picture = f"data:image/{image_type};base64," + base64.b64encode(user[8]).decode('utf-8')

        # Get owner's vehicles
        cursor.execute("SELECT t.type, v.vehicle_number FROM user_vehicles v, vehicle_types t WHERE t.type_id = "
                       "v.type_id AND v.status=1 AND v.user_id=?", (session['user_id'],))
        vehicles = cursor.fetchall()

        # Get unit tenant ids
        cursor.execute("SELECT t.user_id FROM unit_tenants t, users u WHERE t.user_id=u.user_id AND u.status=1 AND"
                       " t.unit_id=?", (unit_num,))
        tenant_user_ids = cursor.fetchall()

        tenants = []
        tenant_vehicles = {}
        for tenant_user_id in tenant_user_ids:
            # Fetch tenant details
            cursor.execute("SELECT * FROM users WHERE user_id=?", (tenant_user_id[0],))
            tenant = cursor.fetchone()

            # Convert BLOB to Base64 for the tenant's profile picture
            tenant_profile_picture = None
            if tenant[8]:
                # Detect image type
                image_type = imghdr.what(None, h=tenant[8])

                # Check if image type is valid
                if image_type in ['jpg', 'jpeg', 'png']:
                    tenant_profile_picture = (f"data:image/{image_type};base64," + base64.b64encode(tenant[8])
                                              .decode('utf-8'))

            tenants.append({'details': tenant, 'profile_picture': tenant_profile_picture})

            # Fetch tenant's vehicles
            cursor.execute("SELECT t.type, v.vehicle_number FROM user_vehicles v, vehicle_types t WHERE t.type_id "
                           "= v.type_id AND v.status=1 AND v.user_id=?", (tenant_user_id[0],))
            tenant_s_vehicle = cursor.fetchall()
            tenant_vehicles[tenant_user_id[0]] = tenant_s_vehicle

        return render_template('unit.html', unit=unit_num, role=session['role'], user=user,
                               profile_picture=profile_picture, vehicles=vehicles, tenants=tenants,
                               tenant_vehicles=tenant_vehicles)

    elif session['role'] == 'Tenant':
        if request.method == 'POST':
            new_vehicle_types = request.form.getlist('newVehicleType[]')
            new_vehicle_numbers = request.form.getlist('newVehicleNumber[]')
            if not new_vehicle_types:
                pass
            else:
                # Insert new vehicles into the database
                for vehicle_type, vehicle_number in zip(new_vehicle_types, new_vehicle_numbers):
                    if vehicle_type and vehicle_number:
                        if vehicle_type == 'Car':
                            vehicle_id = 1
                        else:
                            vehicle_id = 2

                        # Check if the vehicle already exists for the current user
                        cursor.execute("SELECT user_vehicle_id FROM user_vehicles WHERE type_id=? AND "
                                       "vehicle_number=? AND user_id=?", (vehicle_id, vehicle_number,
                                                                          session['user_id']))
                        existing_vehicle = cursor.fetchone()
                        if existing_vehicle is not None:
                            existing_vehicle_id = existing_vehicle[0]
                            cursor.execute("UPDATE user_vehicles SET status=1 WHERE user_vehicle_id=?",
                                           (existing_vehicle_id,))
                        else:
                            cursor.execute("INSERT INTO user_vehicles (type_id, vehicle_number, user_id, status) "
                                           "VALUES (?, ?, ?, 1)", (vehicle_id, vehicle_number, session['user_id']))
                        conn.commit()

                return '''
                    <script>
                        alert("Vehicle added successfully!");
                        window.location.href = "{}";
                    </script>
                    '''.format(url_for('unit'))

        # Get unit id
        cursor.execute("SELECT unit_id FROM unit_tenants WHERE user_id=?", (session['user_id'],))
        unit_num = cursor.fetchone()[0]

        # Get tenant details
        cursor.execute("SELECT * FROM users WHERE user_id=?", (session['user_id'],))
        tenant = cursor.fetchone()

        # Convert BLOB to Base64 for the profile picture
        tenant_profile_picture = None
        if tenant[8]:
            # Detect image type
            image_type = imghdr.what(None, h=tenant[8])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                tenant_profile_picture = (f"data:image/{image_type};base64," + base64.b64encode(tenant[8])
                                          .decode('utf-8'))

        # Get tenant's vehicles
        cursor.execute("SELECT t.type, v.vehicle_number FROM user_vehicles v, vehicle_types t WHERE t.type_id = "
                       "v.type_id AND v.status=1 AND v.user_id=?", (session['user_id'],))
        tenant_vehicles = cursor.fetchall()

        # Get unit owner id
        cursor.execute("SELECT user_id FROM units WHERE unit_id=?", (unit_num,))
        owner_id = cursor.fetchone()[0]

        # Get unit owner details
        cursor.execute("SELECT * FROM users WHERE user_id=?", (owner_id,))
        user = cursor.fetchone()

        # Convert BLOB to Base64 for the profile picture
        profile_picture = None
        if user[8]:
            # Detect image type
            image_type = imghdr.what(None, h=user[8])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                profile_picture = f"data:image/{image_type};base64," + base64.b64encode(user[8]).decode('utf-8')

        # Get owner's vehicles
        cursor.execute("SELECT t.type, v.vehicle_number FROM user_vehicles v, vehicle_types t WHERE t.type_id = "
                       "v.type_id AND v.status=1 AND v.user_id=?", (user[0],))
        vehicles = cursor.fetchall()

        return render_template('tenant_unit.html', unit=unit_num, role=session['role'], user=user,
                               profile_picture=profile_picture, vehicles=vehicles, tenant=tenant,
                               tenant_profile_picture=tenant_profile_picture, tenant_vehicles=tenant_vehicles)

    else:
        # Get unit list with owner details
        cursor.execute("SELECT units.unit_id, units.user_id, u.name, u.phone, u.email, u.picture FROM units LEFT JOIN "
                       "users u ON units.user_id = u.user_id")
        units_list = cursor.fetchall()

        # Process units to convert profile pictures to Base64
        unit_list = []
        for units in units_list:
            # Convert BLOB to Base64 for the profile picture
            profile_picture = None
            if units[5]:
                # Detect image type
                image_type = imghdr.what(None, h=units[5])

                # Check if image type is valid
                if image_type in ['jpg', 'jpeg', 'png']:
                    profile_picture = f"data:image/{image_type};base64," + base64.b64encode(units[5]).decode('utf-8')

            # Create a dictionary for the unit with the Base64-encoded picture
            unit_data = {"unit_id": units[0], "user_id": units[1], "name": units[2], "phone": units[3],
                         "email": units[4], "profile_picture": profile_picture}
            unit_list.append(unit_data)

        return render_template('unit_list.html', units=unit_list)


@app.route('/admin_unit', methods=['GET', 'POST'])
def admin_unit():
    unit_num = request.args.get('unit_id')
    if not unit_num:
        return abort(404, description="Invalid unit.")
    conn = get_db()
    cursor = conn.cursor()
    if request.method == 'POST':
        # Dictionary to store vehicles for each owner and tenant
        owner_vehicles = {}
        tenant_vehicles = {}
        vehicle_entry = {}

        # Combined loop to process both owner and tenant vehicle data
        for field_name, vehicle_data in request.form.items():
            # Check if the field is related to owner or tenant vehicles
            if field_name.startswith("ownerVehicles"):
                # Extract owner_id
                entity_id = field_name.split('[')[1].split(']')[0]

                # Initialize the list for the owner if not already present
                if entity_id not in owner_vehicles:
                    owner_vehicles[entity_id] = []
                current_dict = owner_vehicles[entity_id]

            elif field_name.startswith("tenantVehicles"):
                # Extract tenant_id
                entity_id = field_name.split('[')[1].split(']')[0]

                # Initialize the list for the tenant if not already present
                if entity_id not in tenant_vehicles:
                    tenant_vehicles[entity_id] = []
                current_dict = tenant_vehicles[entity_id]

            # Skip if the field is neither owner nor tenant vehicle
            else:
                continue

            # Store vehicle type or number in a temporary dictionary
            if 'type' in field_name:
                vehicle_entry = {'type': vehicle_data}
            elif 'number' in field_name:
                vehicle_entry['number'] = vehicle_data

                # Once both type and number are added, append to the appropriate list
                current_dict.append(vehicle_entry)

                # Reset for the next vehicle
                vehicle_entry = {}

        # Check if there are any vehicles to update or insert
        if not owner_vehicles and not tenant_vehicles:
            pass

        else:
            for owner_id, vehicles in owner_vehicles.items():
                for vehicle in vehicles:
                    vehicle_type = vehicle.get('type')
                    vehicle_number = vehicle.get('number')
                    if vehicle_type == 'Car':
                        vehicle_id = 1
                    else:
                        vehicle_id = 2

                    # Check if the vehicle already exists for the current user
                    cursor.execute("SELECT user_vehicle_id FROM user_vehicles WHERE type_id=? AND vehicle_number=?"
                                   " AND user_id=?", (vehicle_id, vehicle_number, owner_id))
                    existing_vehicle = cursor.fetchone()
                    if existing_vehicle is not None:
                        existing_vehicle_id = existing_vehicle[0]
                        cursor.execute("UPDATE user_vehicles SET status=1 WHERE user_vehicle_id=?",
                                       (existing_vehicle_id,))
                    else:
                        cursor.execute("INSERT INTO user_vehicles (type_id, vehicle_number, user_id, status) "
                                       "VALUES (?, ?, ?, 1)", (vehicle_id, vehicle_number, owner_id))
                    conn.commit()

            for tenant_id, vehicles in tenant_vehicles.items():
                for vehicle in vehicles:
                    vehicle_type = vehicle.get('type')
                    vehicle_number = vehicle.get('number')
                    if vehicle_type == 'Car':
                        vehicle_id = 1
                    else:
                        vehicle_id = 2

                    # Check if the vehicle already exists for the current user
                    cursor.execute("SELECT user_vehicle_id FROM user_vehicles WHERE type_id=? AND vehicle_number=?"
                                   " AND user_id=?", (vehicle_id, vehicle_number, tenant_id))
                    existing_vehicle = cursor.fetchone()
                    if existing_vehicle is not None:
                        existing_vehicle_id = existing_vehicle[0]
                        cursor.execute("UPDATE user_vehicles SET status=1 WHERE user_vehicle_id=?",
                                       (existing_vehicle_id,))
                    else:
                        cursor.execute("INSERT INTO user_vehicles (type_id, vehicle_number, user_id, status) "
                                       "VALUES (?, ?, ?, 1)", (vehicle_id, vehicle_number, tenant_id))
                    conn.commit()

            return '''
                <script>
                    alert("Vehicle added successfully!");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('admin_unit', unit_id=unit_num))

    # Get owner user id
    cursor.execute("SELECT units.user_id FROM units, users u WHERE units.user_id=u.user_id AND u.status=1 AND "
                   "units.unit_id=?", (unit_num,))
    result = cursor.fetchone()
    user_id = result[0] if result else None

    if not user_id:
        return render_template('admin_unit.html', unit=unit_num, role=session['role'], user=None,
                               profile_picture=None, vehicles=[], tenants=[], tenant_vehicles={})

    # Get owner details
    cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
    user = cursor.fetchone()

    # Convert BLOB to Base64 for the profile picture
    profile_picture = None
    if user[8]:
        # Detect image type
        image_type = imghdr.what(None, h=user[8])

        # Check if image type is valid
        if image_type in ['jpg', 'jpeg', 'png']:
            profile_picture = f"data:image/{image_type};base64," + base64.b64encode(user[8]).decode('utf-8')

    # Get owner's vehicles
    cursor.execute("SELECT t.type, v.vehicle_number FROM user_vehicles v, vehicle_types t WHERE t.type_id = "
                   "v.type_id AND v.status=1 AND v.user_id=?", (user_id,))
    vehicles = cursor.fetchall()

    # Get unit tenant ids
    cursor.execute("SELECT t.user_id FROM unit_tenants t, users u WHERE t.user_id=u.user_id AND u.status=1 AND"
                   " t.unit_id=?", (unit_num,))
    tenant_user_ids = cursor.fetchall()

    tenants = []
    tenant_vehicles = {}
    for tenant_user_id in tenant_user_ids:
        # Fetch tenant details
        cursor.execute("SELECT * FROM users WHERE user_id=?", (tenant_user_id[0],))
        tenant = cursor.fetchone()

        # Convert BLOB to Base64 for the tenant's profile picture
        tenant_profile_picture = None
        if tenant[8]:
            # Detect image type
            image_type = imghdr.what(None, h=tenant[8])

            # Check if image type is valid
            if image_type in ['jpg', 'jpeg', 'png']:
                tenant_profile_picture = (f"data:image/{image_type};base64," + base64.b64encode(tenant[8])
                                          .decode('utf-8'))

        tenants.append({'details': tenant, 'profile_picture': tenant_profile_picture})

        # Fetch tenant's vehicles
        cursor.execute("SELECT t.type, v.vehicle_number FROM user_vehicles v, vehicle_types t WHERE t.type_id "
                       "= v.type_id AND v.status=1 AND v.user_id=?", (tenant_user_id[0],))
        tenant_s_vehicle = cursor.fetchall()
        tenant_vehicles[tenant_user_id[0]] = tenant_s_vehicle

    # Get unit owner history
    cursor.execute("SELECT u.name, u.ic, h.date FROM unit_history h, users u WHERE h.user_id=u.user_id AND "
                   "u.role_id=2 AND h.unit_id=?", (unit_num,))
    owner_histories = cursor.fetchall()

    # Get unit tenant history
    cursor.execute("SELECT u.name, u.ic, h.date FROM unit_history h, users u WHERE h.user_id=u.user_id AND "
                   "u.role_id=3 AND h.unit_id=?", (unit_num,))
    tenant_histories = cursor.fetchall()

    return render_template('admin_unit.html', unit=unit_num, role=session['role'], user=user,
                           profile_picture=profile_picture, vehicles=vehicles, tenants=tenants,
                           tenant_vehicles=tenant_vehicles, owner_histories=owner_histories,
                           tenant_histories=tenant_histories)


@app.route('/remove-owner/<owner_id>/<unit_id>', methods=['POST'])
def remove_owner(owner_id, unit_id):
    # Get current date
    current_date = datetime.now().strftime("%d-%m-%Y")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE units SET user_id=NULL WHERE unit_id=?", (unit_id,))
    cursor.execute("UPDATE users SET status=0 WHERE user_id=?", (owner_id,))
    cursor.execute("INSERT INTO unit_history (unit_id, user_id, date) VALUES (?, ?, ?)",
                   (unit_id, owner_id, current_date))
    conn.commit()
    return jsonify({"message": "Owner remove successfully."})


@app.route('/remove-tenant/<role>/<tenant_id>/<unit_id>', methods=['POST'])
def remove_tenant(role, tenant_id, unit_id):
    # Get current date
    current_date = datetime.now().strftime("%d-%m-%Y")
    conn = get_db()
    cursor = conn.cursor()

    # Check request exist or not
    cursor.execute("SELECT * FROM requests WHERE type='remove tenant' AND unit_id=? AND user_id=? AND status=1",
                   (unit_id, tenant_id))
    request_exist = cursor.fetchone()

    if role == 'Admin':
        if request_exist:
            cursor.execute("UPDATE requests SET status=0 WHERE request_id=?", (request_exist[0],))
        cursor.execute("DELETE FROM unit_tenants WHERE user_id=?", (tenant_id,))
        cursor.execute("UPDATE users SET status=0 WHERE user_id=?", (tenant_id,))
        cursor.execute("INSERT INTO unit_history (unit_id, user_id, date) VALUES (?, ?, ?)",
                       (unit_id, tenant_id, current_date))
        conn.commit()
        return jsonify({"message": "Tenant remove successfully."})
    else:
        if request_exist:
            return jsonify({"message": "Request already sent. Please wait for admin approval."})
        else:
            cursor.execute("INSERT INTO requests (type, unit_id, user_id, status) VALUES ('remove tenant', ?, ?, "
                           "1)", (unit_id, tenant_id))
            conn.commit()
            return jsonify({"message": "Request sent to Admin. Please wait for their approval."})


@app.route('/remove-vehicle/<vehicle_type>/<vehicle_num>/<user_id>', methods=['POST'])
def remove_vehicle(vehicle_type, vehicle_num, user_id):
    conn = get_db()
    cursor = conn.cursor()
    if vehicle_type == 'Car':
        type_id = 1
    else:
        type_id = 2
    cursor.execute("UPDATE user_vehicles SET status=0 WHERE type_id=? AND vehicle_number=? AND user_id=?",
                   (type_id, vehicle_num, user_id))
    conn.commit()
    return jsonify({"message": "Vehicle removed successfully."})


@app.route('/remove-visitor-vehicle/<vehicle_type>/<vehicle_num>/<user_id>', methods=['POST'])
def remove_visitor_vehicle(vehicle_type, vehicle_num, user_id):
    conn = get_db()
    cursor = conn.cursor()
    if vehicle_type == 'Car':
        type_id = 1
    else:
        type_id = 2
    cursor.execute("UPDATE visitor_vehicles SET status=0 WHERE type_id=? AND vehicle_number=? AND visitor_id=?",
                   (type_id, vehicle_num, user_id))
    conn.commit()
    return jsonify({"message": "Vehicle removed successfully."})


@app.route('/generate-register-link/<unit_id>/<role>', methods=['POST'])
def generate_register_link(unit_id, role):
    token = secrets.token_urlsafe(16)
    if role == 'Tenant':
        role_id = 3
    else:
        role_id = 2
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO tokens (unit_id, role_id, token, status) VALUES (?, ?, ?, ?)",
                   (unit_id, role_id, token, 1))
    conn.commit()

    # Generate the registration link with the token
    register_link = f"http://localhost:5000/register?token={token}"
    return jsonify({'register_link': register_link})


@app.route('/register', methods=['GET', 'POST'])
def register():
    token = request.args.get('token')
    if not token:
        return abort(404, description="Registration link is missing.")
    conn = get_db()
    cursor = conn.cursor()

    # Check if token is valid and not used
    cursor.execute("SELECT * FROM tokens WHERE token=? AND status=1", (token,))
    token_data = cursor.fetchone()
    if not token_data:
        return abort(404, description="Invalid or expired registration link.")

    token_id = token_data[0]
    unit_num = token_data[1]
    if token_data[2] == 2:
        role_type = 'add owner'
    else:
        role_type = 'add tenant'

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        gender = request.form['gender']
        ic = request.form['ic']
        phone = request.form['phone']

        # Define password policy
        password_policy = {
            'min_length': 8,
            'digit': r'[0-9]',
            'special_char': r'[!@#$%^&*(),.?":{}|<>]'
        }

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('register', token=token))

        # Check if password meets policy
        elif len(password) < password_policy['min_length']:
            flash('Password must be at least 8 characters long.', 'error')
            return redirect(url_for('register', token=token))
        elif not re.search(password_policy['digit'], password):
            flash('Password must contain at least one digit.', 'error')
            return redirect(url_for('register', token=token))
        elif not re.search(password_policy['special_char'], password):
            flash('Password must contain at least one special character.', 'error')
            return redirect(url_for('register', token=token))

        # Validate contains only digits and length is 12
        elif not re.match(r'^\d{12}$', ic):
            flash('Please enter a valid ic and only digits are allowed.', 'error')
            return redirect(url_for('register', token=token))

        # Validate contains only digits and length is 10/11
        elif not re.match(r'^\d{10,11}$', phone):
            flash('Please enter a valid phone and only digits are allowed.', 'error')
            return redirect(url_for('register', token=token))

        else:
            # Update register info and close token
            cursor.execute("INSERT INTO registers (name, gender, ic, email, password, phone, token_id) VALUES "
                           "(?, ?, ?, ?, ?, ?, ?)", (name, gender, ic, email, password, phone, token_id))
            cursor.execute("UPDATE tokens SET status=0 WHERE token_id=?", (token_id,))
            conn.commit()

            # Get register_id
            cursor.execute("SELECT register_id FROM registers WHERE token_id=?", (token_id,))
            register_id = cursor.fetchone()[0]

            # Update request list
            cursor.execute("INSERT INTO requests (type, register_id, unit_id, status) VALUES (?, ?, ?, 1)",
                           (role_type, register_id, unit_num))
            conn.commit()

            return '''
                <script>
                    alert("Registration completed! Please wait for admin approval. You will be able to log in once " +
                        "your registration is approved.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('landing'))

    return render_template('register.html', token=token, unit_num=unit_num)


@app.route('/request_list')
def request_list():
    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM requests WHERE status=1")
    requests = cursor.fetchall()

    # Convert the second element of each tuple to title case
    requests = [(item[0], item[1].title(), *item[2:]) for item in requests]
    return render_template('request_list.html', requests=requests)


@app.route('/request_tenant_details/<request_id>', methods=['GET', 'POST'])
def request_tenant_details(request_id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        # Get request details
        cursor.execute("SELECT * FROM requests WHERE request_id=?", (request_id,))
        request_details = cursor.fetchone()
        request_type = request_details[1]

        # Update request
        cursor.execute("UPDATE requests SET status=0 WHERE request_id=?", (request_id,))
        conn.commit()

        # Check which button was pressed
        action = request.form.get('action')
        if request_type == 'add tenant':
            if action == 'approve':
                # Get registration details
                cursor.execute("SELECT registers.* FROM registers, requests r WHERE "
                               "registers.register_id=r.register_id AND r.request_id=?", (request_id,))
                register_details = cursor.fetchone()

                # Add new tenant account
                cursor.execute("INSERT INTO users (name, gender, ic, email, password, phone, role_id, status) "
                               "VALUES (?, ?, ?, ?, ?, ?, 3, 1)", (register_details[1], register_details[2],
                                                                   register_details[3], register_details[4],
                                                                   register_details[5], register_details[6]))
                conn.commit()

                # Get the new tenant's user_id and unit
                cursor.execute("SELECT user_id FROM users WHERE ic=? AND role_id=3 AND status=1",
                               (register_details[3],))
                new_tenant_user_id = cursor.fetchone()[0]
                unit_num = request_details[3]

                # Add tenant to unit
                cursor.execute("INSERT INTO unit_tenants (user_id, unit_id) VALUES (?, ?)",
                               (new_tenant_user_id, unit_num))
                conn.commit()

                # Send email to new tenant
                msg = Message('Registration Approved: Welcome to Your New Home!', recipients=[register_details[4]])
                msg.body = (f"Hello {register_details[1]},\n\nCongratulations! Your registration has been approved by "
                            f"the admin. We are thrilled to welcome you as a part of our community.\n\nBest regards,\n"
                            f"CommunityCTRL")
                mail.send(msg)

                return '''
                    <script>
                        alert("New tenant added.");
                        window.location.href = "{}";
                    </script>
                    '''.format(url_for('request_list'))

            return '''
                <script>
                    alert("Request declined successfully.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('request_list'))

        else:
            if action == 'approve':
                # Get current date
                current_date = datetime.now().strftime("%d-%m-%Y")

                # Remove tenant
                cursor.execute("UPDATE users SET status=0 WHERE user_id=?", (request_details[4],))
                cursor.execute("DELETE FROM unit_tenants WHERE user_id=?", (request_details[4],))
                cursor.execute("INSERT INTO unit_history (unit_id, user_id, date) VALUES (?, ?, ?)",
                               (request_details[3], request_details[4], current_date))
                conn.commit()

                return '''
                    <script>
                        alert("Tenant removed.");
                        window.location.href = "{}";
                    </script>
                    '''.format(url_for('request_list'))

            return '''
                <script>
                    alert("Request declined successfully.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('request_list'))

    # Get request details
    cursor.execute("SELECT * FROM requests WHERE request_id=?", (request_id,))
    request_details = cursor.fetchone()

    # Unpack and modify the second element
    request_details = (request_details[0], request_details[1].title(), *request_details[2:])

    # Get unit_id
    unit_num = request_details[3]

    # Get owner details
    cursor.execute("SELECT u.* FROM units, users u WHERE u.user_id=units.user_id AND u.status=1 AND "
                   "units.unit_id=?", (unit_num,))
    user = cursor.fetchone()

    if request_details[1] == 'Add Tenant':
        # Get registration details
        cursor.execute("SELECT registers.* FROM registers, requests r WHERE registers.register_id=r.register_id AND "
                       "r.register_id=?", (request_details[2],))
        register_details = cursor.fetchone()

        return render_template('request_tenant_details.html', unit=unit_num, user=user, request_details=request_details,
                               register_details=register_details)

    else:
        # Get tenant details
        cursor.execute("SELECT * FROM users WHERE user_id=?", (request_details[4],))
        tenant_details = cursor.fetchone()

        return render_template('request_tenant_details.html', unit=unit_num, user=user, request_details=request_details,
                               tenant_details=tenant_details)


@app.route('/request_owner_details/<request_id>', methods=['GET', 'POST'])
def request_owner_details(request_id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        # Get request details
        cursor.execute("SELECT * FROM requests WHERE request_id=?", (request_id,))
        request_details = cursor.fetchone()

        # Update request
        cursor.execute("UPDATE requests SET status=0 WHERE request_id=?", (request_id,))
        conn.commit()

        # Check which button was pressed
        action = request.form.get('action')
        if action == 'approve':
            # Get registration details
            cursor.execute("SELECT registers.* FROM registers, requests r WHERE "
                           "registers.register_id=r.register_id AND r.request_id=?", (request_id,))
            register_details = cursor.fetchone()

            # Add new owner account
            cursor.execute("INSERT INTO users (name, gender, ic, email, password, phone, role_id, status) "
                           "VALUES (?, ?, ?, ?, ?, ?, 2, 1)", (register_details[1], register_details[2],
                                                               register_details[3], register_details[4],
                                                               register_details[5], register_details[6]))
            conn.commit()

            # Get the new owner's user_id and unit
            cursor.execute("SELECT user_id FROM users WHERE ic=? AND role_id=2 AND status=1",
                           (register_details[3],))
            new_owner_user_id = cursor.fetchone()[0]
            unit_num = request_details[3]

            # Update owner to unit
            cursor.execute("UPDATE units SET user_id=? WHERE unit_id=?", (new_owner_user_id, unit_num))
            conn.commit()

            # Send email to new tenant
            msg = Message('Registration Approved: Welcome to Your New Home!', recipients=[register_details[4]])
            msg.body = (f"Hello {register_details[1]},\n\nCongratulations! Your registration has been approved by "
                        f"the admin. We are thrilled to welcome you as a part of our community.\n\nBest regards,\n"
                        f"CommunityCTRL")
            mail.send(msg)

            return '''
                <script>
                    alert("New owner added.");
                    window.location.href = "{}";
                </script>
                '''.format(url_for('request_list'))

        return '''
            <script>
                alert("Request declined successfully.");
                window.location.href = "{}";
            </script>
            '''.format(url_for('request_list'))

    # Get request details
    cursor.execute("SELECT * FROM requests WHERE request_id=?", (request_id,))
    request_details = cursor.fetchone()

    # Unpack and modify the second element
    request_details = (request_details[0], request_details[1].title(), *request_details[2:])

    # Get unit_id
    unit_num = request_details[3]

    # Get registration details
    cursor.execute("SELECT registers.* FROM registers, requests r WHERE registers.register_id=r.register_id AND "
                   "r.register_id=?", (request_details[2],))
    register_details = cursor.fetchone()

    return render_template('request_owner_details.html', unit=unit_num, request_details=request_details,
                           register_details=register_details)


if __name__ == '__main__':
    app.run(debug=True)
