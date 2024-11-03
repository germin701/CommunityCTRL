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
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
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
            return render_template('profile.html', user=user, role=session['role'],
                                   alert_message="OTP verified! Email updated successfully!")
        else:
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
            cursor.execute("UPDATE users SET password=? WHERE user_id=?", (new_password, session['user_id']))
            conn.commit()
            return render_template('profile.html', user=user, role=session['role'],
                                   alert_message="Password updated successfully!")


def validate_announcement_image(file):
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
            error = validate_announcement_image(picture)
            if error:
                return f'''
                    <script>
                        alert("{error}");
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
            error = validate_announcement_image(picture)
            if error:
                return f'''
                    <script>
                        alert("{error}");
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


@app.route('/security_footage')
def security_footage():
    return render_template('security_footage.html')


def generate_video_feed(video_source):
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

        # Apply mask to the frame
        region = cv2.bitwise_and(frame, mask)

        # Perform detection
        start = time.time()
        classes, scores, boxes = model.detect(region, CONFIDENCE_THRESHOLD, NMS_THRESHOLD)
        end = time.time()

        # Get current datetime
        current_time = time.strftime('%Y-%m-%d %H:%M:%S')

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

                    # Store only if this standardized plate hasn't been detected yet
                    if standardized_plate not in detected_plates:
                        detected_plates[standardized_plate] = current_time

        # Calculates and displays the frames per second (FPS)
        fps_text = "FPS: %.2f " % (1 / (end - start))

        # Define background color and rectangle coordinates
        background_color = (0, 0, 0)  # Black background
        fps_rect = (50, 40, 200, 40)  # (x, y, width, height) for FPS
        time_rect = (50, 80, 390, 40)  # (x, y, width, height) for Time

        # Draw rectangles for FPS and Time background
        cv2.rectangle(frame, (fps_rect[0], fps_rect[1]), (fps_rect[0] + fps_rect[2], fps_rect[1] + fps_rect[3]),
                      background_color, -1)
        cv2.rectangle(frame, (time_rect[0], time_rect[1]), (time_rect[0] + time_rect[2], time_rect[1] + time_rect[3]),
                      background_color, -1)

        # Overlay the FPS and current time text on top of the rectangles
        cv2.putText(frame, fps_text, (60, 70), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 140, 255), 2)
        cv2.putText(frame, current_time, (60, 110), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 140, 255), 2)

        # Encode the frame for streaming
        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    # Print unique detected plates with their first detection time
    for plate, timestamp in detected_plates.items():
        print(f"Plate: {plate}, Time: {timestamp}")


@app.route('/lpr_stream')
def lpr_stream():
    # Use the same video for demo purpose
    video_source = 'static/asset/video4.mov'
    return Response(generate_video_feed(video_source), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/get_detected_plates')
def get_detected_plates():
    return jsonify(detected_plates)


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
                            cursor.execute("INSERT INTO user_vehicles (type_id, vehicle_number, user_id) VALUES "
                                           "(?, ?, ?)", (vehicle_id, vehicle_number, session['user_id']))
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
        cursor.execute("SELECT units.unit_id, units.user_id, u.name, u.phone, u.email FROM units LEFT JOIN users u ON "
                       "units.user_id = u.user_id")
        units = cursor.fetchall()

        return render_template('unit_list.html', units=units)


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

    return render_template('admin_unit.html', unit=unit_num, role=session['role'], user=user,
                           profile_picture=profile_picture, vehicles=vehicles, tenants=tenants,
                           tenant_vehicles=tenant_vehicles)


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
