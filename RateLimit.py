import logging
from flask import Flask, request, make_response, render_template, session, jsonify, redirect, url_for, flash
from functools import wraps
import jwt as pyjwt
from collections import defaultdict
import uuid, datetime, sqlite3, hashlib, random, os, secrets, requests, string

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


lab_type = ""#APIAbuse"
lab_name = ""#RateLimitLab"

user_data = {}

RateLimit = Flask(__name__)
RateLimit.secret_key = "vulnerable_lab_by_IHA089"

RATE_LIMIT = 5
RATE_LIMIT_WINDOW = 60

request_counts = defaultdict(lambda: [0, time.time()])

JWT_SECRET = "MoneyIsPower"

class OTPSystem:
    def __init__(self):
        self.otp_store = {}

    def generate_otp(self, username):
        # Generate a 6-digit OTP
        otp = random.randint(1000, 9999)
        # Store the OTP with the current timestamp
        self.otp_store[username] = {
            'otp': otp,
            'timestamp': time.time()
        }
        print(f"OTP for {username}: {otp}")
        return otp

    def validate_otp(self, username, otp):
        current_time = time.time()
        user_data = self.otp_store.get(username)

        if not user_data:
            return "OTP not found or expired."

        # Check if the OTP has expired (5 minutes = 300 seconds)
        if current_time - user_data['timestamp'] > 300:
            del self.otp_store[username]  # Clean up expired OTP
            return "OTP has expired."

        # Check if the OTP matches
        if user_data['otp'] == otp:
            del self.otp_store[username]  # Clean up used OTP
            return "OTP is valid"
        else:
            return "Invalid OTP."


def is_rate_limited(ip):
    count, first_request_time = request_counts[ip]
    current_time = time.time()

    if current_time - first_request_time > RATE_LIMIT_WINDOW:
        request_counts[ip] = [1, current_time]
        return False

    if count < RATE_LIMIT:
        request_counts[ip][0] += 1
        return False

    return True

def create_database():
    db_path = os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        gmail TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        uuid TEXT NOT NULL,
        active TINYINT(1) DEFAULT 0,
        code TEXT NOT NULL
    )
    ''')

    numb = random.randint(100, 999)
    passw = "admin@"+str(numb)
    passw_hash = hashlib.md5(passw.encode()).hexdigest()
    user_uuid = str(uuid.uuid4())
    query = "INSERT INTO users (gmail, username, password, uuid, active, code) VALUES ('admin@iha089.org', 'admin', '"+passw_hash+"', '"+user_uuid+"', '1', '45AEDF32')"
    cursor.execute(query)

    cursor.execute('''
    CREATE TABLE token_info(
        gmail TEXT NOT NULL,
        token TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    conn.commit()
    conn.close()

def generate_code():
    first_two = ''.join(random.choices(string.digits, k=2))
    next_four = ''.join(random.choices(string.ascii_uppercase, k=4))
    last_two = ''.join(random.choices(string.digits, k=2))
    code = first_two + next_four + last_two
    return code
    
def check_database():
    db_path = os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    if not os.path.isfile(db_path):
        create_database()

check_database()

def get_db_connection():
    db_path=os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def check_cookies():
    user_uuid = request.cookies.get("uuid")
    jwt_token = request.cookies.get("jwt_token")

    if user_uuid in user_data and jwt_token == user_data[user_uuid]:
        decoded = pyjwt.decode(jwt_token, JWT_SECRET, algorithms="HS256")
        session['user'] = decoded['username']
        return True
    else:
        return False

@RateLimit.route('/')
def home():
    if not check_cookies():
        session.clear()
    return render_template('index.html', user=session.get('user'))

@RateLimit.route('/index.html')
def index_html():
    if not check_cookies():
        session.clear()
    return render_template('index.html', user=session.get('user'))

@RateLimit.route('/login.html')
def login_html():
    if not check_cookies():
        session.clear()
    return render_template('login.html')

@RateLimit.route('/join.html')
def join_html():
    if not check_cookies():
        session.clear()
    return render_template('join.html')

@RateLimit.route('/forgot-password.html')
def forgor_password_html():
    if not check_cookies():
        session.clear()
    if 'user' in session:
        return render_template('dashboard.html', user=session.get('user'))
    return render_template('forgot-password.html')

@RateLimit.route('/acceptable.html')
def acceptable_html():
    if not check_cookies():
        session.clear()
    return render_template('acceptable.html', user=session.get('user'))

@RateLimit.route('/term.html')
def term_html():
    if not check_cookies():
        session.clear()
    return render_template('term.html', user=session.get('user'))

@RateLimit.route('/privacy.html')
def privacy_html():
    if not check_cookies():
        session.clear()
    return render_template('privacy.html', user=session.get('user'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        check_cookies()
        if 'user' not in session:  
            return redirect(url_for('login_html', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@RateLimit.route('/confirm', methods=['POST'])
def confirm():
    username = request.form.get('username')
    password = request.form.get('password')
    code = request.form.get('confirmationcode')
    hash_password=hashlib.md5(password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT *FROM users WHERE username = ? or gmail = ? AND password=? AND code = ?", (username, username, hash_password, code))
    user = cursor.fetchone()
    
    if user:
        cursor.execute("UPDATE users SET active = 1 WHERE username = ? or gmail = ?", (username, username))
        conn.commit()
        conn.close()
        session['user'] = username
        
        user_uuid = user['uuid'] if 'uuid' in user else str(uuid.uuid4())

        jwt_token = pyjwt.encode({
            "username": username,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm="HS256")

        user_data[user_uuid] = jwt_token

        if 'uuid' not in user:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET uuid = ? WHERE username = ?", (user_uuid, username))
            conn.commit()
            conn.close()

        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie("uuid", user_uuid, httponly=True, samesite="Strict")
        response.set_cookie("jwt_token", jwt_token, httponly=True, samesite="Strict")
        return response
    
    conn.close()
    error_message = "Invalid code"
    return render_template('confirm.html', error=error_message, username=username, password=password)

@RateLimit.route('/sendOTP', methods=['POST'])
def sendOTP():
    username = request.form.get('username')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT *FROM users WHERE username = ? or gmail = ?", (username, username))
    check = cursor.fetchone()
    conn.close()
    if check:
        otp_system = OTPSystem()
        get_otp=otp_system.generate_otp(username)

        username = username.replace(" ", "")
        bdcontent = "<h2>Login Your Account via OTP</h2><p>your OTP is given below</p><div style=\"background-color: orange; color: black; font-size: 14px; padding: 10px; border-radius: 5px; font-family: Arial, sans-serif;\">"+get_otp+"</div><p>If you did not request this, please ignore this email.</p>"
        mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
        payload = {"email": username,
                    "sender":"IHA089 Labs ::: RateLimitLab",
                    "subject":"RateLimitLab::Login Your Accout via OTP",
                    "bodycontent":bdcontent
                }
        try:
            k = requests.post(mail_server, json = payload)
        except:
            return jsonify({"error": "Mail server is not responding"}), 500  

    return render_template('confirmotp.html', username=username)

@RateLimit.route('/confirmotp', methods=['POST'])
def confirmotp():
    username = request.form.get('username')
    otp = request.form.get('confirmationotp')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    if is_rate_limited(ip):
        return jsonify({"error": "Rate limit exceeded"}), 429

    otp_system = OTPSystem()
    check = otp_system.validate_otp(username, otp)
    if check == "OTP is valid":
        session['user'] = username
        user_uuid = user['uuid'] if 'uuid' in user else str(uuid.uuid4())

        jwt_token = pyjwt.encode({
            "username": username,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm="HS256")

        user_data[user_uuid] = jwt_token

        if 'uuid' not in user:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET uuid = ? WHERE username = ?", (user_uuid, username))
            conn.commit()
            conn.close()

        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie("uuid", user_uuid, httponly=True, samesite="Strict")
        response.set_cookie("jwt_token", jwt_token, httponly=True, samesite="Strict")
        return response

@RateLimit.route('/resend', methods=['POST'])
def resend():
    username = request.form.get('username')
    password = request.form.get('password')
    hash_password=hashlib.md5(password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT code FROM users WHERE username = ? or gmail = ? AND password = ?", (username, username, hash_password))
    code = cursor.fetchone()
    if code:
        username=username
        username = username.replace(" ", "")
        bdcontent = "<h2>Verify Your Account password</h2><p>your verification code are given below</p><div style=\"background-color: orange; color: black; font-size: 14px; padding: 10px; border-radius: 5px; font-family: Arial, sans-serif;\">"+code[0]+"</div><p>If you did not request this, please ignore this email.</p>"
        mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
        payload = {"email": username,
                    "sender":"IHA089 Labs ::: RateLimitLab",
                    "subject":"RateLimitLab::Verify Your Accout",
                    "bodycontent":bdcontent
                }
        try:
            k = requests.post(mail_server, json = payload)
        except:
            return jsonify({"error": "Mail server is not responding"}), 500
        error_message="code sent"
    else:
        error_message="Invalid username or password"

    conn.close()
    return render_template('confirm.html', error=error_message, username=username, password=password)

@RateLimit.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        user_uuid = request.cookies.get("uuid")
        jwt_token = request.cookies.get("jwt_token")

        if user_uuid in user_data and jwt_token == user_data[user_uuid]:
            decoded = pyjwt.decode(jwt_token, JWT_SECRET, algorithms="HS256")
            session['user'] = decoded['username']
            return redirect(url_for('dashboard'))

        return render_template('login.html')

    username = request.form.get('username')
    password = request.form.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()
    hash_password = hashlib.md5(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE username = ? or gmail = ? AND password = ?", (username, username, hash_password))
    user = cursor.fetchone()
    conn.close()

    if user:
        if not user[5] == 1:
            return render_template('confirm.html', username=username, password=password)

        session['user'] = username
        user_uuid = user['uuid'] if 'uuid' in user else str(uuid.uuid4())

        jwt_token = pyjwt.encode({
            "username": username,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm="HS256")

        user_data[user_uuid] = jwt_token

        if 'uuid' not in user:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET uuid = ? WHERE username = ?", (user_uuid, username))
            conn.commit()
            conn.close()

        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie("uuid", user_uuid, httponly=True, samesite="Strict") 
        response.set_cookie("jwt_token", jwt_token, httponly=True, samesite="Strict")
        return response

    error_message = "Invalid username or password. Please try again."
    return render_template('login.html', error=error_message)

@RateLimit.route('/resetpassword', methods=['POST'])
def resetpassword():
    password=request.form.get('password')
    token = request.form.get('token')
    if not token or token == "11111111111111111111":
        flash("Token is missing.")
        return redirect(url_for('home'))
    query = "SELECT gmail FROM token_info where token = ?"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, (token,))
    result = cursor.fetchone()
    conn.close()
    if result:
        conn = get_db_connection()
        cursor = conn.cursor()
        hash_password = hashlib.md5(password.encode()).hexdigest()
        query = "UPDATE users SET password = ? WHERE gmail = ?"
        cursor.execute(query, (hash_password, result[0], ))
        conn.commit()
        conn.close()
        flash("Password updated successfully.")
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "UPDATE token_info SET token = 11111111111111111111 WHERE gmail = ?"
        cursor.execute(query, (result[0], ))
        conn.commit()
        conn.close()
        return redirect(url_for('login_html'))
    else:
        flash("Invalid token. Please try again.")
        return redirect(url_for('home'))
    
@RateLimit.route('/join', methods=['GET', 'POST'])
def join():
    if not check_cookies():
        session.clear()
    if 'user' in session:
        return render_template('dashboard.html', user=session.get('user'))

    email = request.form.get('email')
    username = request.form.get('username')
    password = request.form.get('password')
    if not email.endswith('@iha089.org'):
        error_message = "Only email with @iha089.org domain is allowed."
        return render_template('join.html', error=error_message)
    conn = get_db_connection()
    cursor = conn.cursor()
    hash_password = hashlib.md5(password.encode()).hexdigest()
    query = f"INSERT INTO users (gmail, username, password) VALUES ('{email}', '{username}', '{hash_password}')".format(email, username, password)
    cursor.execute("SELECT * FROM users where gmail = ?", (email,))
    if cursor.fetchone():
        error_message = "Email already taken. Please choose another."
        conn.close()
        return render_template('join.html', error=error_message)
    
    try:
        user_uuid = str(uuid.uuid4())
        code = generate_code()
        cursor.execute("INSERT INTO users (gmail, username, password, uuid, active, code) VALUES (?, ?, ?, ?, ?, ?)", (email, username, hash_password, user_uuid, '0', code))
        conn.commit()
        username=email
        username = username.replace(" ", "")
        bdcontent = "<h2>Verify Your Account password</h2><p>your verification code are given below</p><div style=\"background-color: orange; color: black; font-size: 14px; padding: 10px; border-radius: 5px; font-family: Arial, sans-serif;\">"+code+"</div><p>If you did not request this, please ignore this email.</p>"
        mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
        payload = {"email": username,
                    "sender":"IHA089 Labs ::: RateLimitLab",
                    "subject":"RateLimitLab::Verify Your Accout",
                    "bodycontent":bdcontent
                }
        try:
            k = requests.post(mail_server, json = payload)
        except:
            return jsonify({"error": "Mail server is not responding"}), 500

        return render_template('confirm.html', username=email, password=password)
    except sqlite3.Error:
        error_message = "Something went wrong. Please try again later."
        return render_template('join.html', error=error_message)
    finally:
        conn.close()
    
@RateLimit.route('/reset', methods=['GET'])
def reset():
    token = request.args.get('token')
    if not token:
        flash("Token is missing.")
        return redirect(url_for('home'))
    query = "SELECT gmail FROM token_info where token = ?"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, (token,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return render_template('reset-password.html', token=token)
    else:
        flash("Invalid token. Please try again.")
        return redirect(url_for('home'))
    
@RateLimit.route('/forgot', methods=['POST'])
def forgot():
    try:
        data = request.get_json()
        
        if 'username' in data:
            uname = data['username']                

            conn = get_db_connection()
            cursor = conn.cursor()
            query = "SELECT 1 FROM users WHERE gmail = ?"
            cursor.execute(query, (uname,))
            result = cursor.fetchone()
            conn.close()
            if result is not None:
                token = secrets.token_hex(32)
                conn = get_db_connection()
                cursor = conn.cursor()
                query = "SELECT 1 FROM token_info WHERE gmail = ?"
                cursor.execute(query, (uname, ))
                result = cursor.fetchone()
                
                if result is not None:
                    current_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
                    query = "UPDATE token_info SET token = ?, timestamp = ? WHERE gmail = ?"
                    cursor.execute(query, (token, current_timestamp, uname, ))
                    conn.commit()
                else:
                    query = f"INSERT INTO token_info(gmail, token) VALUES ('{uname}', '{token}')".format(uname, token)
                    cursor.execute(query)
                    conn.commit()
                conn.close()
                username = uname.replace(" ","")
                cmplt_url = "https://iha089-labs.in/reset?token="+token
                bdcontent = "<h2>Reset Your Account password</h2><p>Click the button below to reset your account password on Improper Access Control Lab</p><a href=\""+cmplt_url+"\">Verify Your Account</a><p>If you did not request this, please ignore this email.</p>"
                mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
                payload = {"email": username,
                            "sender":"IHA089 Labs ::: RateLimitLab",
                            "subject":"RateLimitLab::Click bellow link to reset your password",
                            "bodycontent":bdcontent
                    }
                try:
                    k = requests.post(mail_server, json = payload)
                except:
                    return jsonify({"error": "Mail server is not responding"}), 500  
            else:
                pass

            return jsonify({"message": "Reset link sent on your mail"}), 200
        else:
            return jsonify({"error": "Username is required"}), 400
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    
@RateLimit.route('/dashboard')
@RateLimit.route("/dashboard.html")
@login_required
def dashboard():
    if not check_cookies():
        session.clear()
    if 'user' not in session:
        return redirect(url_for('login_html'))
    admin_list=['admin', 'administrator']
    if session.get('user') in admin_list:
        return render_template('admin-dashboard.html', user=session.get('user'))

    return render_template('dashboard.html', user=session.get('user'))

@RateLimit.route('/logout.html')
def logout():
    session.clear() 
    response = make_response(redirect(url_for('login_html')))
    response.set_cookie("uuid", "", httponly=True, samesite="Strict") 
    response.set_cookie("jwt_token", "", httponly=True, samesite="Strict")
    return response

@RateLimit.route('/profile')
@RateLimit.route('/profile.html')
@login_required
def profile():
    if not check_cookies():
        session.clear()
    if 'user' not in session:
        return redirect(url_for('login_html'))
    return render_template('profile.html', user=session.get('user'))

@RateLimit.route('/reset_password', methods=['POST'])
def reset_password():
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    token = request.form.get('token')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    expected_token = hashlib.md5(f"{user['id']}2024".encode()).hexdigest()
    if token == expected_token:
        hash_password = hashlib.md5(new_password.encode()).hexdigest()
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hash_password, user['id']))
        conn.commit()
        conn.close()
        return jsonify({"message": "Password updated successfully!"})
    
    conn.close()
    return jsonify({"error": "Invalid token"}), 400

@RateLimit.after_request
def add_cache_control_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


RateLimit.run("127.0.0.1", 3434)
