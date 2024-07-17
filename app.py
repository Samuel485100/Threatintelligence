from flask import Flask, render_template, request, redirect, url_for, session
from threat_data import get_threat_data, get_pulse_data, process_threat_data
from werkzeug.security import generate_password_hash, check_password_hash
import json
import random
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = 'your secret key'

# In-memory storage for registered users
users = {}

def send_otp(email, otp):
    # Email settings
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'sender_email_id'
    smtp_password = "sender_email_id_password"

    # Create the message
    msg = MIMEText(f'Your OTP is: {otp}')
    msg['Subject'] = 'OTP for Login'
    msg['From'] = smtp_username
    msg['To'] = email

    # Send the email
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_username, smtp_password)
    server.send_message(msg)
    server.quit()

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        # Store the hashed password for security
        users[username] = {
            'password': generate_password_hash(password),
            'email': email
        }
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            # Generate and send OTP
            otp = random.randint(100000, 999999)
            session['otp'] = otp
            session['username'] = username
            send_otp(user['email'], otp)
            return redirect(url_for('verify_otp'))
    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = int(request.form['otp'])
        if 'otp' in session and session['otp'] == user_otp:
            return redirect(url_for('home'))
    return render_template('verify_otp.html')

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    ip_addresses = get_threat_data()
    data_json = json.dumps(ip_addresses)
    return render_template('index.html', data=data_json)

@app.route('/pie')
def pie():
    # Execute the threat_data.py script and get the threat percentages
    threat_percentages = process_threat_data(get_pulse_data())

    # Render the pie.html template and pass the threat percentages to it
    return render_template('pie.html', threat_percentages=threat_percentages)

@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    # Redirect to the welcome page
    return redirect(url_for('welcome'))

if __name__ == '__main__':
    app.run(debug=True)
