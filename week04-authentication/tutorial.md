# Week 4 Tutorial: Multi-Factor Authentication Systems

**Estimated Time**: 4-5 hours  
**Prerequisites**: Week 3 completed, understanding of PKI and digital certificates

## 🎯 Tutorial Goals

By the end of this tutorial, you will have:
1. **Part 1** (60 min): Implemented TOTP-based two-factor authentication
2. **Part 2** (45 min): Built SMS/Email verification systems  
3. **Part 3** (60 min): Created secure session management
4. **Part 4** (90 min): Implemented OAuth 2.0 authentication flows
5. **Part 5** (45 min): Built risk-based authentication

### 📊 Progress Tracking
Complete each module and run its checkpoint before proceeding:
- [ ] Part 1: TOTP Two-Factor Authentication ✅ Checkpoint 1
- [ ] Part 2: SMS/Email Verification ✅ Checkpoint 2
- [ ] Part 3: Secure Session Management ✅ Checkpoint 3
- [ ] Part 4: OAuth 2.0 Implementation ✅ Checkpoint 4
- [ ] Part 5: Risk-Based Authentication ✅ Checkpoint 5

## 🔧 Setup Check

Before we begin, verify your environment:

```bash
# Check Python version
python --version  # Should be 3.11+

# Install required packages
pip install pyotp qrcode[pil] flask flask-session requests bcrypt

# Check installations
python -c "import pyotp; print('✅ TOTP support ready')"
python -c "import qrcode; print('✅ QR code support ready')"

# Create working directory
mkdir week4-auth
cd week4-auth
```

---

## 📘 Part 1: TOTP Two-Factor Authentication (60 minutes)

**Learning Objective**: Implement Time-based One-Time Password (TOTP) authentication

**What you'll build**: Complete 2FA system with QR code setup

### Step 1: Understanding TOTP

Create `totp_authentication.py`:

```python
import pyotp
import qrcode
import io
import base64
import time
import secrets
from datetime import datetime, timedelta
import json
import hashlib
import bcrypt

class TOTPAuthenticator:
    """Time-based One-Time Password authentication system"""
    
    def __init__(self, issuer_name="CSCI347 Auth System"):
        self.issuer_name = issuer_name
        self.users_db = {}  # In production, use proper database
        self.backup_codes = {}  # Store backup codes securely
    
    def generate_secret_key(self):
        """Generate a secure random secret key for TOTP"""
        # Generate 160-bit (20 byte) secret, base32 encoded
        secret = pyotp.random_base32()
        return secret
    
    def create_user_account(self, username, password, email=None):
        """
        Create new user account with TOTP setup
        
        Args:
            username (str): Username
            password (str): Plain text password (will be hashed)
            email (str): User email for account recovery
            
        Returns:
            dict: User account information including TOTP secret
        """
        if username in self.users_db:
            raise ValueError("Username already exists")
        
        # Hash password securely
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Generate TOTP secret
        totp_secret = self.generate_secret_key()
        
        # Generate backup codes
        backup_codes = self._generate_backup_codes()
        
        # Store user information
        user_info = {
            'username': username,
            'password_hash': password_hash,
            'email': email,
            'totp_secret': totp_secret,
            'totp_enabled': False,  # User must verify setup first
            'backup_codes': [bcrypt.hashpw(code.encode(), bcrypt.gensalt()) for code in backup_codes],
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None
        }
        
        self.users_db[username] = user_info
        print(f"✅ User account created: {username}")
        
        return {
            'username': username,
            'totp_secret': totp_secret,
            'backup_codes': backup_codes,  # Return plain text codes for user to save
            'setup_required': True
        }
    
    def generate_qr_code(self, username):
        """
        Generate QR code for TOTP setup
        
        Args:
            username (str): Username
            
        Returns:
            str: Base64 encoded QR code image
        """
        if username not in self.users_db:
            raise ValueError("User not found")
        
        user = self.users_db[username]
        
        # Create TOTP URI for authenticator apps
        totp_uri = pyotp.totp.TOTP(user['totp_secret']).provisioning_uri(
            name=username,
            issuer_name=self.issuer_name
        )
        
        print(f"🔗 TOTP URI: {totp_uri}")
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Convert to image
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for display
        buffer = io.BytesIO()
        qr_image.save(buffer, format='PNG')
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        print(f"✅ QR code generated for {username}")
        return qr_base64
    
    def verify_totp_setup(self, username, totp_code):
        """
        Verify TOTP setup with user-provided code
        
        Args:
            username (str): Username
            totp_code (str): 6-digit TOTP code from authenticator app
            
        Returns:
            bool: True if verification successful
        """
        if username not in self.users_db:
            raise ValueError("User not found")
        
        user = self.users_db[username]
        
        # Create TOTP object
        totp = pyotp.TOTP(user['totp_secret'])
        
        # Verify code (allow for clock skew)
        if totp.verify(totp_code, valid_window=1):
            # Enable TOTP for this user
            user['totp_enabled'] = True
            print(f"✅ TOTP setup verified and enabled for {username}")
            return True
        else:
            print(f"❌ Invalid TOTP code for {username}")
            return False
    
    def authenticate_user(self, username, password, totp_code=None, backup_code=None):
        """
        Authenticate user with password and second factor
        
        Args:
            username (str): Username
            password (str): Password
            totp_code (str): TOTP code from authenticator app
            backup_code (str): Backup code if TOTP unavailable
            
        Returns:
            dict: Authentication result
        """
        if username not in self.users_db:
            return {'success': False, 'message': 'Invalid credentials'}
        
        user = self.users_db[username]
        
        # Check if account is locked
        if user.get('locked_until'):
            lock_time = datetime.fromisoformat(user['locked_until'])
            if datetime.now() < lock_time:
                return {'success': False, 'message': 'Account temporarily locked'}
        
        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            self._handle_failed_login(username)
            return {'success': False, 'message': 'Invalid credentials'}
        
        # If TOTP is enabled, verify second factor
        if user['totp_enabled']:
            second_factor_valid = False
            
            if totp_code:
                # Verify TOTP code
                totp = pyotp.TOTP(user['totp_secret'])
                if totp.verify(totp_code, valid_window=1):
                    second_factor_valid = True
                    print("✅ TOTP code verified")
                else:
                    print("❌ Invalid TOTP code")
            
            elif backup_code:
                # Verify backup code
                if self._verify_backup_code(username, backup_code):
                    second_factor_valid = True
                    print("✅ Backup code verified and consumed")
                else:
                    print("❌ Invalid backup code")
            
            if not second_factor_valid:
                self._handle_failed_login(username)
                return {
                    'success': False, 
                    'message': 'Invalid second factor',
                    'requires_2fa': True
                }
        
        # Successful authentication
        user['last_login'] = datetime.now().isoformat()
        user['failed_attempts'] = 0
        user['locked_until'] = None
        
        print(f"✅ User {username} authenticated successfully")
        return {
            'success': True,
            'message': 'Authentication successful',
            'username': username,
            'last_login': user['last_login']
        }
    
    def _generate_backup_codes(self, count=10):
        """Generate backup codes for account recovery"""
        codes = []
        for _ in range(count):
            # Generate 8-digit backup codes
            code = ''.join([str(secrets.randbelow(10)) for _ in range(8)])
            codes.append(code)
        return codes
    
    def _verify_backup_code(self, username, backup_code):
        """Verify and consume backup code"""
        user = self.users_db[username]
        
        for i, hashed_code in enumerate(user['backup_codes']):
            if bcrypt.checkpw(backup_code.encode(), hashed_code):
                # Remove used backup code
                user['backup_codes'].pop(i)
                return True
        return False
    
    def _handle_failed_login(self, username):
        """Handle failed login attempt with rate limiting"""
        user = self.users_db[username]
        user['failed_attempts'] = user.get('failed_attempts', 0) + 1
        
        # Lock account after 5 failed attempts for 15 minutes
        if user['failed_attempts'] >= 5:
            lock_time = datetime.now() + timedelta(minutes=15)
            user['locked_until'] = lock_time.isoformat()
            print(f"⚠️  Account {username} locked until {lock_time}")
    
    def get_user_status(self, username):
        """Get user account status information"""
        if username not in self.users_db:
            return None
        
        user = self.users_db[username]
        return {
            'username': username,
            'totp_enabled': user['totp_enabled'],
            'backup_codes_remaining': len(user['backup_codes']),
            'last_login': user.get('last_login'),
            'failed_attempts': user.get('failed_attempts', 0),
            'is_locked': bool(user.get('locked_until'))
        }

def demo_totp_authentication():
    """Demonstrate TOTP authentication system"""
    print("🔐 TOTP Authentication System Demo")
    print("="*50)
    
    # Create authenticator
    auth = TOTPAuthenticator("CSCI347 Demo")
    
    # Step 1: Create user account
    print("\n📋 Step 1: Creating user account")
    user_info = auth.create_user_account(
        username="alice",
        password="secure_password_123!",
        email="alice@csci347lab.com"
    )
    
    print(f"   Username: {user_info['username']}")
    print(f"   TOTP Secret: {user_info['totp_secret']}")
    print(f"   Backup codes: {user_info['backup_codes'][:3]}... (showing first 3)")
    
    # Step 2: Generate QR code for setup
    print(f"\n📋 Step 2: Generating QR code for authenticator app")
    qr_code = auth.generate_qr_code("alice")
    print(f"   QR code generated (base64): {qr_code[:50]}...")
    
    # Save QR code to file for testing
    import base64
    with open("totp_qr_code.png", "wb") as f:
        f.write(base64.b64decode(qr_code))
    print("   QR code saved as 'totp_qr_code.png'")
    print("   📱 Scan this with Google Authenticator or Authy")
    
    # Step 3: Simulate TOTP setup verification
    print(f"\n📋 Step 3: Simulating TOTP verification")
    
    # Generate current TOTP code for demonstration
    totp = pyotp.TOTP(user_info['totp_secret'])
    current_code = totp.now()
    print(f"   Current TOTP code (for testing): {current_code}")
    
    # Verify setup
    setup_success = auth.verify_totp_setup("alice", current_code)
    print(f"   Setup verification: {'✅ Success' if setup_success else '❌ Failed'}")
    
    # Step 4: Test authentication
    print(f"\n📋 Step 4: Testing authentication")
    
    # Test with correct credentials and TOTP
    auth_result = auth.authenticate_user(
        username="alice",
        password="secure_password_123!",
        totp_code=current_code
    )
    print(f"   Correct credentials: {auth_result}")
    
    # Test with wrong TOTP code
    auth_result = auth.authenticate_user(
        username="alice", 
        password="secure_password_123!",
        totp_code="123456"
    )
    print(f"   Wrong TOTP code: {auth_result}")
    
    # Test with backup code
    backup_code = user_info['backup_codes'][0]
    auth_result = auth.authenticate_user(
        username="alice",
        password="secure_password_123!",
        backup_code=backup_code
    )
    print(f"   Backup code authentication: {auth_result}")
    
    # Step 5: Check user status
    print(f"\n📋 Step 5: User account status")
    status = auth.get_user_status("alice")
    print(f"   Status: {status}")
    
    return auth

def demo_totp_security_features():
    """Demonstrate TOTP security features"""
    print(f"\n🔒 TOTP Security Features Demo")
    print("="*50)
    
    auth = TOTPAuthenticator()
    
    # Create test user
    user_info = auth.create_user_account("bob", "password123")
    totp = pyotp.TOTP(user_info['totp_secret'])
    auth.verify_totp_setup("bob", totp.now())
    
    # Demonstrate time window
    print("🕒 Time-based code generation:")
    for i in range(3):
        current_time = int(time.time()) + (i * 30)  # 30-second intervals
        code_at_time = totp.at(current_time)
        print(f"   Time +{i*30}s: {code_at_time}")
    
    # Demonstrate failed attempt handling
    print(f"\n🚨 Failed attempt handling:")
    for i in range(6):
        result = auth.authenticate_user("bob", "wrong_password")
        print(f"   Attempt {i+1}: {result['message']}")
        if 'locked' in result['message']:
            break
    
    # Show account status
    status = auth.get_user_status("bob")
    print(f"   Final status: Locked = {status['is_locked']}")
    
    print(f"\n💡 TOTP Security Benefits:")
    print("   • Time-based codes expire every 30 seconds")
    print("   • Codes are mathematically derived from shared secret")
    print("   • Works offline (no network required)")
    print("   • Backup codes provide recovery mechanism")
    print("   • Rate limiting prevents brute force attacks")

if __name__ == "__main__":
    auth_system = demo_totp_authentication()
    demo_totp_security_features()
```

### Step 2: TOTP Integration with Web Interface

Create a simple Flask web interface (`totp_web_demo.py`):

```python
from flask import Flask, request, render_template_string, session, redirect, url_for, jsonify
import secrets
from totp_authentication import TOTPAuthenticator

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Global authenticator instance
auth_system = TOTPAuthenticator("CSCI347 Web Demo")

# HTML Templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>CSCI347 - TOTP Authentication</title></head>
<body>
    <h1>🔐 TOTP Authentication Demo</h1>
    
    {% if message %}
        <div style="color: {% if 'success' in message.lower() %}green{% else %}red{% endif %}; margin: 10px 0;">
            {{ message }}
        </div>
    {% endif %}
    
    <h2>Login</h2>
    <form method="POST" action="/login">
        <p>
            <label>Username:</label><br>
            <input type="text" name="username" required>
        </p>
        <p>
            <label>Password:</label><br>
            <input type="password" name="password" required>
        </p>
        {% if requires_2fa %}
        <p>
            <label>TOTP Code (6 digits):</label><br>
            <input type="text" name="totp_code" maxlength="6" placeholder="123456">
        </p>
        <p>OR</p>
        <p>
            <label>Backup Code (8 digits):</label><br>
            <input type="text" name="backup_code" maxlength="8" placeholder="12345678">
        </p>
        {% endif %}
        <p>
            <input type="submit" value="Login">
        </p>
    </form>
    
    <h2>Create Account</h2>
    <form method="POST" action="/register">
        <p>
            <label>Username:</label><br>
            <input type="text" name="username" required>
        </p>
        <p>
            <label>Password:</label><br>
            <input type="password" name="password" required>
        </p>
        <p>
            <label>Email:</label><br>
            <input type="email" name="email">
        </p>
        <p>
            <input type="submit" value="Register">
        </p>
    </form>
</body>
</html>
"""

SETUP_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Setup TOTP</title></head>
<body>
    <h1>🔐 Setup Two-Factor Authentication</h1>
    
    <h2>Step 1: Scan QR Code</h2>
    <p>Use Google Authenticator, Authy, or similar app:</p>
    <img src="data:image/png;base64,{{ qr_code }}" alt="TOTP QR Code" style="border: 1px solid #ccc;">
    
    <h2>Step 2: Enter Verification Code</h2>
    <form method="POST" action="/verify_setup">
        <p>
            <label>6-digit code from your authenticator app:</label><br>
            <input type="text" name="totp_code" maxlength="6" required>
        </p>
        <p>
            <input type="submit" value="Verify & Enable 2FA">
        </p>
    </form>
    
    <h2>Backup Codes</h2>
    <p><strong>Save these backup codes in a secure location:</strong></p>
    <ul>
    {% for code in backup_codes %}
        <li><code>{{ code }}</code></li>
    {% endfor %}
    </ul>
    <p><em>Each backup code can only be used once.</em></p>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
    <h1>🎯 Welcome, {{ username }}!</h1>
    
    <h2>Account Status</h2>
    <ul>
        <li><strong>TOTP Enabled:</strong> {{ status.totp_enabled }}</li>
        <li><strong>Backup Codes Remaining:</strong> {{ status.backup_codes_remaining }}</li>
        <li><strong>Last Login:</strong> {{ status.last_login or 'Never' }}</li>
        <li><strong>Failed Attempts:</strong> {{ status.failed_attempts }}</li>
    </ul>
    
    <p><a href="/logout">Logout</a></p>
    
    <h2>Security Information</h2>
    <p>✅ Your account is protected with two-factor authentication!</p>
    <ul>
        <li>TOTP codes change every 30 seconds</li>
        <li>Backup codes provide account recovery</li>
        <li>Failed login attempts are tracked and rate-limited</li>
    </ul>
</body>
</html>
"""

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    email = request.form.get('email', '')
    
    try:
        user_info = auth_system.create_user_account(username, password, email)
        session['pending_username'] = username
        session['backup_codes'] = user_info['backup_codes']
        return redirect(url_for('setup_totp'))
    except ValueError as e:
        return render_template_string(LOGIN_TEMPLATE, message=str(e))

@app.route('/setup_totp')
def setup_totp():
    username = session.get('pending_username')
    if not username:
        return redirect(url_for('index'))
    
    qr_code = auth_system.generate_qr_code(username)
    backup_codes = session.get('backup_codes', [])
    
    return render_template_string(SETUP_TEMPLATE, 
                                qr_code=qr_code, 
                                backup_codes=backup_codes)

@app.route('/verify_setup', methods=['POST'])
def verify_setup():
    username = session.get('pending_username')
    totp_code = request.form['totp_code']
    
    if auth_system.verify_totp_setup(username, totp_code):
        session['username'] = username
        session.pop('pending_username', None)
        session.pop('backup_codes', None)
        return redirect(url_for('dashboard'))
    else:
        return render_template_string(SETUP_TEMPLATE, 
                                    message="Invalid code. Please try again.")

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    totp_code = request.form.get('totp_code')
    backup_code = request.form.get('backup_code')
    
    result = auth_system.authenticate_user(username, password, totp_code, backup_code)
    
    if result['success']:
        session['username'] = username
        return redirect(url_for('dashboard'))
    else:
        requires_2fa = result.get('requires_2fa', False)
        return render_template_string(LOGIN_TEMPLATE, 
                                    message=result['message'],
                                    requires_2fa=requires_2fa)

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        return redirect(url_for('index'))
    
    status = auth_system.get_user_status(username)
    return render_template_string(DASHBOARD_TEMPLATE, 
                                username=username, 
                                status=status)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    print("🌐 Starting TOTP Web Demo")
    print("Visit http://localhost:5000 to test TOTP authentication")
    print("Use Google Authenticator or Authy to scan QR codes")
    app.run(debug=True, host='0.0.0.0')
```

**Run the web demo:**
```bash
python totp_web_demo.py
```

### ✅ Checkpoint 1: TOTP Authentication

Test your TOTP implementation:
1. Can you generate QR codes for authenticator apps?
2. Do you understand time-based code generation?
3. Can you implement backup codes for account recovery?

---

## 📘 Part 2: SMS/Email Verification (45 minutes)

**Learning Objective**: Implement verification codes via SMS and email

**What you'll build**: Multi-channel verification system

Create `sms_email_verification.py`:

```python
import secrets
import smtplib
import time
from datetime import datetime, timedelta
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import json
import hashlib

class MultiChannelVerifier:
    """SMS and Email verification system"""
    
    def __init__(self, smtp_server=None, smtp_port=587, 
                 smtp_username=None, smtp_password=None,
                 sms_provider=None):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.sms_provider = sms_provider
        
        # In-memory store for verification codes (use database in production)
        self.verification_codes = {}
        self.rate_limits = {}  # Track rate limiting per phone/email
        
        # Configuration
        self.code_length = 6
        self.code_validity_minutes = 10
        self.max_attempts = 3
        self.rate_limit_minutes = 1  # Min time between requests
        self.daily_limit = 10  # Max codes per phone/email per day
    
    def generate_verification_code(self):
        """Generate secure 6-digit verification code"""
        return ''.join([str(secrets.randbelow(10)) for _ in range(self.code_length)])
    
    def send_email_verification(self, email, purpose="account verification"):
        """
        Send verification code via email
        
        Args:
            email (str): Email address
            purpose (str): Purpose of verification
            
        Returns:
            dict: Result with code_id for verification
        """
        if not self._check_rate_limit(email):
            return {
                'success': False,
                'message': 'Rate limit exceeded. Please wait before requesting another code.'
            }
        
        # Generate verification code
        code = self.generate_verification_code()
        code_id = hashlib.sha256(f"{email}{code}{time.time()}".encode()).hexdigest()[:16]
        
        # Store verification code
        self.verification_codes[code_id] = {
            'code': code,
            'email': email,
            'purpose': purpose,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(minutes=self.code_validity_minutes),
            'attempts': 0,
            'type': 'email'
        }
        
        # Send email
        success = self._send_email(email, code, purpose)
        
        if success:
            self._update_rate_limit(email)
            print(f"✅ Verification code sent to {email}")
            return {
                'success': True,
                'code_id': code_id,
                'expires_in_minutes': self.code_validity_minutes
            }
        else:
            # Remove code if sending failed
            del self.verification_codes[code_id]
            return {
                'success': False,
                'message': 'Failed to send email verification code'
            }
    
    def send_sms_verification(self, phone_number, purpose="account verification"):
        """
        Send verification code via SMS
        
        Args:
            phone_number (str): Phone number (E.164 format recommended)
            purpose (str): Purpose of verification
            
        Returns:
            dict: Result with code_id for verification
        """
        # Normalize phone number
        phone_number = self._normalize_phone_number(phone_number)
        
        if not self._check_rate_limit(phone_number):
            return {
                'success': False,
                'message': 'Rate limit exceeded. Please wait before requesting another code.'
            }
        
        # Generate verification code
        code = self.generate_verification_code()
        code_id = hashlib.sha256(f"{phone_number}{code}{time.time()}".encode()).hexdigest()[:16]
        
        # Store verification code
        self.verification_codes[code_id] = {
            'code': code,
            'phone': phone_number,
            'purpose': purpose,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(minutes=self.code_validity_minutes),
            'attempts': 0,
            'type': 'sms'
        }
        
        # Send SMS
        success = self._send_sms(phone_number, code, purpose)
        
        if success:
            self._update_rate_limit(phone_number)
            print(f"✅ Verification code sent to {phone_number}")
            return {
                'success': True,
                'code_id': code_id,
                'expires_in_minutes': self.code_validity_minutes
            }
        else:
            # Remove code if sending failed
            del self.verification_codes[code_id]
            return {
                'success': False,
                'message': 'Failed to send SMS verification code'
            }
    
    def verify_code(self, code_id, submitted_code):
        """
        Verify submitted code
        
        Args:
            code_id (str): Code ID from send request
            submitted_code (str): Code submitted by user
            
        Returns:
            dict: Verification result
        """
        if code_id not in self.verification_codes:
            return {
                'success': False,
                'message': 'Invalid or expired verification code'
            }
        
        code_info = self.verification_codes[code_id]
        
        # Check if code has expired
        if datetime.now() > code_info['expires_at']:
            del self.verification_codes[code_id]
            return {
                'success': False,
                'message': 'Verification code has expired'
            }
        
        # Check attempt limit
        if code_info['attempts'] >= self.max_attempts:
            del self.verification_codes[code_id]
            return {
                'success': False,
                'message': 'Too many failed attempts. Please request a new code.'
            }
        
        # Verify code
        code_info['attempts'] += 1
        
        if submitted_code == code_info['code']:
            # Successful verification
            verified_info = {
                'success': True,
                'message': 'Verification successful',
                'purpose': code_info['purpose'],
                'verified_at': datetime.now().isoformat()
            }
            
            if code_info['type'] == 'email':
                verified_info['email'] = code_info['email']
            else:
                verified_info['phone'] = code_info['phone']
            
            # Clean up code
            del self.verification_codes[code_id]
            
            print(f"✅ Code verified successfully for {code_info['purpose']}")
            return verified_info
        else:
            return {
                'success': False,
                'message': f'Invalid code. {self.max_attempts - code_info["attempts"]} attempts remaining.'
            }
    
    def _send_email(self, email, code, purpose):
        """Send verification email (mock implementation)"""
        # Mock implementation - in production, use proper SMTP
        if self.smtp_server and self.smtp_username:
            try:
                # Real email sending logic would go here
                msg = MimeMultipart()
                msg['From'] = self.smtp_username
                msg['To'] = email
                msg['Subject'] = f"Verification Code - {purpose.title()}"
                
                body = f"""
                Your verification code is: {code}
                
                This code will expire in {self.code_validity_minutes} minutes.
                Do not share this code with anyone.
                
                Purpose: {purpose}
                Requested at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                
                If you did not request this code, please ignore this email.
                """
                
                msg.attach(MimeText(body, 'plain'))
                
                # This would actually send the email in production
                print(f"📧 Mock email to {email}: Your code is {code}")
                return True
                
            except Exception as e:
                print(f"❌ Email sending failed: {e}")
                return False
        else:
            # Mock mode
            print(f"📧 Mock email to {email}: Your verification code is {code}")
            return True
    
    def _send_sms(self, phone, code, purpose):
        """Send SMS verification (mock implementation)"""
        # Mock implementation - in production, use Twilio, AWS SNS, etc.
        if self.sms_provider:
            try:
                # Real SMS sending logic would go here
                message = f"Your verification code is {code}. Valid for {self.code_validity_minutes} minutes. Purpose: {purpose}"
                print(f"📱 Mock SMS to {phone}: {message}")
                return True
            except Exception as e:
                print(f"❌ SMS sending failed: {e}")
                return False
        else:
            # Mock mode
            print(f"📱 Mock SMS to {phone}: Your verification code is {code}")
            return True
    
    def _normalize_phone_number(self, phone):
        """Normalize phone number format"""
        # Remove all non-digit characters
        digits = ''.join(filter(str.isdigit, phone))
        
        # Add +1 for US numbers if not present
        if len(digits) == 10:
            digits = '1' + digits
        elif len(digits) == 11 and digits[0] == '1':
            pass
        
        return '+' + digits
    
    def _check_rate_limit(self, contact):
        """Check if contact can receive another code"""
        now = datetime.now()
        
        if contact not in self.rate_limits:
            self.rate_limits[contact] = {'last_sent': None, 'daily_count': 0, 'daily_reset': now.date()}
        
        limit_info = self.rate_limits[contact]
        
        # Reset daily counter if new day
        if limit_info['daily_reset'] < now.date():
            limit_info['daily_count'] = 0
            limit_info['daily_reset'] = now.date()
        
        # Check daily limit
        if limit_info['daily_count'] >= self.daily_limit:
            print(f"⚠️  Daily limit exceeded for {contact}")
            return False
        
        # Check rate limit
        if limit_info['last_sent']:
            time_since_last = now - limit_info['last_sent']
            if time_since_last.total_seconds() < (self.rate_limit_minutes * 60):
                print(f"⚠️  Rate limit active for {contact}")
                return False
        
        return True
    
    def _update_rate_limit(self, contact):
        """Update rate limit tracking"""
        now = datetime.now()
        
        if contact not in self.rate_limits:
            self.rate_limits[contact] = {'last_sent': None, 'daily_count': 0, 'daily_reset': now.date()}
        
        self.rate_limits[contact]['last_sent'] = now
        self.rate_limits[contact]['daily_count'] += 1
    
    def get_verification_stats(self):
        """Get verification system statistics"""
        active_codes = len(self.verification_codes)
        email_codes = sum(1 for c in self.verification_codes.values() if c['type'] == 'email')
        sms_codes = sum(1 for c in self.verification_codes.values() if c['type'] == 'sms')
        
        return {
            'active_codes': active_codes,
            'email_codes': email_codes,
            'sms_codes': sms_codes,
            'rate_limited_contacts': len(self.rate_limits)
        }

def demo_multi_channel_verification():
    """Demonstrate multi-channel verification system"""
    print("📱 Multi-Channel Verification Demo")
    print("="*50)
    
    # Create verifier
    verifier = MultiChannelVerifier()
    
    # Demo 1: Email verification
    print("\n📋 Demo 1: Email Verification")
    email_result = verifier.send_email_verification(
        "alice@csci347lab.com",
        "account registration"
    )
    
    print(f"   Send result: {email_result}")
    
    if email_result['success']:
        code_id = email_result['code_id']
        
        # Get the actual code (normally user would enter from email)
        actual_code = None
        for stored_code_id, code_info in verifier.verification_codes.items():
            if stored_code_id == code_id:
                actual_code = code_info['code']
                break
        
        print(f"   Generated code (for testing): {actual_code}")
        
        # Test wrong code
        wrong_result = verifier.verify_code(code_id, "000000")
        print(f"   Wrong code result: {wrong_result}")
        
        # Test correct code
        correct_result = verifier.verify_code(code_id, actual_code)
        print(f"   Correct code result: {correct_result}")
    
    # Demo 2: SMS verification
    print(f"\n📋 Demo 2: SMS Verification")
    sms_result = verifier.send_sms_verification(
        "+1-555-123-4567",
        "password reset"
    )
    
    print(f"   Send result: {sms_result}")
    
    if sms_result['success']:
        code_id = sms_result['code_id']
        
        # Get the actual code
        actual_code = None
        for stored_code_id, code_info in verifier.verification_codes.items():
            if stored_code_id == code_id:
                actual_code = code_info['code']
                break
        
        print(f"   Generated code (for testing): {actual_code}")
        
        # Verify code
        verify_result = verifier.verify_code(code_id, actual_code)
        print(f"   Verification result: {verify_result}")
    
    # Demo 3: Rate limiting
    print(f"\n📋 Demo 3: Rate Limiting")
    
    # Try to send multiple codes quickly
    for i in range(3):
        result = verifier.send_email_verification(
            "spam@example.com",
            f"test {i}"
        )
        print(f"   Attempt {i+1}: {'✅ Success' if result['success'] else '❌ ' + result['message']}")
        
        if i == 0:
            # Wait a bit for second attempt
            time.sleep(0.1)
    
    # Demo 4: System statistics
    print(f"\n📋 Demo 4: System Statistics")
    stats = verifier.get_verification_stats()
    print(f"   Statistics: {stats}")

def demo_verification_security():
    """Demonstrate security features of verification system"""
    print(f"\n🔒 Verification Security Features")
    print("="*50)
    
    security_features = [
        "✅ Rate limiting prevents abuse (1 min between requests)",
        "✅ Daily limits prevent excessive usage (10 codes per day)",
        "✅ Codes expire after 10 minutes",
        "✅ Limited attempts (3 tries per code)",
        "✅ Codes are cryptographically secure (secrets module)",
        "✅ Code IDs are hashed to prevent enumeration",
        "✅ Phone numbers are normalized for consistency",
        "✅ Proper cleanup of expired/used codes"
    ]
    
    for feature in security_features:
        print(f"   {feature}")
    
    print(f"\n💡 Best Practices:")
    print("   • Use HTTPS for all verification endpoints")
    print("   • Log verification attempts for monitoring")
    print("   • Implement CAPTCHA for high-volume users")
    print("   • Use dedicated SMS/email services (Twilio, SES)")
    print("   • Monitor for abuse patterns")
    print("   • Provide clear error messages without revealing internals")

if __name__ == "__main__":
    demo_multi_channel_verification()
    demo_verification_security()
```

### ✅ Checkpoint 2: Multi-Channel Verification

Verify your verification system:
1. Can you send codes via both SMS and email?
2. Do you understand rate limiting and abuse prevention?
3. Can you implement proper code expiration?

---

## 📘 Part 3: Secure Session Management (60 minutes)

**Learning Objective**: Implement secure session handling for authenticated users

**What you'll build**: Session management system with security controls

Create `secure_session_management.py`:

```python
import secrets
import jwt
import time
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import json

@dataclass
class SessionInfo:
    """Session information data class"""
    session_id: str
    user_id: str
    username: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    ip_address: str
    user_agent: str
    is_authenticated: bool = True
    mfa_verified: bool = False
    permissions: list = None
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []

class SecureSessionManager:
    """Secure session management with JWT and server-side storage"""
    
    def __init__(self, secret_key=None, session_timeout_hours=24, 
                 max_sessions_per_user=3, require_mfa=True):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.session_timeout_hours = session_timeout_hours
        self.max_sessions_per_user = max_sessions_per_user
        self.require_mfa = require_mfa
        
        # Server-side session storage (use Redis or database in production)
        self.sessions = {}
        self.user_sessions = {}  # user_id -> [session_ids]
        
        # Security tracking
        self.failed_sessions = {}  # Track invalid session attempts
        self.session_analytics = {
            'total_created': 0,
            'total_expired': 0,
            'total_revoked': 0,
            'concurrent_peak': 0
        }
    
    def create_session(self, user_id: str, username: str, ip_address: str, 
                      user_agent: str, mfa_verified: bool = False, 
                      permissions: list = None) -> Dict[str, Any]:
        """
        Create new authenticated session
        
        Args:
            user_id (str): Unique user identifier
            username (str): Username
            ip_address (str): Client IP address
            user_agent (str): Client user agent
            mfa_verified (bool): Whether MFA was completed
            permissions (list): User permissions
            
        Returns:
            dict: Session information including JWT token
        """
        # Check MFA requirement
        if self.require_mfa and not mfa_verified:
            return {
                'success': False,
                'message': 'Multi-factor authentication required',
                'requires_mfa': True
            }
        
        # Enforce session limit per user
        if user_id in self.user_sessions:
            if len(self.user_sessions[user_id]) >= self.max_sessions_per_user:
                # Remove oldest session
                oldest_session_id = self.user_sessions[user_id][0]
                self.revoke_session(oldest_session_id)
        
        # Generate secure session ID
        session_id = secrets.token_hex(32)
        
        # Create session info
        now = datetime.utcnow()
        session_info = SessionInfo(
            session_id=session_id,
            user_id=user_id,
            username=username,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(hours=self.session_timeout_hours),
            ip_address=ip_address,
            user_agent=user_agent,
            mfa_verified=mfa_verified,
            permissions=permissions or []
        )
        
        # Store session
        self.sessions[session_id] = session_info
        
        # Track user sessions
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = []
        self.user_sessions[user_id].append(session_id)
        
        # Update analytics
        self.session_analytics['total_created'] += 1
        current_sessions = len(self.sessions)
        if current_sessions > self.session_analytics['concurrent_peak']:
            self.session_analytics['concurrent_peak'] = current_sessions
        
        # Create JWT token
        jwt_payload = {
            'session_id': session_id,
            'user_id': user_id,
            'username': username,
            'iat': int(now.timestamp()),
            'exp': int(session_info.expires_at.timestamp()),
            'ip': ip_address,
            'mfa': mfa_verified
        }
        
        jwt_token = jwt.encode(jwt_payload, self.secret_key, algorithm='HS256')
        
        print(f"✅ Session created for {username} (ID: {session_id[:8]}...)")
        
        return {
            'success': True,
            'session_id': session_id,
            'jwt_token': jwt_token,
            'expires_at': session_info.expires_at.isoformat(),
            'mfa_verified': mfa_verified
        }
    
    def validate_session(self, jwt_token: str, ip_address: str = None, 
                        require_mfa: bool = None) -> Dict[str, Any]:
        """
        Validate session token and return session info
        
        Args:
            jwt_token (str): JWT session token
            ip_address (str): Current client IP (for security checks)
            require_mfa (bool): Override MFA requirement
            
        Returns:
            dict: Validation result with session info
        """
        try:
            # Decode JWT token
            payload = jwt.decode(jwt_token, self.secret_key, algorithms=['HS256'])
            session_id = payload['session_id']
            
            # Check if session exists
            if session_id not in self.sessions:
                self._record_failed_session(ip_address, "Session not found")
                return {'success': False, 'message': 'Invalid session'}
            
            session_info = self.sessions[session_id]
            
            # Check if session has expired
            if datetime.utcnow() > session_info.expires_at:
                self.revoke_session(session_id)
                return {'success': False, 'message': 'Session expired'}
            
            # Security checks
            if ip_address and self._is_ip_suspicious(session_info.ip_address, ip_address):
                # Log suspicious activity but allow (could be VPN, mobile switching)
                print(f"⚠️  IP address changed for session {session_id[:8]}... "
                      f"({session_info.ip_address} -> {ip_address})")
            
            # Check MFA requirement
            if require_mfa is None:
                require_mfa = self.require_mfa
            
            if require_mfa and not session_info.mfa_verified:
                return {
                    'success': False,
                    'message': 'Multi-factor authentication required',
                    'requires_mfa': True
                }
            
            # Update last activity
            session_info.last_activity = datetime.utcnow()
            
            # Return session information
            return {
                'success': True,
                'session_id': session_id,
                'user_id': session_info.user_id,
                'username': session_info.username,
                'mfa_verified': session_info.mfa_verified,
                'permissions': session_info.permissions,
                'last_activity': session_info.last_activity.isoformat(),
                'expires_at': session_info.expires_at.isoformat()
            }
            
        except jwt.ExpiredSignatureError:
            self._record_failed_session(ip_address, "Expired token")
            return {'success': False, 'message': 'Session expired'}
        except jwt.InvalidTokenError:
            self._record_failed_session(ip_address, "Invalid token")
            return {'success': False, 'message': 'Invalid session token'}
    
    def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a specific session
        
        Args:
            session_id (str): Session ID to revoke
            
        Returns:
            bool: True if session was revoked
        """
        if session_id not in self.sessions:
            return False
        
        session_info = self.sessions[session_id]
        user_id = session_info.user_id
        
        # Remove from sessions
        del self.sessions[session_id]
        
        # Remove from user sessions list
        if user_id in self.user_sessions:
            if session_id in self.user_sessions[user_id]:
                self.user_sessions[user_id].remove(session_id)
            
            # Clean up empty user session list
            if not self.user_sessions[user_id]:
                del self.user_sessions[user_id]
        
        # Update analytics
        self.session_analytics['total_revoked'] += 1
        
        print(f"🔒 Session revoked: {session_id[:8]}...")
        return True
    
    def revoke_all_user_sessions(self, user_id: str) -> int:
        """
        Revoke all sessions for a specific user
        
        Args:
            user_id (str): User ID
            
        Returns:
            int: Number of sessions revoked
        """
        if user_id not in self.user_sessions:
            return 0
        
        session_ids = self.user_sessions[user_id].copy()
        revoked_count = 0
        
        for session_id in session_ids:
            if self.revoke_session(session_id):
                revoked_count += 1
        
        print(f"🔒 Revoked {revoked_count} sessions for user {user_id}")
        return revoked_count
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions
        
        Returns:
            int: Number of sessions cleaned up
        """
        now = datetime.utcnow()
        expired_sessions = []
        
        for session_id, session_info in self.sessions.items():
            if now > session_info.expires_at:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.revoke_session(session_id)
            self.session_analytics['total_expired'] += 1
        
        if expired_sessions:
            print(f"🧹 Cleaned up {len(expired_sessions)} expired sessions")
        
        return len(expired_sessions)
    
    def get_user_sessions(self, user_id: str) -> list:
        """Get all active sessions for a user"""
        if user_id not in self.user_sessions:
            return []
        
        user_session_info = []
        for session_id in self.user_sessions[user_id]:
            if session_id in self.sessions:
                session_info = self.sessions[session_id]
                user_session_info.append({
                    'session_id': session_id[:8] + '...',
                    'created_at': session_info.created_at.isoformat(),
                    'last_activity': session_info.last_activity.isoformat(),
                    'expires_at': session_info.expires_at.isoformat(),
                    'ip_address': session_info.ip_address,
                    'user_agent': session_info.user_agent[:50] + '...' if len(session_info.user_agent) > 50 else session_info.user_agent
                })
        
        return user_session_info
    
    def get_session_analytics(self) -> dict:
        """Get session management analytics"""
        self.cleanup_expired_sessions()  # Clean up first
        
        return {
            'active_sessions': len(self.sessions),
            'unique_users': len(self.user_sessions),
            'total_created': self.session_analytics['total_created'],
            'total_expired': self.session_analytics['total_expired'],
            'total_revoked': self.session_analytics['total_revoked'],
            'concurrent_peak': self.session_analytics['concurrent_peak'],
            'failed_attempts': sum(len(attempts) for attempts in self.failed_sessions.values())
        }
    
    def _is_ip_suspicious(self, original_ip: str, current_ip: str) -> bool:
        """Check if IP address change is suspicious"""
        # Simple check - in production, use geolocation and more sophisticated analysis
        return original_ip != current_ip
    
    def _record_failed_session(self, ip_address: str, reason: str):
        """Record failed session attempt for monitoring"""
        if ip_address:
            if ip_address not in self.failed_sessions:
                self.failed_sessions[ip_address] = []
            
            self.failed_sessions[ip_address].append({
                'timestamp': datetime.utcnow().isoformat(),
                'reason': reason
            })
            
            # Keep only recent failures (last 24 hours)
            cutoff = datetime.utcnow() - timedelta(hours=24)
            self.failed_sessions[ip_address] = [
                attempt for attempt in self.failed_sessions[ip_address]
                if datetime.fromisoformat(attempt['timestamp']) > cutoff
            ]

def demo_secure_session_management():
    """Demonstrate secure session management"""
    print("🔐 Secure Session Management Demo")
    print("="*50)
    
    # Create session manager
    session_manager = SecureSessionManager(
        session_timeout_hours=24,
        max_sessions_per_user=3,
        require_mfa=True
    )
    
    # Demo 1: Create session without MFA (should fail)
    print("\n📋 Demo 1: Create session without MFA")
    result = session_manager.create_session(
        user_id="user123",
        username="alice",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Chrome)",
        mfa_verified=False
    )
    print(f"   Result: {result}")
    
    # Demo 2: Create session with MFA
    print("\n📋 Demo 2: Create session with MFA")
    result = session_manager.create_session(
        user_id="user123",
        username="alice",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Chrome)",
        mfa_verified=True,
        permissions=["read", "write"]
    )
    
    if result['success']:
        jwt_token = result['jwt_token']
        session_id = result['session_id']
        
        print(f"   ✅ Session created")
        print(f"   Session ID: {session_id[:8]}...")
        print(f"   JWT Token: {jwt_token[:50]}...")
        
        # Demo 3: Validate session
        print(f"\n📋 Demo 3: Validate session")
        validation = session_manager.validate_session(
            jwt_token=jwt_token,
            ip_address="192.168.1.100"
        )
        print(f"   Validation result: {validation}")
        
        # Demo 4: Create multiple sessions
        print(f"\n📋 Demo 4: Create multiple sessions (test limits)")
        for i in range(4):  # Exceed the limit of 3
            result = session_manager.create_session(
                user_id="user123",
                username="alice",
                ip_address=f"192.168.1.{101+i}",
                user_agent=f"Browser {i+1}",
                mfa_verified=True
            )
            print(f"   Session {i+1}: {'✅ Created' if result['success'] else '❌ ' + result['message']}")
        
        # Demo 5: List user sessions
        print(f"\n📋 Demo 5: User sessions")
        user_sessions = session_manager.get_user_sessions("user123")
        print(f"   Active sessions for user123: {len(user_sessions)}")
        for i, session in enumerate(user_sessions):
            print(f"   Session {i+1}: {session['session_id']} from {session['ip_address']}")
        
        # Demo 6: Session analytics
        print(f"\n📋 Demo 6: Session analytics")
        analytics = session_manager.get_session_analytics()
        print(f"   Analytics: {analytics}")
        
        # Demo 7: Revoke all user sessions
        print(f"\n📋 Demo 7: Revoke all user sessions")
        revoked_count = session_manager.revoke_all_user_sessions("user123")
        print(f"   Revoked sessions: {revoked_count}")

def demo_session_security_features():
    """Demonstrate session security features"""
    print(f"\n🔒 Session Security Features")
    print("="*50)
    
    security_features = [
        "✅ JWT tokens with HMAC-SHA256 signatures",
        "✅ Server-side session storage for immediate revocation",
        "✅ Session timeout and automatic cleanup",
        "✅ Maximum sessions per user limit",
        "✅ MFA requirement enforcement",
        "✅ IP address tracking and monitoring",
        "✅ User agent fingerprinting",
        "✅ Failed session attempt tracking",
        "✅ Comprehensive session analytics"
    ]
    
    for feature in security_features:
        print(f"   {feature}")
    
    print(f"\n💡 Session Security Best Practices:")
    print("   • Use secure, random session IDs (cryptographically strong)")
    print("   • Implement session fixation protection")
    print("   • Set appropriate session timeouts")
    print("   • Use HTTPS only for session cookies")
    print("   • Implement concurrent session limits")
    print("   • Monitor for suspicious session activity")
    print("   • Provide session management dashboard for users")
    print("   • Log all session events for audit trail")

# Integration with Flask for practical demo
def create_session_protected_app():
    """Create Flask app with session protection"""
    from flask import Flask, request, session, jsonify, render_template_string
    
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(16)
    
    session_manager = SecureSessionManager()
    
    PROTECTED_TEMPLATE = """
    <h1>🔒 Protected Area</h1>
    <p>Welcome, {{ username }}!</p>
    <p>Session expires: {{ expires_at }}</p>
    <p>MFA verified: {{ mfa_verified }}</p>
    <p>Permissions: {{ permissions }}</p>
    <a href="/logout">Logout</a>
    """
    
    @app.route('/login', methods=['POST'])
    def login():
        username = request.json.get('username')
        mfa_verified = request.json.get('mfa_verified', False)
        
        result = session_manager.create_session(
            user_id=f"user_{username}",
            username=username,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            mfa_verified=mfa_verified
        )
        
        return jsonify(result)
    
    @app.route('/protected')
    def protected():
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401
        
        token = auth_header.split(' ')[1]
        validation = session_manager.validate_session(token, request.remote_addr)
        
        if not validation['success']:
            return jsonify({'error': validation['message']}), 401
        
        return render_template_string(PROTECTED_TEMPLATE, **validation)
    
    return app

if __name__ == "__main__":
    demo_secure_session_management()
    demo_session_security_features()
    
    # Optionally start Flask demo
    # app = create_session_protected_app()
    # app.run(debug=True)
```

### ✅ Checkpoint 3: Secure Session Management

Test your session system:
1. Can you create and validate JWT-based sessions?
2. Do you understand session security controls?
3. Can you implement proper session lifecycle management?

---

## 📘 Part 4: OAuth 2.0 Implementation (90 minutes)

**Learning Objective**: Implement OAuth 2.0 authorization flows

**What you'll build**: OAuth 2.0 server with multiple grant types

Create `oauth2_server.py`:

```python
import secrets
import jwt
import hashlib
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, urlencode
import json
from dataclasses import dataclass
from typing import Optional, Dict, List

@dataclass
class OAuthClient:
    """OAuth 2.0 client registration"""
    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: List[str]
    grant_types: List[str]
    scope: List[str]
    created_at: datetime

@dataclass
class AuthorizationCode:
    """Authorization code for OAuth flow"""
    code: str
    client_id: str
    user_id: str
    scope: List[str]
    redirect_uri: str
    expires_at: datetime
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None

@dataclass
class AccessToken:
    """Access token information"""
    token: str
    client_id: str
    user_id: str
    scope: List[str]
    expires_at: datetime
    token_type: str = "Bearer"

@dataclass
class RefreshToken:
    """Refresh token information"""
    token: str
    client_id: str
    user_id: str
    scope: List[str]
    access_token: str

class OAuth2Server:
    """OAuth 2.0 Authorization Server Implementation"""
    
    def __init__(self, issuer="https://auth.csci347lab.com"):
        self.issuer = issuer
        self.secret_key = secrets.token_hex(32)
        
        # Storage (use proper database in production)
        self.clients = {}
        self.authorization_codes = {}
        self.access_tokens = {}
        self.refresh_tokens = {}
        self.users = {}  # Simple user store for demo
        
        # Configuration
        self.code_lifetime_seconds = 600  # 10 minutes
        self.access_token_lifetime_seconds = 3600  # 1 hour
        self.refresh_token_lifetime_days = 30
        
        # Supported features
        self.supported_grant_types = [
            'authorization_code',
            'client_credentials',
            'refresh_token',
            'password'  # Not recommended for production
        ]
        
        self.supported_scopes = [
            'read', 'write', 'admin', 'profile', 'email'
        ]
    
    def register_client(self, client_name: str, redirect_uris: List[str], 
                       grant_types: List[str] = None, 
                       scope: List[str] = None) -> OAuthClient:
        """
        Register new OAuth 2.0 client
        
        Args:
            client_name: Human readable client name
            redirect_uris: List of valid redirect URIs
            grant_types: Supported grant types
            scope: Available scopes for client
            
        Returns:
            OAuthClient: Registered client information
        """
        client_id = secrets.token_urlsafe(16)
        client_secret = secrets.token_urlsafe(32)
        
        if grant_types is None:
            grant_types = ['authorization_code']
        
        if scope is None:
            scope = ['read']
        
        client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            client_name=client_name,
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            scope=scope,
            created_at=datetime.utcnow()
        )
        
        self.clients[client_id] = client
        
        print(f"✅ OAuth client registered: {client_name}")
        print(f"   Client ID: {client_id}")
        print(f"   Client Secret: {client_secret}")
        
        return client
    
    def authorize(self, client_id: str, redirect_uri: str, scope: str,
                 state: str = None, response_type: str = "code",
                 user_id: str = None, code_challenge: str = None,
                 code_challenge_method: str = None) -> Dict:
        """
        Handle authorization request (Authorization Code flow)
        
        Args:
            client_id: Client identifier
            redirect_uri: Redirect URI
            scope: Requested scope
            state: State parameter for CSRF protection
            response_type: Response type (should be 'code')
            user_id: Authenticated user ID
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE method (S256 or plain)
            
        Returns:
            dict: Authorization response
        """
        # Validate client
        if client_id not in self.clients:
            return {'error': 'invalid_client'}
        
        client = self.clients[client_id]
        
        # Validate redirect URI
        if redirect_uri not in client.redirect_uris:
            return {'error': 'invalid_redirect_uri'}
        
        # Validate response type
        if response_type != 'code':
            return {'error': 'unsupported_response_type'}
        
        # Validate scope
        requested_scopes = scope.split() if scope else []
        invalid_scopes = [s for s in requested_scopes if s not in client.scope]
        if invalid_scopes:
            return {'error': 'invalid_scope', 'invalid_scopes': invalid_scopes}
        
        # In real implementation, user would be authenticated here
        if not user_id:
            return {
                'error': 'user_authentication_required',
                'authorization_url': f'/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state}'
            }
        
        # Generate authorization code
        code = secrets.token_urlsafe(32)
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user_id,
            scope=requested_scopes,
            redirect_uri=redirect_uri,
            expires_at=datetime.utcnow() + timedelta(seconds=self.code_lifetime_seconds),
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method
        )
        
        self.authorization_codes[code] = auth_code
        
        # Build redirect response
        params = {'code': code}
        if state:
            params['state'] = state
        
        redirect_url = f"{redirect_uri}?{urlencode(params)}"
        
        print(f"✅ Authorization code generated for {client.client_name}")
        
        return {
            'success': True,
            'redirect_url': redirect_url,
            'authorization_code': code
        }
    
    def token(self, grant_type: str, **kwargs) -> Dict:
        """
        Handle token request
        
        Args:
            grant_type: OAuth grant type
            **kwargs: Grant-specific parameters
            
        Returns:
            dict: Token response
        """
        if grant_type not in self.supported_grant_types:
            return {'error': 'unsupported_grant_type'}
        
        if grant_type == 'authorization_code':
            return self._handle_authorization_code_grant(**kwargs)
        elif grant_type == 'client_credentials':
            return self._handle_client_credentials_grant(**kwargs)
        elif grant_type == 'refresh_token':
            return self._handle_refresh_token_grant(**kwargs)
        elif grant_type == 'password':
            return self._handle_password_grant(**kwargs)
        else:
            return {'error': 'unsupported_grant_type'}
    
    def _handle_authorization_code_grant(self, client_id: str, client_secret: str,
                                       code: str, redirect_uri: str, 
                                       code_verifier: str = None) -> Dict:
        """Handle authorization code grant"""
        # Validate client credentials
        if not self._validate_client(client_id, client_secret):
            return {'error': 'invalid_client'}
        
        # Validate authorization code
        if code not in self.authorization_codes:
            return {'error': 'invalid_grant'}
        
        auth_code = self.authorization_codes[code]
        
        # Check expiration
        if datetime.utcnow() > auth_code.expires_at:
            del self.authorization_codes[code]
            return {'error': 'invalid_grant'}
        
        # Validate client and redirect URI
        if auth_code.client_id != client_id or auth_code.redirect_uri != redirect_uri:
            return {'error': 'invalid_grant'}
        
        # Validate PKCE if used
        if auth_code.code_challenge:
            if not code_verifier:
                return {'error': 'invalid_request', 'error_description': 'code_verifier required'}
            
            if not self._validate_pkce(auth_code.code_challenge, 
                                     auth_code.code_challenge_method, 
                                     code_verifier):
                return {'error': 'invalid_grant'}
        
        # Generate tokens
        access_token = self._generate_access_token(client_id, auth_code.user_id, auth_code.scope)
        refresh_token = self._generate_refresh_token(client_id, auth_code.user_id, auth_code.scope, access_token.token)
        
        # Clean up authorization code
        del self.authorization_codes[code]
        
        print(f"✅ Access token issued for authorization code grant")
        
        return {
            'access_token': access_token.token,
            'token_type': access_token.token_type,
            'expires_in': int((access_token.expires_at - datetime.utcnow()).total_seconds()),
            'refresh_token': refresh_token.token,
            'scope': ' '.join(access_token.scope)
        }
    
    def _handle_client_credentials_grant(self, client_id: str, client_secret: str,
                                       scope: str = None) -> Dict:
        """Handle client credentials grant"""
        # Validate client credentials
        if not self._validate_client(client_id, client_secret):
            return {'error': 'invalid_client'}
        
        client = self.clients[client_id]
        
        # Validate grant type
        if 'client_credentials' not in client.grant_types:
            return {'error': 'unauthorized_client'}
        
        # Process scope
        if scope:
            requested_scopes = scope.split()
            invalid_scopes = [s for s in requested_scopes if s not in client.scope]
            if invalid_scopes:
                return {'error': 'invalid_scope'}
        else:
            requested_scopes = client.scope
        
        # Generate access token (no refresh token for client credentials)
        access_token = self._generate_access_token(client_id, None, requested_scopes)
        
        print(f"✅ Access token issued for client credentials grant")
        
        return {
            'access_token': access_token.token,
            'token_type': access_token.token_type,
            'expires_in': int((access_token.expires_at - datetime.utcnow()).total_seconds()),
            'scope': ' '.join(access_token.scope)
        }
    
    def _handle_refresh_token_grant(self, client_id: str, client_secret: str,
                                  refresh_token: str, scope: str = None) -> Dict:
        """Handle refresh token grant"""
        # Validate client credentials
        if not self._validate_client(client_id, client_secret):
            return {'error': 'invalid_client'}
        
        # Validate refresh token
        if refresh_token not in self.refresh_tokens:
            return {'error': 'invalid_grant'}
        
        refresh_token_info = self.refresh_tokens[refresh_token]
        
        if refresh_token_info.client_id != client_id:
            return {'error': 'invalid_grant'}
        
        # Process scope
        if scope:
            requested_scopes = scope.split()
            # Scope can only be reduced, not expanded
            invalid_scopes = [s for s in requested_scopes if s not in refresh_token_info.scope]
            if invalid_scopes:
                return {'error': 'invalid_scope'}
        else:
            requested_scopes = refresh_token_info.scope
        
        # Revoke old access token
        old_access_token = refresh_token_info.access_token
        if old_access_token in self.access_tokens:
            del self.access_tokens[old_access_token]
        
        # Generate new access token
        new_access_token = self._generate_access_token(
            client_id, refresh_token_info.user_id, requested_scopes
        )
        
        # Update refresh token
        refresh_token_info.access_token = new_access_token.token
        
        print(f"✅ Access token refreshed")
        
        return {
            'access_token': new_access_token.token,
            'token_type': new_access_token.token_type,
            'expires_in': int((new_access_token.expires_at - datetime.utcnow()).total_seconds()),
            'scope': ' '.join(new_access_token.scope)
        }
    
    def _handle_password_grant(self, client_id: str, client_secret: str,
                             username: str, password: str, scope: str = None) -> Dict:
        """Handle resource owner password credentials grant (not recommended)"""
        # Validate client credentials
        if not self._validate_client(client_id, client_secret):
            return {'error': 'invalid_client'}
        
        client = self.clients[client_id]
        
        # Validate grant type
        if 'password' not in client.grant_types:
            return {'error': 'unauthorized_client'}
        
        # Validate user credentials (simplified for demo)
        if username not in self.users or self.users[username]['password'] != password:
            return {'error': 'invalid_grant'}
        
        user_id = self.users[username]['user_id']
        
        # Process scope
        if scope:
            requested_scopes = scope.split()
            invalid_scopes = [s for s in requested_scopes if s not in client.scope]
            if invalid_scopes:
                return {'error': 'invalid_scope'}
        else:
            requested_scopes = client.scope
        
        # Generate tokens
        access_token = self._generate_access_token(client_id, user_id, requested_scopes)
        refresh_token = self._generate_refresh_token(client_id, user_id, requested_scopes, access_token.token)
        
        print(f"✅ Access token issued for password grant")
        
        return {
            'access_token': access_token.token,
            'token_type': access_token.token_type,
            'expires_in': int((access_token.expires_at - datetime.utcnow()).total_seconds()),
            'refresh_token': refresh_token.token,
            'scope': ' '.join(access_token.scope)
        }
    
    def validate_token(self, token: str) -> Dict:
        """Validate access token and return token info"""
        if token not in self.access_tokens:
            return {'error': 'invalid_token'}
        
        token_info = self.access_tokens[token]
        
        if datetime.utcnow() > token_info.expires_at:
            del self.access_tokens[token]
            return {'error': 'invalid_token'}
        
        return {
            'valid': True,
            'client_id': token_info.client_id,
            'user_id': token_info.user_id,
            'scope': token_info.scope,
            'expires_at': token_info.expires_at.isoformat()
        }
    
    def _generate_access_token(self, client_id: str, user_id: str, scope: List[str]) -> AccessToken:
        """Generate access token"""
        token = secrets.token_urlsafe(32)
        
        access_token = AccessToken(
            token=token,
            client_id=client_id,
            user_id=user_id,
            scope=scope,
            expires_at=datetime.utcnow() + timedelta(seconds=self.access_token_lifetime_seconds)
        )
        
        self.access_tokens[token] = access_token
        return access_token
    
    def _generate_refresh_token(self, client_id: str, user_id: str, 
                              scope: List[str], access_token: str) -> RefreshToken:
        """Generate refresh token"""
        token = secrets.token_urlsafe(32)
        
        refresh_token = RefreshToken(
            token=token,
            client_id=client_id,
            user_id=user_id,
            scope=scope,
            access_token=access_token
        )
        
        self.refresh_tokens[token] = refresh_token
        return refresh_token
    
    def _validate_client(self, client_id: str, client_secret: str) -> bool:
        """Validate client credentials"""
        if client_id not in self.clients:
            return False
        
        client = self.clients[client_id]
        return client.client_secret == client_secret
    
    def _validate_pkce(self, challenge: str, method: str, verifier: str) -> bool:
        """Validate PKCE code challenge"""
        if method == 'S256':
            import hashlib
            import base64
            expected = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).decode().rstrip('=')
            return expected == challenge
        elif method == 'plain':
            return challenge == verifier
        else:
            return False

def demo_oauth2_server():
    """Demonstrate OAuth 2.0 server implementation"""
    print("🔐 OAuth 2.0 Server Demo")
    print("="*50)
    
    # Create OAuth server
    oauth_server = OAuth2Server()
    
    # Add demo user
    oauth_server.users['alice'] = {
        'user_id': 'user123',
        'password': 'password123'  # In production, use proper hashing
    }
    
    # Demo 1: Register OAuth client
    print("\n📋 Demo 1: Register OAuth Client")
    client = oauth_server.register_client(
        client_name="CSCI347 Demo App",
        redirect_uris=["https://app.csci347lab.com/callback"],
        grant_types=["authorization_code", "refresh_token", "client_credentials"],
        scope=["read", "write", "profile"]
    )
    
    # Demo 2: Authorization Code Flow
    print(f"\n📋 Demo 2: Authorization Code Flow")
    
    # Step 1: Authorization request
    auth_result = oauth_server.authorize(
        client_id=client.client_id,
        redirect_uri="https://app.csci347lab.com/callback",
        scope="read profile",
        state="xyz123",
        user_id="user123"  # Assume user is authenticated
    )
    
    print(f"   Authorization result: {auth_result}")
    
    if auth_result.get('success'):
        authorization_code = auth_result['authorization_code']
        
        # Step 2: Token request
        token_result = oauth_server.token(
            grant_type="authorization_code",
            client_id=client.client_id,
            client_secret=client.client_secret,
            code=authorization_code,
            redirect_uri="https://app.csci347lab.com/callback"
        )
        
        print(f"   Token result: {token_result}")
        
        if 'access_token' in token_result:
            access_token = token_result['access_token']
            refresh_token = token_result['refresh_token']
            
            # Step 3: Validate access token
            validation = oauth_server.validate_token(access_token)
            print(f"   Token validation: {validation}")
            
            # Step 4: Refresh token
            refresh_result = oauth_server.token(
                grant_type="refresh_token",
                client_id=client.client_id,
                client_secret=client.client_secret,
                refresh_token=refresh_token
            )
            print(f"   Refresh result: {refresh_result}")
    
    # Demo 3: Client Credentials Flow
    print(f"\n📋 Demo 3: Client Credentials Flow")
    
    client_creds_result = oauth_server.token(
        grant_type="client_credentials",
        client_id=client.client_id,
        client_secret=client.client_secret,
        scope="read"
    )
    
    print(f"   Client credentials result: {client_creds_result}")
    
    # Demo 4: Password Grant (not recommended)
    print(f"\n📋 Demo 4: Password Grant (Demo Only)")
    
    password_result = oauth_server.token(
        grant_type="password",
        client_id=client.client_id,
        client_secret=client.client_secret,
        username="alice",
        password="password123",
        scope="read write"
    )
    
    print(f"   Password grant result: {password_result}")

def demo_oauth2_security():
    """Demonstrate OAuth 2.0 security features"""
    print(f"\n🔒 OAuth 2.0 Security Features")
    print("="*50)
    
    security_features = [
        "✅ Client authentication with client_secret",
        "✅ Authorization code with short lifetime (10 minutes)",
        "✅ Access token expiration (1 hour)",
        "✅ Refresh token rotation",
        "✅ Scope validation and restriction",
        "✅ Redirect URI validation",
        "✅ State parameter for CSRF protection",
        "✅ PKCE support for public clients",
        "✅ Multiple grant types support"
    ]
    
    for feature in security_features:
        print(f"   {feature}")
    
    print(f"\n💡 OAuth 2.0 Best Practices:")
    print("   • Always use HTTPS for authorization endpoints")
    print("   • Implement proper client authentication")
    print("   • Use PKCE for public clients (mobile/SPA)")
    print("   • Keep authorization codes short-lived")
    print("   • Implement proper scope validation")
    print("   • Log all OAuth flows for monitoring")
    print("   • Use opaque tokens or JWT with proper validation")
    print("   • Implement token revocation endpoints")

if __name__ == "__main__":
    demo_oauth2_server()
    demo_oauth2_security()
```

### ✅ Checkpoint 4: OAuth 2.0 Implementation

Verify your OAuth implementation:
1. Can you implement authorization code flow?
2. Do you understand different OAuth grant types?
3. Can you validate tokens and manage scope?

---

## 📘 Part 5: Risk-Based Authentication (45 minutes)

**Learning Objective**: Implement adaptive authentication based on risk factors

**What you'll build**: Risk assessment and adaptive authentication system

Create `risk_based_authentication.py`:

```python
import hashlib
import json
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
import math
import ipaddress

@dataclass
class LoginAttempt:
    """Login attempt information"""
    user_id: str
    username: str
    ip_address: str
    user_agent: str
    timestamp: datetime
    success: bool
    location: Optional[str] = None
    device_fingerprint: Optional[str] = None
    
@dataclass
class RiskAssessment:
    """Risk assessment result"""
    risk_score: float
    risk_level: str
    factors: List[str]
    recommended_actions: List[str]
    require_mfa: bool
    require_device_verification: bool
    allow_login: bool

class RiskBasedAuthenticator:
    """Risk-based authentication system"""
    
    def __init__(self):
        # Risk scoring thresholds
        self.risk_thresholds = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8
        }
        
        # Historical data storage
        self.login_history = {}  # user_id -> [LoginAttempt]
        self.user_profiles = {}  # user_id -> profile data
        self.ip_reputation = {}  # ip -> reputation score
        self.device_history = {}  # user_id -> {device_fingerprint -> info}
        
        # Risk factors configuration
        self.risk_factors = {
            'new_device': 0.4,
            'new_location': 0.3,
            'suspicious_ip': 0.5,
            'unusual_time': 0.2,
            'failed_attempts': 0.3,
            'velocity_attack': 0.6,
            'impossible_travel': 0.8
        }
        
        # Time-based patterns
        self.business_hours = (9, 17)  # 9 AM to 5 PM
        self.max_travel_speed_kmh = 1000  # Maximum realistic travel speed
    
    def assess_login_risk(self, user_id: str, username: str, ip_address: str,
                         user_agent: str, location: str = None) -> RiskAssessment:
        """
        Assess risk for a login attempt
        
        Args:
            user_id: User identifier
            username: Username
            ip_address: Client IP address
            user_agent: Client user agent
            location: Geographic location (optional)
            
        Returns:
            RiskAssessment: Comprehensive risk assessment
        """
        risk_factors = []
        risk_score = 0.0
        
        # Generate device fingerprint
        device_fingerprint = self._generate_device_fingerprint(user_agent, ip_address)
        
        # Initialize user profile if first time
        if user_id not in self.user_profiles:
            self._initialize_user_profile(user_id)
        
        # Analyze various risk factors
        
        # 1. New device detection
        if self._is_new_device(user_id, device_fingerprint):
            risk_factors.append("New device detected")
            risk_score += self.risk_factors['new_device']
        
        # 2. Location analysis
        if location:
            if self._is_new_location(user_id, location):
                risk_factors.append("New geographic location")
                risk_score += self.risk_factors['new_location']
            
            # Check for impossible travel
            if self._is_impossible_travel(user_id, location):
                risk_factors.append("Impossible travel detected")
                risk_score += self.risk_factors['impossible_travel']
        
        # 3. IP reputation analysis
        ip_risk = self._analyze_ip_reputation(ip_address)
        if ip_risk > 0.5:
            risk_factors.append("Suspicious IP address")
            risk_score += self.risk_factors['suspicious_ip'] * ip_risk
        
        # 4. Time-based analysis
        if self._is_unusual_time(user_id):
            risk_factors.append("Login at unusual time")
            risk_score += self.risk_factors['unusual_time']
        
        # 5. Failed attempt history
        failed_attempts_risk = self._analyze_failed_attempts(user_id)
        if failed_attempts_risk > 0:
            risk_factors.append(f"Recent failed login attempts")
            risk_score += failed_attempts_risk
        
        # 6. Velocity attack detection
        if self._detect_velocity_attack(user_id):
            risk_factors.append("High frequency login attempts")
            risk_score += self.risk_factors['velocity_attack']
        
        # Normalize risk score (0.0 to 1.0)
        risk_score = min(risk_score, 1.0)
        
        # Determine risk level
        if risk_score < self.risk_thresholds['low']:
            risk_level = 'low'
        elif risk_score < self.risk_thresholds['medium']:
            risk_level = 'medium'
        elif risk_score < self.risk_thresholds['high']:
            risk_level = 'high'
        else:
            risk_level = 'critical'
        
        # Determine authentication requirements
        require_mfa = risk_score >= self.risk_thresholds['low']
        require_device_verification = risk_score >= self.risk_thresholds['medium']
        allow_login = risk_score < 0.9  # Block critical risk logins
        
        # Generate recommendations
        recommendations = self._generate_recommendations(risk_level, risk_factors)
        
        print(f"🔍 Risk assessment for {username}:")
        print(f"   Risk Score: {risk_score:.2f}")
        print(f"   Risk Level: {risk_level.upper()}")
        print(f"   Factors: {len(risk_factors)} detected")
        
        return RiskAssessment(
            risk_score=risk_score,
            risk_level=risk_level,
            factors=risk_factors,
            recommended_actions=recommendations,
            require_mfa=require_mfa,
            require_device_verification=require_device_verification,
            allow_login=allow_login
        )
    
    def record_login_attempt(self, user_id: str, username: str, ip_address: str,
                           user_agent: str, success: bool, location: str = None):
        """Record login attempt for future risk analysis"""
        device_fingerprint = self._generate_device_fingerprint(user_agent, ip_address)
        
        attempt = LoginAttempt(
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.utcnow(),
            success=success,
            location=location,
            device_fingerprint=device_fingerprint
        )
        
        # Store in history
        if user_id not in self.login_history:
            self.login_history[user_id] = []
        
        self.login_history[user_id].append(attempt)
        
        # Keep only recent history (last 100 attempts)
        self.login_history[user_id] = self.login_history[user_id][-100:]
        
        # Update user profile
        self._update_user_profile(user_id, attempt)
        
        # Update IP reputation
        self._update_ip_reputation(ip_address, success)
    
    def _initialize_user_profile(self, user_id: str):
        """Initialize user profile for risk analysis"""
        self.user_profiles[user_id] = {
            'known_devices': set(),
            'known_locations': set(),
            'typical_login_hours': [],
            'first_seen': datetime.utcnow(),
            'last_login': None
        }
        
        self.device_history[user_id] = {}
    
    def _update_user_profile(self, user_id: str, attempt: LoginAttempt):
        """Update user profile based on login attempt"""
        profile = self.user_profiles[user_id]
        
        if attempt.success:
            # Update known devices
            profile['known_devices'].add(attempt.device_fingerprint)
            
            # Update known locations
            if attempt.location:
                profile['known_locations'].add(attempt.location)
            
            # Update typical login hours
            hour = attempt.timestamp.hour
            profile['typical_login_hours'].append(hour)
            
            # Keep only recent login hours (last 50)
            profile['typical_login_hours'] = profile['typical_login_hours'][-50:]
            
            # Update device history
            if attempt.device_fingerprint not in self.device_history[user_id]:
                self.device_history[user_id][attempt.device_fingerprint] = {
                    'first_seen': attempt.timestamp,
                    'last_seen': attempt.timestamp,
                    'user_agent': attempt.user_agent,
                    'ip_addresses': set()
                }
            
            device_info = self.device_history[user_id][attempt.device_fingerprint]
            device_info['last_seen'] = attempt.timestamp
            device_info['ip_addresses'].add(attempt.ip_address)
            
            profile['last_login'] = attempt.timestamp
    
    def _generate_device_fingerprint(self, user_agent: str, ip_address: str) -> str:
        """Generate device fingerprint from user agent and IP"""
        # Simplified fingerprinting - in production, use more sophisticated methods
        fingerprint_data = f"{user_agent}:{ip_address}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
    
    def _is_new_device(self, user_id: str, device_fingerprint: str) -> bool:
        """Check if device is new for this user"""
        if user_id not in self.user_profiles:
            return True
        
        return device_fingerprint not in self.user_profiles[user_id]['known_devices']
    
    def _is_new_location(self, user_id: str, location: str) -> bool:
        """Check if location is new for this user"""
        if user_id not in self.user_profiles:
            return True
        
        return location not in self.user_profiles[user_id]['known_locations']
    
    def _is_impossible_travel(self, user_id: str, location: str) -> bool:
        """Check for impossible travel scenario"""
        if user_id not in self.login_history:
            return False
        
        recent_attempts = [a for a in self.login_history[user_id] 
                         if a.success and a.location and 
                         (datetime.utcnow() - a.timestamp).total_seconds() < 3600]  # Last hour
        
        if not recent_attempts:
            return False
        
        last_attempt = recent_attempts[-1]
        
        # Calculate distance (simplified - use proper geolocation in production)
        if last_attempt.location != location:
            # Assume maximum realistic travel speed
            time_diff_hours = (datetime.utcnow() - last_attempt.timestamp).total_seconds() / 3600
            # If less than 1 hour between different locations, consider suspicious
            return time_diff_hours < 1
        
        return False
    
    def _analyze_ip_reputation(self, ip_address: str) -> float:
        """Analyze IP address reputation"""
        # Simplified IP reputation - in production, use threat intelligence feeds
        
        # Check if IP is in private ranges
        try:
            ip = ipaddress.ip_address(ip_address)
            if ip.is_private:
                return 0.1  # Low risk for private IPs
        except:
            pass
        
        # Check our internal reputation database
        if ip_address in self.ip_reputation:
            return self.ip_reputation[ip_address]
        
        # Default risk for unknown IPs
        return 0.2
    
    def _update_ip_reputation(self, ip_address: str, success: bool):
        """Update IP reputation based on login success/failure"""
        if ip_address not in self.ip_reputation:
            self.ip_reputation[ip_address] = 0.2
        
        # Adjust reputation based on activity
        if success:
            self.ip_reputation[ip_address] = max(0.0, self.ip_reputation[ip_address] - 0.05)
        else:
            self.ip_reputation[ip_address] = min(1.0, self.ip_reputation[ip_address] + 0.1)
    
    def _is_unusual_time(self, user_id: str) -> bool:
        """Check if login time is unusual for user"""
        current_hour = datetime.utcnow().hour
        
        if user_id not in self.user_profiles:
            # Check against business hours for new users
            return not (self.business_hours[0] <= current_hour <= self.business_hours[1])
        
        profile = self.user_profiles[user_id]
        typical_hours = profile.get('typical_login_hours', [])
        
        if not typical_hours:
            return False
        
        # Calculate how often user logs in at this hour
        hour_frequency = typical_hours.count(current_hour) / len(typical_hours)
        
        # If less than 5% of logins at this hour, consider unusual
        return hour_frequency < 0.05
    
    def _analyze_failed_attempts(self, user_id: str) -> float:
        """Analyze recent failed login attempts"""
        if user_id not in self.login_history:
            return 0.0
        
        # Look at last 24 hours
        cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_attempts = [a for a in self.login_history[user_id] if a.timestamp > cutoff]
        
        if not recent_attempts:
            return 0.0
        
        failed_count = sum(1 for a in recent_attempts if not a.success)
        total_count = len(recent_attempts)
        
        # Calculate risk based on failure rate
        failure_rate = failed_count / total_count
        return min(failure_rate * self.risk_factors['failed_attempts'], 0.5)
    
    def _detect_velocity_attack(self, user_id: str) -> bool:
        """Detect high-velocity login attempts"""
        if user_id not in self.login_history:
            return False
        
        # Look at last 10 minutes
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        recent_attempts = [a for a in self.login_history[user_id] if a.timestamp > cutoff]
        
        # If more than 10 attempts in 10 minutes, flag as velocity attack
        return len(recent_attempts) > 10
    
    def _generate_recommendations(self, risk_level: str, risk_factors: List[str]) -> List[str]:
        """Generate security recommendations based on risk assessment"""
        recommendations = []
        
        if risk_level == 'low':
            recommendations.append("Allow login with standard authentication")
            
        elif risk_level == 'medium':
            recommendations.append("Require multi-factor authentication")
            recommendations.append("Send security notification to user")
            
        elif risk_level == 'high':
            recommendations.append("Require multi-factor authentication")
            recommendations.append("Require device verification")
            recommendations.append("Send immediate security alert")
            recommendations.append("Consider requiring password change")
            
        else:  # critical
            recommendations.append("Block login attempt")
            recommendations.append("Require manual security review")
            recommendations.append("Alert security team immediately")
            recommendations.append("Consider account suspension")
        
        # Specific recommendations based on factors
        if "New device detected" in risk_factors:
            recommendations.append("Require email verification for new device")
            
        if "Impossible travel detected" in risk_factors:
            recommendations.append("Investigate potential account compromise")
            
        if "High frequency login attempts" in risk_factors:
            recommendations.append("Implement rate limiting")
        
        return recommendations

def demo_risk_based_authentication():
    """Demonstrate risk-based authentication system"""
    print("🎯 Risk-Based Authentication Demo")
    print("="*50)
    
    rba = RiskBasedAuthenticator()
    
    # Demo 1: Normal user behavior (low risk)
    print("\n📋 Demo 1: Normal User Behavior")
    
    # Simulate normal login pattern
    user_id = "user123"
    username = "alice"
    
    # First few logins to establish pattern
    for i in range(5):
        rba.record_login_attempt(
            user_id=user_id,
            username=username,
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
            success=True,
            location="San Francisco, CA"
        )
    
    # Normal login attempt
    risk = rba.assess_login_risk(
        user_id=user_id,
        username=username,
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
        location="San Francisco, CA"
    )
    
    print(f"   Risk Level: {risk.risk_level}")
    print(f"   Risk Score: {risk.risk_score:.2f}")
    print(f"   MFA Required: {risk.require_mfa}")
    print(f"   Allow Login: {risk.allow_login}")
    
    # Demo 2: New device (medium risk)
    print(f"\n📋 Demo 2: New Device Login")
    
    risk = rba.assess_login_risk(
        user_id=user_id,
        username=username,
        ip_address="192.168.1.101",  # Different IP
        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 14_0) Mobile Safari",  # Mobile device
        location="San Francisco, CA"
    )
    
    print(f"   Risk Level: {risk.risk_level}")
    print(f"   Risk Score: {risk.risk_score:.2f}")
    print(f"   Risk Factors: {risk.factors}")
    print(f"   Recommendations: {risk.recommended_actions[:2]}")
    
    # Demo 3: Suspicious location (high risk)
    print(f"\n📋 Demo 3: Suspicious Location")
    
    risk = rba.assess_login_risk(
        user_id=user_id,
        username=username,
        ip_address="203.0.113.1",  # Different IP
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
        location="Moscow, Russia"  # Very different location
    )
    
    print(f"   Risk Level: {risk.risk_level}")
    print(f"   Risk Score: {risk.risk_score:.2f}")
    print(f"   Risk Factors: {risk.factors}")
    print(f"   Device Verification Required: {risk.require_device_verification}")
    
    # Demo 4: Failed attempts (increasing risk)
    print(f"\n📋 Demo 4: Failed Login Attempts")
    
    # Simulate failed login attempts
    for i in range(5):
        rba.record_login_attempt(
            user_id=user_id,
            username=username,
            ip_address="198.51.100.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
            success=False,
            location="San Francisco, CA"
        )
    
    risk = rba.assess_login_risk(
        user_id=user_id,
        username=username,
        ip_address="198.51.100.1",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
        location="San Francisco, CA"
    )
    
    print(f"   Risk Level: {risk.risk_level}")
    print(f"   Risk Score: {risk.risk_score:.2f}")
    print(f"   Risk Factors: {risk.factors}")

def demo_adaptive_authentication():
    """Demonstrate adaptive authentication responses"""
    print(f"\n🔄 Adaptive Authentication Responses")
    print("="*50)
    
    response_examples = [
        {
            'risk_level': 'low',
            'actions': ['Standard username/password authentication', 'Log successful login']
        },
        {
            'risk_level': 'medium', 
            'actions': ['Require TOTP/SMS code', 'Send security notification email', 'Log elevated risk event']
        },
        {
            'risk_level': 'high',
            'actions': ['Require multiple authentication factors', 'Device verification via email/SMS', 'Temporary account monitoring', 'Alert security team']
        },
        {
            'risk_level': 'critical',
            'actions': ['Block login attempt', 'Require manual review', 'Account suspension', 'Immediate security investigation']
        }
    ]
    
    for example in response_examples:
        print(f"\n   📊 {example['risk_level'].upper()} Risk Response:")
        for action in example['actions']:
            print(f"      • {action}")

if __name__ == "__main__":
    demo_risk_based_authentication()
    demo_adaptive_authentication()
```

### ✅ Checkpoint 5: Risk-Based Authentication

Verify your risk assessment system:
1. Can you calculate risk scores from multiple factors?
2. Do you understand adaptive authentication responses?
3. Can you build user behavioral profiles for risk analysis?

---

## ✅ Tutorial Completion Checklist

After completing all parts, verify your understanding:

- [ ] You can implement TOTP-based two-factor authentication
- [ ] You understand multi-channel verification (SMS/Email)
- [ ] You can create secure session management systems
- [ ] You can implement OAuth 2.0 authorization flows
- [ ] You can build risk-based authentication systems
- [ ] You understand authentication security best practices

## 🚀 Ready for the Assignment?

Perfect! Now you have comprehensive knowledge of multi-factor authentication systems. The assignment will combine these concepts into an enterprise-grade MFA solution.

**Next step**: Review [assignment.md](assignment.md) for detailed requirements.

## 💡 Key Concepts Learned

1. **Time-based One-Time Passwords (TOTP)** with authenticator apps
2. **Multi-channel verification** via SMS and email
3. **Secure session management** with JWT tokens
4. **OAuth 2.0 authorization flows** and token management
5. **Risk-based authentication** with adaptive responses
6. **Authentication security controls** and best practices
7. **User experience considerations** in security design

---

**Questions?** Check the troubleshooting section or ask in Canvas discussions!