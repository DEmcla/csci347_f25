# Week 4 Assignment: Secure Multi-Factor Authentication System

**Due**: End of Week 4 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Upload to Canvas

## 🎯 Assignment Overview

Build a comprehensive multi-factor authentication (MFA) system that supports multiple authentication factors and secure session management. Your implementation should demonstrate mastery of authentication protocols, TOTP, session security, and risk-based authentication concepts learned this week.

## 📋 Requirements

### Core Functionality (70 points)

Your MFA system must implement these features:

#### 1. Multi-Factor Authentication Engine (25 points)
- **TOTP (Time-based One-Time Password)** implementation using HMAC-SHA1
- **Backup authentication codes** generation and validation
- **QR code generation** for authenticator app setup
- **Rate limiting** to prevent brute force attacks

#### 2. Secure Session Management (25 points)
- **JWT token generation** with proper claims and expiration
- **Session validation** and renewal mechanisms
- **Secure logout** with token invalidation
- **Session hijacking protection** with IP and user agent validation

#### 3. Risk-Based Authentication (20 points)
- **Device fingerprinting** based on user agent and screen resolution
- **Location-based risk assessment** using IP geolocation
- **Suspicious activity detection** (unusual login times, failed attempts)
- **Adaptive authentication** requiring additional factors for high-risk scenarios

### Web Interface (20 points)

Create a Flask-based web application with these pages:

```
/register          - User registration with MFA setup
/login             - Primary authentication (username/password)
/mfa-setup         - TOTP setup with QR code display
/mfa-verify        - Second factor verification
/dashboard         - Protected area requiring authentication
/profile           - User profile with authentication history
/logout            - Secure session termination
```

### Security Features (10 points)

- **Password hashing** with bcrypt and appropriate cost factor
- **CSRF protection** for all forms
- **Input validation** and sanitization
- **Secure random number generation** for tokens and codes

## 🔧 Technical Specifications

### Required Libraries
```python
from flask import Flask, request, render_template, redirect, session, jsonify
from flask_session import Session
import pyotp
import qrcode
import jwt
import bcrypt
import secrets
import datetime
import requests
import sqlite3
import json
```

### File Structure
```
mfa_system.py             # Main Flask application
auth_manager.py           # Authentication logic
risk_engine.py            # Risk assessment functionality
database.py               # Database operations
templates/                # HTML templates
  ├── login.html
  ├── mfa_setup.html
  ├── mfa_verify.html
  ├── dashboard.html
  └── profile.html
static/                   # CSS and JavaScript files
users.db                  # SQLite database
README.txt                # Implementation documentation
```

### Database Schema
```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret TEXT,
    backup_codes TEXT,  -- JSON array of backup codes
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

-- Sessions table
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Authentication logs
CREATE TABLE auth_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT,  -- 'login_success', 'login_failure', 'mfa_success', etc.
    ip_address TEXT,
    user_agent TEXT,
    risk_score REAL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## 📝 Detailed Requirements

### 1. Authentication Manager
```python
class AuthManager:
    def __init__(self, db_connection):
        self.db = db_connection
        
    def register_user(self, username, email, password):
        """
        Register new user with secure password hashing
        
        Args:
            username (str): Unique username
            email (str): User's email address
            password (str): Plain text password
            
        Returns:
            dict: Registration result with user ID or error
        """
        # Hash password with bcrypt
        # Generate TOTP secret
        # Create backup codes
        # Store in database
        
    def authenticate_user(self, username, password, ip_address, user_agent):
        """
        Primary authentication with username/password
        
        Args:
            username (str): Username
            password (str): Password
            ip_address (str): Client IP address
            user_agent (str): Client user agent
            
        Returns:
            dict: Authentication result with user info or error
        """
        # Verify username and password
        # Check account lockout status
        # Log authentication attempt
        # Return user data if successful
        
    def verify_totp(self, user_id, token):
        """
        Verify TOTP token for second factor
        
        Args:
            user_id (int): User identifier
            token (str): 6-digit TOTP code
            
        Returns:
            bool: True if token is valid
        """
        # Get user's TOTP secret
        # Verify token with time window tolerance
        # Prevent token replay attacks
        
    def create_session(self, user_id, ip_address, user_agent):
        """
        Create secure session with JWT token
        
        Args:
            user_id (int): User identifier
            ip_address (str): Client IP
            user_agent (str): Client user agent
            
        Returns:
            str: JWT session token
        """
        # Generate session ID
        # Create JWT with proper claims
        # Store session in database
        # Return token
```

### 2. Risk Assessment Engine
```python
class RiskEngine:
    def __init__(self, db_connection):
        self.db = db_connection
        
    def assess_login_risk(self, user_id, ip_address, user_agent, timestamp):
        """
        Assess risk level for login attempt
        
        Args:
            user_id (int): User attempting login
            ip_address (str): Client IP address
            user_agent (str): Client user agent
            timestamp (datetime): Login timestamp
            
        Returns:
            dict: Risk assessment with score and factors
        """
        risk_score = 0.0
        risk_factors = []
        
        # Check for new device (user agent analysis)
        # Assess geographic location (IP geolocation)
        # Analyze time patterns (unusual login hours)
        # Check recent failed attempts
        # Calculate composite risk score
        
        return {
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'factors': risk_factors
        }
        
    def _get_risk_level(self, score):
        """Convert numerical score to risk level"""
        if score < 0.3:
            return 'LOW'
        elif score < 0.7:
            return 'MEDIUM'
        else:
            return 'HIGH'
```

### 3. Web Application Routes
```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        # Primary authentication
        auth_result = auth_manager.authenticate_user(
            username, password, ip_address, user_agent
        )
        
        if auth_result['success']:
            # Assess login risk
            risk_assessment = risk_engine.assess_login_risk(
                auth_result['user_id'], ip_address, user_agent, datetime.now()
            )
            
            # Store in session for MFA step
            session['pending_user_id'] = auth_result['user_id']
            session['risk_level'] = risk_assessment['risk_level']
            
            return redirect('/mfa-verify')
        else:
            return render_template('login.html', error=auth_result['error'])
    
    return render_template('login.html')

@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'pending_user_id' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        token = request.form['token']
        user_id = session['pending_user_id']
        
        # Verify TOTP token
        if auth_manager.verify_totp(user_id, token):
            # Create secure session
            session_token = auth_manager.create_session(
                user_id, request.remote_addr, request.headers.get('User-Agent')
            )
            
            # Store in secure session
            session['token'] = session_token
            session['user_id'] = user_id
            session.pop('pending_user_id')
            
            return redirect('/dashboard')
        else:
            return render_template('mfa_verify.html', error='Invalid code')
    
    return render_template('mfa_verify.html')
```

## 💻 Example Usage

```bash
# Start the MFA system
python mfa_system.py

# Navigate to http://localhost:5000
# Register a new account
# Set up TOTP authentication with QR code
# Test login flow with various risk scenarios
```

### Example Authentication Flow
1. **User Registration**: Create account with secure password
2. **MFA Setup**: Scan QR code with authenticator app (Google Authenticator, Authy)
3. **Login Attempt**: Enter username/password
4. **Risk Assessment**: System evaluates login risk factors
5. **MFA Challenge**: Enter TOTP code from authenticator app
6. **Session Creation**: Generate secure JWT session token
7. **Access Dashboard**: Navigate to protected resources

## 📊 Grading Rubric (100 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|---------|
| **MFA Implementation** | 25% | 25 points |
| **Session Management** | 25% | 25 points |
| **Risk Assessment** | 20% | 20 points |
| **Web Interface** | 20% | 20 points |
| **Security Practices** | 10% | 10 points |

### 5-Point Scale Criteria

**MFA Implementation (25 points)**
- **Excellent (25)**: Perfect TOTP implementation, backup codes, QR generation
- **Proficient (20)**: Good MFA functionality, minor implementation issues
- **Developing (15)**: Basic MFA works, some features missing
- **Needs Improvement (10)**: MFA partially functional, significant issues
- **Inadequate (5)**: MFA doesn't work properly or major security flaws
- **No Submission (0)**: Missing or no attempt

**Session Management (25 points)**
- **Excellent (25)**: Secure JWT implementation, proper validation, session protection
- **Proficient (20)**: Good session handling, minor security issues
- **Developing (15)**: Basic session management, some security gaps
- **Needs Improvement (10)**: Session management works but significant vulnerabilities
- **Inadequate (5)**: Poor session handling, major security flaws
- **No Submission (0)**: Missing or no attempt

**Risk Assessment (20 points)**
- **Excellent (20)**: Comprehensive risk factors, adaptive authentication
- **Proficient (16)**: Good risk assessment, most factors considered
- **Developing (12)**: Basic risk evaluation, limited factors
- **Needs Improvement (8)**: Simple risk assessment, few factors
- **Inadequate (4)**: Minimal or no risk assessment
- **No Submission (0)**: Missing or no attempt

**Web Interface (20 points)**
- **Excellent (20)**: All pages functional, good UX, proper error handling
- **Proficient (16)**: Most pages work well, good usability
- **Developing (12)**: Basic pages functional, adequate interface
- **Needs Improvement (8)**: Some pages work, poor usability
- **Inadequate (4)**: Major interface problems, broken functionality
- **No Submission (0)**: Missing or no attempt

**Security Practices (10 points)**
- **Excellent (10)**: Comprehensive security implementation, CSRF protection, input validation
- **Proficient (8)**: Good security practices, minor vulnerabilities
- **Developing (6)**: Basic security considerations
- **Needs Improvement (4)**: Limited security practices
- **Inadequate (2)**: Poor or no security considerations
- **No Submission (0)**: Missing or no attempt

### Grade Scale
- **90-100 points (A)**: Enterprise-ready MFA system
- **80-89 points (B)**: Good implementation, minor issues
- **70-79 points (C)**: Satisfactory, meets basic requirements
- **60-69 points (D)**: Below expectations, significant issues
- **Below 60 points (F)**: Unsatisfactory, major problems

## 🚀 Bonus Opportunities (+5 points each)

### 1. Biometric Authentication Simulation
Simulate fingerprint/face recognition:
```python
def simulate_biometric_auth(user_id, biometric_data):
    """Simulate biometric authentication with fuzzy matching"""
    # Implement template matching simulation
    # Add noise tolerance for realistic behavior
```

### 2. Push Notification MFA
Implement push-based authentication:
```python
def send_push_notification(user_id, device_token):
    """Send push notification for authentication approval"""
    # Generate authentication request
    # Send via push notification service
```

### 3. Advanced Risk Analytics
Add machine learning-style risk assessment:
```python
def ml_risk_assessment(user_behavior_data):
    """Use behavioral patterns for risk assessment"""
    # Analyze login patterns, typing speed, mouse movements
    # Generate risk score based on behavioral biometrics
```

## 📋 Submission Checklist

Before submitting, verify:

- [ ] **User registration and MFA setup work correctly**
- [ ] **TOTP authentication functions properly with authenticator apps**
- [ ] **Session management provides secure authentication state**
- [ ] **Risk assessment considers multiple factors**
- [ ] **All web pages render and function correctly**
- [ ] **Database operations handle errors gracefully**
- [ ] **Security measures protect against common attacks**
- [ ] **Code is well-structured and documented**
- [ ] **README.txt explains setup and security design**

### Testing Your MFA System
```bash
# Test complete authentication flow
1. Register new user account
2. Set up TOTP with QR code scanning
3. Log out and attempt login
4. Test TOTP verification
5. Verify dashboard access

# Test risk scenarios
1. Login from different IP addresses
2. Use different browsers/devices
3. Attempt login at unusual times
4. Test with incorrect TOTP codes

# Test security features
1. Verify password hashing strength
2. Test session timeout behavior
3. Confirm CSRF protection works
4. Validate input sanitization
```

## 📚 Resources and References

### Documentation
- **PyOTP Documentation**: https://pypi.org/project/pyotp/
- **JWT Specification**: https://tools.ietf.org/html/rfc7519
- **TOTP Algorithm**: https://tools.ietf.org/html/rfc6238

### Security Standards
- **NIST SP 800-63B Authentication**: https://pages.nist.gov/800-63-3/sp800-63b.html
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

### Example Implementation Structure
```python
# mfa_system.py - Main application
from flask import Flask, render_template, request, session, redirect
from auth_manager import AuthManager
from risk_engine import RiskEngine
from database import DatabaseManager

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Initialize components
db_manager = DatabaseManager('users.db')
auth_manager = AuthManager(db_manager.get_connection())
risk_engine = RiskEngine(db_manager.get_connection())

@app.route('/')
def index():
    return redirect('/login')

# Define all routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Registration logic
    pass

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Primary authentication
    pass

@app.route('/mfa-setup', methods=['GET', 'POST'])
def mfa_setup():
    # TOTP setup with QR code
    pass

@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    # Second factor verification
    pass

@app.route('/dashboard')
def dashboard():
    # Protected area
    pass

if __name__ == '__main__':
    db_manager.init_database()
    app.run(debug=True, port=5000)
```

## ❓ Frequently Asked Questions

**Q: Which authenticator apps should I test with?**  
A: Google Authenticator, Authy, and Microsoft Authenticator are good choices for testing TOTP compatibility.

**Q: How should I handle backup codes?**  
A: Generate 10-12 single-use backup codes, hash them before storage, and invalidate after use.

**Q: What constitutes a high-risk login?**  
A: New device, unusual location, off-hours access, recent failed attempts, or multiple risk factors combined.

**Q: How long should sessions last?**  
A: Consider 30 minutes for high-security applications, 24 hours for standard applications, with sliding expiration.

**Q: Should I implement remember device functionality?**  
A: This is bonus material - implement device tokens that reduce MFA requirements for trusted devices.

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

1. **Would I trust this MFA system to protect my own sensitive accounts?**
2. **Does the risk assessment meaningfully improve security?**
3. **Are sessions properly secured against hijacking?**
4. **Have I tested the TOTP implementation with real authenticator apps?**
5. **Does the system gracefully handle all error conditions?**

---

**Need Help?**
- Review the authentication tutorial materials
- Test your TOTP implementation with multiple authenticator apps
- Check Canvas discussions for common integration issues
- Attend office hours for security design review

**Good luck!** This assignment will give you hands-on experience with enterprise-grade authentication systems.