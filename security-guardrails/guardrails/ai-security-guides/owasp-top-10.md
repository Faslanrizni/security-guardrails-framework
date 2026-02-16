# OWASP Top 10 (2021) - Security Reference Guide

**Last Updated:** 2021 | **For AI-Generated Code**

This document provides a comprehensive reference for the OWASP Top 10 vulnerabilities, specifically tailored for developers using AI-assisted coding tools. Use this as a checklist when generating or reviewing code.

---

## Table of Contents

1. [A01:2021 - Broken Access Control](#a012021---broken-access-control)
2. [A02:2021 - Cryptographic Failures](#a022021---cryptographic-failures)
3. [A03:2021 - Injection](#a032021---injection)
4. [A04:2021 - Insecure Design](#a042021---insecure-design)
5. [A05:2021 - Security Misconfiguration](#a052021---security-misconfiguration)
6. [A06:2021 - Vulnerable and Outdated Components](#a062021---vulnerable-and-outdated-components)
7. [A07:2021 - Identification and Authentication Failures](#a072021---identification-and-authentication-failures)
8. [A08:2021 - Software and Data Integrity Failures](#a082021---software-and-data-integrity-failures)
9. [A09:2021 - Security Logging and Monitoring Failures](#a092021---security-logging-and-monitoring-failures)
10. [A10:2021 - Server-Side Request Forgery (SSRF)](#a102021---server-side-request-forgery-ssrf)

---

## A01:2021 - Broken Access Control

### Description
Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data.

### Common Vulnerabilities
- Bypassing access control checks by modifying the URL, internal application state, or HTML page
- Allowing viewing or editing someone else's account by providing its unique identifier (insecure direct object references)
- Accessing API with missing access controls for POST, PUT, and DELETE
- Elevation of privilege (acting as a user without being logged in, or acting as an admin when logged in as a user)
- Metadata manipulation, such as replaying or tampering with a JSON Web Token (JWT)
- CORS misconfiguration allows unauthorized API access
- Force browsing to authenticated pages as an unauthenticated user or privileged pages as a standard user

### AI Code Generation Requirements

**ALWAYS implement:**
```
✓ Validate user permissions on EVERY request (server-side)
✓ Deny by default (fail closed)
✓ Implement role-based access control (RBAC) or attribute-based access control (ABAC)
✓ Disable directory listing and ensure file metadata is not accessible
✓ Log access control failures and alert admins on repeated failures
✓ Invalidate JWT tokens on the server after logout
✓ Rate limit API to minimize harm from automated attacks
```

**NEVER do:**
```
✗ Rely on client-side access control checks only
✗ Allow direct object references without authorization (e.g., /user/1234)
✗ Trust user-supplied parameters for authorization decisions
✗ Use predictable identifiers (use UUIDs instead)
✗ Skip authorization checks in APIs
```

### Code Examples

** INSECURE (Direct Object Reference):**
```javascript
// User can access any order by changing the ID
app.get('/api/orders/:orderId', (req, res) => {
  const order = db.getOrder(req.params.orderId);
  res.json(order); // NO AUTHORIZATION CHECK!
});
```

** SECURE:**
```javascript
app.get('/api/orders/:orderId', authenticateUser, (req, res) => {
  const order = db.getOrder(req.params.orderId);
  
  // Verify the order belongs to the authenticated user
  if (!order || order.userId !== req.user.id) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  res.json(order);
});
```

** INSECURE (Missing Authorization in API):**
```python
@app.route('/api/users/<user_id>/delete', methods=['DELETE'])
def delete_user(user_id):
    # No check if current user is admin!
    db.delete_user(user_id)
    return {'success': True}
```

** SECURE:**
```python
@app.route('/api/users/<user_id>/delete', methods=['DELETE'])
@require_role('admin')  # Decorator enforces admin role
def delete_user(user_id):
    # Additional check: admins can't delete themselves
    if user_id == session['user_id']:
        return {'error': 'Cannot delete own account'}, 403
    
    db.delete_user(user_id)
    return {'success': True}
```

### Testing Checklist
- [ ] Can users access resources they don't own by changing IDs?
- [ ] Are administrative functions protected from regular users?
- [ ] Do all API endpoints enforce authorization?
- [ ] Are access control failures logged?
- [ ] Is CORS configured restrictively?

---

## A02:2021 - Cryptographic Failures

### Description
Previously known as "Sensitive Data Exposure." Focuses on failures related to cryptography (or lack thereof), which often lead to exposure of sensitive data.

### Common Vulnerabilities
- Transmitting data in clear text (HTTP, FTP, SMTP)
- Using old or weak cryptographic algorithms
- Using default crypto keys or weak/reused passwords
- Not enforcing encryption (missing HSTS headers)
- Not validating server certificates and trust chains
- Using deprecated hash functions (MD5, SHA1) for passwords
- Lack of proper key management

### AI Code Generation Requirements

**ALWAYS implement:**
```
✓ Use HTTPS/TLS for all transmissions
✓ Encrypt sensitive data at rest using AES-256 or stronger
✓ Use strong, industry-standard algorithms (bcrypt, Argon2, scrypt for passwords)
✓ Use proper key management (rotate keys, store in vault)
✓ Implement perfect forward secrecy (PFS)
✓ Disable caching for sensitive data
✓ Use HSTS headers to enforce HTTPS
✓ Apply appropriate encryption based on data classification
```

**NEVER do:**
```
✗ Store passwords in plaintext or with weak hashing (MD5, SHA1)
✗ Use deprecated TLS versions (< TLS 1.2)
✗ Hardcode encryption keys in source code
✗ Use custom/homegrown cryptographic algorithms
✗ Transmit sensitive data over unencrypted connections
✗ Store credit card data unnecessarily (use tokenization)
```

### Code Examples

**❌ INSECURE (Weak Password Hashing):**
```javascript
const crypto = require('crypto');

function hashPassword(password) {
  // MD5 is cryptographically broken!
  return crypto.createHash('md5').update(password).digest('hex');
}
```

**✅ SECURE:**
```javascript
const bcrypt = require('bcrypt');

async function hashPassword(password) {
  const saltRounds = 12; // Cost factor
  const hash = await bcrypt.hash(password, saltRounds);
  return hash;
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}
```

**❌ INSECURE (Hardcoded Encryption Key):**
```python
from Crypto.Cipher import AES

# NEVER hardcode keys!
KEY = b'this_is_a_secret'

def encrypt_data(data):
    cipher = AES.new(KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext
```

**✅ SECURE:**
```python
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_data(data, key):
    """
    Encrypt data using AES-256-GCM
    Key should be retrieved from secure key management service
    """
    # Generate random nonce
    nonce = get_random_bytes(12)
    
    # Create cipher with GCM mode (authenticated encryption)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # Return nonce + tag + ciphertext for later decryption
    return nonce + tag + ciphertext

def get_encryption_key():
    """Retrieve key from environment variable or key vault"""
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        raise ValueError("ENCRYPTION_KEY not set")
    return bytes.fromhex(key)
```

**✅ SECURE (Enforce HTTPS):**
```javascript
// Express.js middleware to enforce HTTPS
app.use((req, res, next) => {
  if (req.header('x-forwarded-proto') !== 'https') {
    return res.redirect(`https://${req.header('host')}${req.url}`);
  }
  next();
});

// Add HSTS header
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
```

### Testing Checklist
- [ ] Is all sensitive data encrypted in transit (TLS 1.2+)?
- [ ] Is sensitive data encrypted at rest?
- [ ] Are passwords hashed with strong algorithms (bcrypt, Argon2)?
- [ ] Are encryption keys stored securely (not in code)?
- [ ] Is HSTS header present?
- [ ] Are deprecated crypto algorithms avoided?

---

## A03:2021 - Injection

### Description
An application is vulnerable to injection attacks when user-supplied data is not validated, filtered, or sanitized. Injection flaws occur when hostile data is sent to an interpreter as part of a command or query.

### Common Vulnerabilities
- SQL, NoSQL, OS command, ORM, LDAP injection
- Hostile data directly used in dynamic queries, commands, or stored procedures
- Dynamic queries, commands, or stored procedures that contain untrusted data
- Hostile data used in ORM search parameters to extract sensitive records
- Hostile data directly used or concatenated in SQL or command

### AI Code Generation Requirements

**ALWAYS implement:**
```
✓ Use parameterized queries (prepared statements) for SQL
✓ Use ORM frameworks with built-in protections
✓ Validate and sanitize ALL user inputs (whitelist approach)
✓ Escape special characters in user input
✓ Use least privilege for database connections
✓ Implement input validation on server-side
✓ Use stored procedures (with parameterization)
✓ Apply context-specific encoding when outputting user data
```

**NEVER do:**
```
✗ Concatenate user input directly into queries
✗ Use string interpolation for SQL queries
✗ Trust client-side validation alone
✗ Use eval() or similar functions with user input
✗ Execute OS commands with user-supplied data
✗ Disable ORM query sanitization
```

### Code Examples

**❌ INSECURE (SQL Injection):**
```python
# NEVER concatenate user input into SQL!
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    # If username = "admin' OR '1'='1", this returns all users!
    return db.execute(query)
```

**✅ SECURE:**
```python
def get_user(username):
    # Use parameterized query
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (username,))

# Or with named parameters (even better)
def get_user_safe(username):
    query = "SELECT * FROM users WHERE username = :username"
    return db.execute(query, {'username': username})
```

**❌ INSECURE (NoSQL Injection - MongoDB):**
```javascript
// User input: { "username": {"$ne": null}, "password": {"$ne": null} }
app.post('/login', (req, res) => {
  db.collection('users').findOne({
    username: req.body.username, // Vulnerable!
    password: req.body.password
  });
});
```

**✅ SECURE:**
```javascript
app.post('/login', (req, res) => {
  // Validate input types
  const username = String(req.body.username);
  const password = String(req.body.password);
  
  // Additional validation
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
  }
  
  db.collection('users').findOne({
    username: username,
    password: hashPassword(password)
  });
});
```

**❌ INSECURE (Command Injection):**
```javascript
const { exec } = require('child_process');

app.get('/convert', (req, res) => {
  const filename = req.query.file;
  // If filename = "file.pdf; rm -rf /", this is catastrophic!
  exec(`convert ${filename} output.png`, (error, stdout) => {
    res.send(stdout);
  });
});
```

**✅ SECURE:**
```javascript
const { execFile } = require('child_process');
const path = require('path');

app.get('/convert', (req, res) => {
  const filename = req.query.file;
  
  // Validate filename
  if (!filename || !/^[a-zA-Z0-9_\-\.]+$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // Use execFile (doesn't invoke shell) with array arguments
  execFile('convert', [filename, 'output.png'], (error, stdout) => {
    if (error) {
      return res.status(500).json({ error: 'Conversion failed' });
    }
    res.send(stdout);
  });
});
```

**✅ SECURE (ORM Usage):**
```python
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    email = Column(String)

# Using ORM - automatically parameterized
def get_user_by_username(username):
    session = Session()
    # This is safe - SQLAlchemy parameterizes automatically
    user = session.query(User).filter(User.username == username).first()
    return user
```

### Testing Checklist
- [ ] Are all SQL queries using prepared statements?
- [ ] Is user input validated and sanitized?
- [ ] Are ORM frameworks used correctly?
- [ ] Are OS commands avoided or properly sanitized?
- [ ] Is input validation performed server-side?
- [ ] Are special characters escaped in queries?

---

## A04:2021 - Insecure Design

### Description
A new category for 2021 focusing on risks related to design and architectural flaws. Requires more use of threat modeling, secure design patterns, and reference architectures.

### Common Vulnerabilities
- Missing or ineffective security controls
- Lack of threat modeling during design phase
- Using insecure design patterns
- Failure to segregate tenants in multi-tenant architecture
- Missing rate limiting on business logic
- Lack of defense in depth
- Hardcoded security decisions

### AI Code Generation Requirements

**ALWAYS implement:**
```
✓ Apply principle of least privilege
✓ Implement defense in depth (multiple security layers)
✓ Use secure design patterns (fail secure, complete mediation)
✓ Segregate duties and enforce separation of concerns
✓ Limit resource consumption per user/tenant
✓ Use security frameworks and libraries
✓ Validate business logic constraints
✓ Implement proper session management
```

**NEVER do:**
```
✗ Rely on single security control
✗ Skip threat modeling
✗ Implement security as an afterthought
✗ Use insecure defaults
✗ Trust user input without validation
✗ Allow unlimited resource consumption
```

### Design Patterns

**✅ SECURE (Rate Limiting):**
```javascript
const rateLimit = require('express-rate-limit');

// Limit password reset attempts
const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // Limit each IP to 3 requests per windowMs
  message: 'Too many password reset attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/password-reset', resetLimiter, async (req, res) => {
  // Password reset logic
});

// Different limits for different endpoints
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true, // Don't count successful logins
});

app.post('/api/login', loginLimiter, async (req, res) => {
  // Login logic
});
```

**✅ SECURE (Fail Secure - Circuit Breaker):**
```python
from circuitbreaker import circuit

@circuit(failure_threshold=5, recovery_timeout=60)
def call_external_api(data):
    """
    If external API fails 5 times, circuit opens
    and requests fail fast for 60 seconds
    """
    response = requests.post('https://api.example.com/process', json=data)
    
    if response.status_code != 200:
        raise Exception('API call failed')
    
    return response.json()

def process_user_data(user_data):
    try:
        result = call_external_api(user_data)
        return result
    except Exception as e:
        # Fail secure: deny operation if external check fails
        logger.error(f'External API failed: {e}')
        return {'error': 'Service temporarily unavailable'}, 503
```

**✅ SECURE (Multi-Tenant Isolation):**
```javascript
// Ensure tenant isolation in all queries
class TenantAwareRepository {
  constructor(tenantId) {
    if (!tenantId) {
      throw new Error('Tenant ID required');
    }
    this.tenantId = tenantId;
  }
  
  async findById(id) {
    // ALWAYS include tenant_id in queries
    return db.query(
      'SELECT * FROM resources WHERE id = ? AND tenant_id = ?',
      [id, this.tenantId]
    );
  }
  
  async create(data) {
    // Automatically inject tenant_id
    return db.query(
      'INSERT INTO resources (data, tenant_id) VALUES (?, ?)',
      [data, this.tenantId]
    );
  }
}

// Middleware to extract tenant from JWT
app.use((req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  req.tenantId = decoded.tenantId;
  req.repo = new TenantAwareRepository(req.tenantId);
  next();
});
```

**✅ SECURE (Resource Limits):**
```python
from functools import wraps
import time

def resource_limit(max_size_mb=10, max_time_seconds=30):
    """Decorator to limit resource consumption"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check input size
            if hasattr(args[0], '__len__'):
                size_mb = len(str(args[0])) / (1024 * 1024)
                if size_mb > max_size_mb:
                    raise ValueError(f'Input too large: {size_mb}MB > {max_size_mb}MB')
            
            # Set timeout
            import signal
            def timeout_handler(signum, frame):
                raise TimeoutError('Operation timed out')
            
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(max_time_seconds)
            
            try:
                result = func(*args, **kwargs)
                signal.alarm(0)  # Cancel alarm
                return result
            except TimeoutError:
                raise ValueError('Operation took too long')
        
        return wrapper
    return decorator

@resource_limit(max_size_mb=5, max_time_seconds=10)
def process_user_file(file_content):
    # Process file with automatic resource limits
    return analyze(file_content)
```

### Testing Checklist
- [ ] Is threat modeling performed for new features?
- [ ] Are rate limits implemented on sensitive operations?
- [ ] Is there defense in depth (multiple security layers)?
- [ ] Are resource limits enforced per user/tenant?
- [ ] Is tenant isolation properly implemented?
- [ ] Do security controls fail securely?

---

## A05:2021 - Security Misconfiguration

### Description
Security misconfiguration can happen at any level of an application stack, including network services, platform, web server, database, frameworks, custom code, and pre-installed virtual machines, containers, or storage.

### Common Vulnerabilities
- Missing appropriate security hardening across any part of the application stack
- Improperly configured permissions on cloud services
- Unnecessary features enabled or installed (e.g., unnecessary ports, services, pages, accounts, or privileges)
- Default accounts and their passwords still enabled and unchanged
- Error handling reveals stack traces or other overly informative error messages
- Latest security features disabled or not configured securely
- Security settings in application servers, frameworks, libraries, databases not set to secure values
- Server does not send security headers or directives, or they are not set to secure values

### AI Code Generation Requirements

**ALWAYS implement:**
```
✓ Disable unnecessary features, components, documentation
✓ Remove or change default accounts and passwords
✓ Implement proper error handling (generic messages to users)
✓ Set security headers (CSP, HSTS, X-Frame-Options, etc.)
✓ Keep all components updated and patched
✓ Use secure configurations for all environments
✓ Implement least privilege for all accounts
✓ Segment application architecture
```

**NEVER do:**
```
✗ Use default credentials
✗ Expose stack traces to users
✗ Run with unnecessary privileges
✗ Use development/debug modes in production
✗ Leave sample/test code in production
✗ Expose detailed error messages
✗ Run outdated software versions
```

### Code Examples

**❌ INSECURE (Exposing Stack Traces):**
```javascript
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await db.getUser(req.params.id);
    res.json(user);
  } catch (error) {
    // NEVER expose stack traces!
    res.status(500).json({ 
      error: error.message,
      stack: error.stack // Reveals internal structure!
    });
  }
});
```

**✅ SECURE:**
```javascript
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await db.getUser(req.params.id);
    res.json(user);
  } catch (error) {
    // Log full error server-side
    logger.error('Error fetching user:', {
      userId: req.params.id,
      error: error.message,
      stack: error.stack
    });
    
    // Return generic message to user
    res.status(500).json({ 
      error: 'An error occurred while processing your request'
    });
  }
});
```

**✅ SECURE (Security Headers):**
```javascript
const helmet = require('helmet');

app.use(helmet()); // Applies multiple security headers

// Or configure individually
app.use((req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Enable XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Content Security Policy
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
  
  // HSTS
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  
  // Referrer Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Permissions Policy
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  next();
});
```

**✅ SECURE (Environment-Specific Configuration):**
```python
import os

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY must be set")
    
    # Secure defaults
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # Allow HTTP in dev

class ProductionConfig(Config):
    DEBUG = False  # NEVER enable debug in production
    SESSION_COOKIE_SECURE = True
    
    # Additional production hardening
    PREFERRED_URL_SCHEME = 'https'
    
    # Ensure all sensitive config comes from environment
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL must be set in production")

# Load config based on environment
env = os.environ.get('FLASK_ENV', 'production')
if env == 'development':
    config = DevelopmentConfig()
elif env == 'production':
    config = ProductionConfig()
else:
    raise ValueError(f"Unknown environment: {env}")
```

**❌ INSECURE (Debug Mode in Production):**
```python
# NEVER do this!
app.run(debug=True, host='0.0.0.0', port=5000)
```

**✅ SECURE:**
```python
if __name__ == '__main__':
    # Use environment variable
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    if debug_mode:
        print("WARNING: Running in debug mode!")
    
    app.run(
        debug=debug_mode,
        host='127.0.0.1',  # Don't bind to all interfaces
        port=5000
    )
```

**✅ SECURE (CORS Configuration):**
```javascript
const cors = require('cors');

// ❌ INSECURE: Allow all origins
// app.use(cors());

// ✅ SECURE: Restrictive CORS
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://example.com',
      'https://app.example.com'
    ];
    
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
```

### Testing Checklist
- [ ] Are all security headers properly configured?
- [ ] Are default credentials changed?
- [ ] Is debug mode disabled in production?
- [ ] Are unnecessary features/ports disabled?
- [ ] Are error messages generic (no stack traces)?
- [ ] Is the application stack properly hardened?
- [ ] Are all components up to date?

---

## A06:2021 - Vulnerable and Outdated Components

### Description
Using components with known vulnerabilities is a widespread issue. If you are unaware of all the components you use (both client-side and server-side), you are likely at risk.

### Common Vulnerabilities
- Not knowing versions of all components (client and server-side)
- Software is vulnerable, unsupported, or out of date (OS, web/application server, DBMS, applications, APIs, runtime environments, libraries)
- Not scanning for vulnerabilities regularly
- Not fixing or upgrading the underlying platform, frameworks, and dependencies in a timely manner
- Developers not testing the compatibility of updated, upgraded, or patched libraries
- Not securing component configurations

### AI Code Generation Requirements

**ALWAYS implement:**
```
✓ Use only company-approved dependencies
✓ Monitor for security updates and CVEs
✓ Remove unused dependencies and features
✓ Use dependency scanning tools (Dependabot, Snyk, etc.)
✓ Pin dependency versions for reproducibility
✓ Obtain components from official sources over secure links
✓ Monitor for unmaintained libraries
✓ Keep inventory of all components and versions
```

**NEVER do:**
```
✗ Use deprecated or unmaintained libraries
✗ Install dependencies from untrusted sources
✗ Ignore security warnings in package managers
✗ Use wildcard version specifiers in production
✗ Skip dependency updates indefinitely
✗ Include unnecessary dependencies
```

### Dependency Management Examples

**✅ SECURE (package.json - Node.js):**
```json
{
  "name": "secure-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.2",
    "helmet": "7.1.0",
    "bcrypt": "5.1.1"
  },
  "devDependencies": {
    "eslint": "8.54.0"
  },
  "scripts": {
    "audit": "npm audit",
    "audit-fix": "npm audit fix",
    "check-updates": "npx npm-check-updates"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=9.0.0"
  }
}
```

**✅ SECURE (requirements.txt - Python):**
```python
# Pin exact versions for reproducibility
Django==4.2.7
psycopg2-binary==2.9.9
cryptography==41.0.7
requests==2.31.0

# Use hashes for additional security (pip-compile --generate-hashes)
# certifi==2023.11.17 \
#     --hash=sha256:e036ab49d5b79556f99cfc2d9320b34cfbe5be05c5871b51de9329f0603b0474
```

**✅ SECURE (Automated Scanning):**
```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    # Run weekly
    - cron: '0 0 * * 0'

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run npm audit
        run: npm audit --audit-level=moderate
      
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
```

**✅ SECURE (Dependency Review):**
```bash
# Before installing new dependency:

# 1. Check last update date
npm view package-name time

# 2. Check for known vulnerabilities
npm audit
snyk test

# 3. Check license compatibility
npm view package-name license

# 4. Check GitHub stars and activity
# Visit: https://github.com/author/package-name

# 5. Review dependencies
npm view package-name dependencies
```

**✅ SECURE (Go Modules):**
```go
// go.mod
module github.com/company/secure-app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/golang-jwt/jwt/v5 v5.2.0
    golang.org/x/crypto v0.17.0
)

// Use go mod tidy to remove unused dependencies
// Use go list -m -u all to check for updates
// Use govulncheck to scan for vulnerabilities
```

**Update Strategy:**
```bash
#!/bin/bash
# update-dependencies.sh

echo "Checking for outdated dependencies..."

# Node.js
npx npm-check-updates -u
npm install
npm audit fix

# Python
pip list --outdated
pip install -U pip-review
pip-review --auto

# Run tests after updates
npm test
python -m pytest

echo "Review changes and commit if tests pass"
```

### Testing Checklist
- [ ] Are all dependencies at their latest secure versions?
- [ ] Are dependency scans run regularly (CI/CD)?
- [ ] Are unused dependencies removed?
- [ ] Is there a process for responding to security advisories?
- [ ] Are component licenses compatible with project?
- [ ] Are dependencies from trusted sources only?

---

## A07:2021 - Identification and Authentication Failures

### Description
Previously known as "Broken Authentication." Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.

### Common Vulnerabilities
- Permits automated attacks such as credential stuffing
- Permits brute force or other automated attacks
- Permits default, weak, or well-known passwords
- Uses weak or ineffective credential recovery and forgot-password processes
- Uses plain text, encrypted, or weakly hashed passwords
- Has missing or ineffective multi-factor authentication
- Exposes session identifier in the URL
- Reuses session identifier after successful login
- Does not properly invalidate sessions during logout or period of inactivity

### AI Code Generation Requirements

**ALWAYS implement:**
```
✓ Implement multi-factor authentication (MFA) where possible
✓ Use strong password requirements (length > complexity)
✓ Implement secure password recovery mechanisms
✓ Use bcrypt, Argon2, or scrypt for password hashing
✓ Protect against brute force with rate limiting
✓ Implement account lockout after failed attempts
✓ Generate new session ID after login
✓ Invalidate sessions on logout
✓ Use secure, random session identifiers
✓ Set appropriate session timeouts
```

**NEVER do:**
```
✗ Store passwords in plaintext or with weak hashing
✗ Allow weak passwords
✗ Expose session IDs in URLs
✗ Use predictable session identifiers
✗ Implement insecure password recovery (security questions)
✗ Skip rate limiting on authentication endpoints
✗ Allow unlimited login attempts
```

### Code Examples

**❌ INSECURE (No Rate Limiting):**
```javascript
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.getUserByUsername(username);
  
  if (user && await bcrypt.compare(password, user.passwordHash)) {
    req.session.userId = user.id;
    res.json({ success: true });
  } else {
    // Attacker can try unlimited passwords!
    res.status(401).json({ error: 'Invalid credentials' });
  }
});
```

**✅ SECURE:**
```javascript
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

// Rate limiter: max 5 attempts per 15 minutes
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: 'Too many login attempts, please try again later'
});

// Speed limiter: progressively delay responses
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 2,
  delayMs: 500
});

app.post('/login', loginLimiter, speedLimiter, async (req, res) => {
  const { username, password } = req.body;
  
  // Validate input
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }
  
  const user = await db.getUserByUsername(username);
  
  // Use constant-time comparison to prevent timing attacks
  if (!user) {
    // Still hash to prevent timing attacks revealing valid usernames
    await bcrypt.hash(password, 10);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Check if account is locked
  if (user.lockedUntil && user.lockedUntil > Date.now()) {
    return res.status(423).json({ 
      error: 'Account locked due to too many failed attempts' 
    });
  }
  
  const validPassword = await bcrypt.compare(password, user.passwordHash);
  
  if (validPassword) {
    // Reset failed attempts
    await db.updateUser(user.id, { 
      failedAttempts: 0, 
      lockedUntil: null 
    });
    
    // Regenerate session ID after login
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: 'Login failed' });
      }
      
      req.session.userId = user.id;
      req.session.loginTime = Date.now();
      
      res.json({ success: true });
    });
  } else {
    // Increment failed attempts
    const failedAttempts = (user.failedAttempts || 0) + 1;
    const updates = { failedAttempts };
    
    // Lock account after 5 failed attempts
    if (failedAttempts >= 5) {
      updates.lockedUntil = Date.now() + (30 * 60 * 1000); // 30 minutes
    }
    
    await db.updateUser(user.id, updates);
    
    res.status(401).json({ error: 'Invalid credentials' });
  }
});
```

**✅ SECURE (Session Management):**
```javascript
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');

const redisClient = createClient({
  url: process.env.REDIS_URL,
  legacyMode: true
});
redisClient.connect();

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // Don't use default 'connect.sid'
  cookie: {
    secure: true, // HTTPS only
    httpOnly: true, // No JavaScript access
    sameSite: 'lax', // CSRF protection
    maxAge: 30 * 60 * 1000 // 30 minutes
  }
}));

// Session timeout middleware
app.use((req, res, next) => {
  if (req.session.userId) {
    const now = Date.now();
    const loginTime = req.session.loginTime || now;
    const sessionAge = now - loginTime;
    
    // Force re-authentication after 8 hours
    if (sessionAge > 8 * 60 * 60 * 1000) {
      req.session.destroy();
      return res.status(401).json({ error: 'Session expired' });
    }
    
    // Update last activity
    req.session.lastActivity = now;
  }
  next();
});

// Logout endpoint
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('sessionId');
    res.json({ success: true });
  });
});
```

**✅ SECURE (Password Requirements):**
```python
import re
from zxcvbn import zxcvbn

def validate_password(password, username=None, email=None):
    """
    Validate password strength
    Focus on length > complexity
    """
    errors = []
    
    # Minimum length
    if len(password) < 12:
        errors.append('Password must be at least 12 characters')
    
    # Maximum length (prevent DoS)
    if len(password) > 128:
        errors.append('Password must be less than 128 characters')
    
    # Check against common passwords using zxcvbn
    result = zxcvbn(password, user_inputs=[username, email] if username or email else [])
    
    if result['score'] < 3:  # Score 0-4, need at least 3
        errors.append(f'Password is too weak: {result["feedback"]["warning"]}')
        if result['feedback']['suggestions']:
            errors.extend(result['feedback']['suggestions'])
    
    # Check for username/email in password
    if username and username.lower() in password.lower():
        errors.append('Password must not contain username')
    
    if email and email.split('@')[0].lower() in password.lower():
        errors.append('Password must not contain email')
    
    return len(errors) == 0, errors

# Usage
valid, errors = validate_password('MyP@ssw0rd123', 'john', 'john@example.com')
if not valid:
    return {'error': errors}, 400
```

**✅ SECURE (Password Reset):**
```python
import secrets
from datetime import datetime, timedelta

def initiate_password_reset(email):
    """Secure password reset flow"""
    user = db.get_user_by_email(email)
    
    # Always return success to prevent email enumeration
    if not user:
        logger.info(f'Password reset requested for non-existent email: {email}')
        return {'success': True}
    
    # Generate cryptographically secure token
    token = secrets.token_urlsafe(32)
    
    # Store hashed token in database
    hashed_token = bcrypt.hashpw(token.encode(), bcrypt.gensalt())
    
    db.update_user(user.id, {
        'reset_token': hashed_token,
        'reset_token_expires': datetime.utcnow() + timedelta(hours=1)
    })
    
    # Send email with token (use HTTPS link)
    reset_link = f'https://example.com/reset-password?token={token}'
    send_email(user.email, 'Password Reset', f'Click here: {reset_link}')
    
    return {'success': True}

def reset_password(token, new_password):
    """Complete password reset"""
    # Find user by checking token against all hashed tokens
    users = db.get_users_with_reset_tokens()
    
    user = None
    for u in users:
        if bcrypt.checkpw(token.encode(), u.reset_token.encode()):
            user = u
            break
    
    if not user:
        return {'error': 'Invalid or expired reset token'}, 400
    
    # Check expiration
    if datetime.utcnow() > user.reset_token_expires:
        return {'error': 'Reset token has expired'}, 400
    
    # Validate new password
    valid, errors = validate_password(new_password, user.username, user.email)
    if not valid:
        return {'error': errors}, 400
    
    # Update password and clear reset token
    password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    
    db.update_user(user.id, {
        'password_hash': password_hash,
        'reset_token': None,
        'reset_token_expires': None,
        'failed_attempts': 0,
        'locked_until': None
    })
    
    # Invalidate all existing sessions
    db.delete_user_sessions(user.id)
    
    # Log the password change
    logger.info(f'Password reset completed for user: {user.id}')
    
    return {'success': True}
```

**✅ SECURE (Multi-Factor Authentication):**
```python
import pyotp
import qrcode
from io import BytesIO
import base64

def setup_mfa(user_id):
    """Initialize MFA for user"""
    # Generate secret
    secret = pyotp.random_base32()
    
    # Store secret (encrypted at rest)
    db.update_user(user_id, {'mfa_secret': secret})
    
    # Generate provisioning URI for QR code
    user = db.get_user(user_id)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='YourApp'
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_code = base64.b64encode(buffer.getvalue()).decode()
    
    return {
        'secret': secret,
        'qr_code': qr_code
    }

def verify_mfa(user_id, code):
    """Verify MFA code"""
    user = db.get_user(user_id)
    
    if not user.mfa_secret:
        return False
    
    totp = pyotp.TOTP(user.mfa_secret)
    
    # valid_window allows for clock drift (±30 seconds)
    return totp.verify(code, valid_window=1)

# In login flow:
@app.post('/login')
def login(username, password):
    # ... password verification ...
    
    if user.mfa_enabled:
        # Don't create full session yet
        temp_token = secrets.token_urlsafe(32)
        cache.set(f'mfa_pending:{temp_token}', user.id, expire=300)
        
        return {
            'mfa_required': True,
            'temp_token': temp_token
        }
    
    # ... create session ...

@app.post('/verify-mfa')
def verify_mfa_login(temp_token, mfa_code):
    user_id = cache.get(f'mfa_pending:{temp_token}')
    
    if not user_id:
        return {'error': 'Invalid or expired token'}, 400
    
    if verify_mfa(user_id, mfa_code):
        cache.delete(f'mfa_pending:{temp_token}')
        # Create full session
        session['user_id'] = user_id
        return {'success': True}
    
    return {'error': 'Invalid MFA code'}, 401
```

### Testing Checklist
- [ ] Is rate limiting implemented on authentication endpoints?
- [ ] Are passwords hashed with strong algorithms?
- [ ] Is account lockout implemented after failed attempts?
- [ ] Are session IDs regenerated after login?
- [ ] Are sessions properly invalidated on logout?
- [ ] Is MFA available for sensitive accounts?
- [ ] Are password requirements enforced?
- [ ] Is the password reset process secure?

---

## A08:2021 - Software and Data Integrity Failures

### Description
A new category for 2021 focusing on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. Code and infrastructure that does not protect against integrity violations is vulnerable.

### Common Vulnerabilities
- Applications rely on plugins, libraries, or modules from untrusted sources
- Insecure CI/CD pipeline allows insertion of malicious code
- Auto-update functionality without sufficient integrity verification
- Objects or data encoded or serialized into structure that attacker can see and modify
- Using insecure deserialization
- No code signing or integrity verification

### AI Code Generation Requirements

**ALWAYS implement:**
```
✓ Use digital signatures to verify software updates
✓ Validate integrity of dependencies (checksums, signatures)
✓ Use trusted repositories and registries
✓ Implement code signing for deployments
✓ Use safe deserialization practices
✓ Verify data integrity with checksums/hashes
✓ Implement CI/CD pipeline security
✓ Use Content Security Policy for CDN resources
```

**NEVER do:**
```
✗ Use insecure deserialization (pickle, Java serialization)
✗ Auto-update without verification
✗ Trust unsigned code or data
✗ Skip integrity checks on downloads
✗ Use CDN resources without SRI
✗ Allow untrusted data in deserialization
```

### Code Examples

**❌ INSECURE (Insecure Deserialization - Python):**
```python
import pickle

# NEVER use pickle with untrusted data!
def load_user_data(data):
    # Attacker can execute arbitrary code!
    user = pickle.loads(data)
    return user
```

**✅ SECURE:**
```python
import json
from typing import Dict, Any

def load_user_data(data: str) -> Dict[str, Any]:
    """Use JSON for safe deserialization"""
    try:
        # JSON is safe - only deserializes primitives
        user = json.loads(data)
        
        # Validate structure
        required_fields = ['id', 'username', 'email']
        for field in required_fields:
            if field not in user:
                raise ValueError(f'Missing required field: {field}')
        
        # Validate types
        if not isinstance(user['id'], int):
            raise ValueError('Invalid user ID type')
        
        return user
    except json.JSONDecodeError as e:
        raise ValueError(f'Invalid JSON: {e}')

# If you must use pickle (internal data only):
import hmac
import hashlib

def secure_pickle_loads(data: bytes, secret_key: bytes) -> Any:
    """Pickle with HMAC verification for internal use only"""
    # Separate signature and data
    signature = data[:32]
    pickled_data = data[32:]
    
    # Verify signature
    expected_sig = hmac.new(secret_key, pickled_data, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError('Invalid signature - data may be tampered')
    
    return pickle.loads(pickled_data)
```

**✅ SECURE (Subresource Integrity - CDN):**
```html
<!-- ❌ INSECURE: No integrity check -->
<script src="https://cdn.example.com/library.js"></script>

<!-- ✅ SECURE: SRI ensures file hasn't been tampered with -->
<script 
  src="https://cdn.example.com/library.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/ux43i3jF/a"
  crossorigin="anonymous">
</script>

<!-- Generate SRI hash: -->
<!-- curl -s https://cdn.example.com/library.js | openssl dgst -sha384 -binary | openssl base64 -A -->
```

**✅ SECURE (Dependency Integrity):**
```json
// package-lock.json (Node.js) - automatically includes integrity hashes
{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ==",
      "dependencies": {
        "accepts": "~1.3.8"
      }
    }
  }
}
```

**✅ SECURE (File Upload Integrity):**
```python
import hashlib
from werkzeug.utils import secure_filename

def save_upload(file, expected_hash=None):
    """Save uploaded file with integrity check"""
    filename = secure_filename(file.filename)
    
    # Read file content
    content = file.read()
    
    # Calculate hash
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Verify integrity if hash provided
    if expected_hash and file_hash != expected_hash:
        raise ValueError('File integrity check failed - hash mismatch')
    
    # Save file
    path = os.path.join(UPLOAD_FOLDER, filename)
    with open(path, 'wb') as f:
        f.write(content)
    
    # Return file path and hash for verification
    return {
        'path': path,
        'hash': file_hash,
        'algorithm': 'sha256'
    }
```

**✅ SECURE (CI/CD Pipeline Security):**
```yaml
# .github/workflows/deploy.yml
name: Secure Deploy

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    # Use specific commit SHA, not tags (tags can be moved)
    container: 
      image: node:18@sha256:a6385a6bb2fdcb7c48fc871e35e32af8daaa82c518e69a0c2a8bdb93c6e5d2d7
    
    steps:
      - uses: actions/checkout@v3
      
      # Verify dependencies haven't been tampered with
      - name: Verify lock file
        run: |
          npm ci
          npm audit --audit-level=moderate
      
      # Sign artifacts
      - name: Sign build artifacts
        run: |
          # Build application
          npm run build
          
          # Create checksum
          sha256sum dist/* > dist/checksums.txt
          
          # Sign with GPG (key stored in secrets)
          echo "${{ secrets.GPG_PRIVATE_KEY }}" | gpg --import
          gpg --armor --detach-sign dist/checksums.txt
      
      # Deploy with verification
      - name: Deploy
        run: |
          # Upload to server
          scp -r dist/* deploy@server:/var/www/app/
          
          # Verify on server
          ssh deploy@server 'cd /var/www/app && sha256sum -c checksums.txt'
```

**✅ SECURE (Code Signing Verification):**
```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def verify_update(update_file, signature_file, public_key_file):
    """Verify software update before installation"""
    # Load public key
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    # Read update file
    with open(update_file, 'rb') as f:
        update_data = f.read()
    
    # Read signature
    with open(signature_file, 'rb') as f:
        signature = f.read()
    
    # Verify signature
    try:
        public_key.verify(
            signature,
            update_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        logger.error('Update signature verification failed!')
        return False

# Before applying update
if not verify_update('update.zip', 'update.zip.sig', 'vendor_public_key.pem'):
    raise ValueError('Update verification failed - signature invalid')

# Only install if verification succeeds
install_update('update.zip')
```

**✅ SECURE (Safe Deserialization Patterns):**
```javascript
// ❌ INSECURE: eval with user input
function deserialize(data) {
  return eval('(' + data + ')'); // NEVER DO THIS!
}

// ✅ SECURE: JSON.parse with validation
function deserialize(data) {
  // Parse JSON safely
  const obj = JSON.parse(data);
  
  // Validate structure with schema
  const Ajv = require('ajv');
  const ajv = new Ajv();
  
  const schema = {
    type: 'object',
    properties: {
      id: { type: 'number' },
      name: { type: 'string' },
      email: { type: 'string', format: 'email' }
    },
    required: ['id', 'name', 'email'],
    additionalProperties: false
  };
  
  const validate = ajv.compile(schema);
  
  if (!validate(obj)) {
    throw new Error('Invalid data structure: ' + JSON.stringify(validate.errors));
  }
  
  return obj;
}
```

### Testing Checklist
- [ ] Are software updates verified before installation?
- [ ] Are dependencies checked for integrity (hashes)?
- [ ] Is deserialization using safe formats (JSON)?
- [ ] Is the CI/CD pipeline secured?
- [ ] Are CDN resources using SRI?
- [ ] Is code signing implemented for releases?
- [ ] Are file uploads verified for integrity?

---

## A09:2021 - Security Logging and Monitoring Failures

### Description
Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs any time security logging and monitoring are insufficient.

### Common Vulnerabilities
- Auditable events (logins, failed logins, high-value transactions) not logged
- Warnings and errors generate no, inadequate, or unclear log messages
- Logs of applications and APIs not monitored for suspicious activity
- Logs only stored locally
- Appropriate alerting thresholds and response escalation processes not in place
- Penetration testing and scans by dynamic application security testing (DAST) tools do not trigger alerts
- Application unable to detect, escalate, or alert for active attacks in real-time or near real-time

### AI Code Generation Requirements

**ALWAYS implement:**
```
✓ Log all authentication events (success and failure)
✓ Log access control failures
✓ Log input validation failures
✓ Use structured logging (JSON)
✓ Include context (user ID, IP, timestamp, action)
✓ Centralize logs (send to SIEM)
✓ Implement log rotation and retention
✓ Alert on suspicious patterns
✓ Protect logs from tampering (write-only)
```

**NEVER do:**
```
✗ Log sensitive data (passwords, tokens, PII)
✗ Use only local logging
✗ Ignore logging in error handlers
✗ Log to world-readable files
✗ Skip timestamp or context in logs
✗ Use inconsistent log formats
✗ Allow log injection
```

### Code Examples

**✅ SECURE (Structured Logging):**
```javascript
const winston = require('winston');

// Configure structured logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'user-service' },
  transports: [
    // Write all logs to console
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    // Write all errors to error.log
    new winston.transports.File({ 
      filename: 'error.log', 
      level: 'error' 
    }),
    // Write all logs to combined.log
    new winston.transports.File({ 
      filename: 'combined.log' 
    })
  ]
});

// Security event logging
function logSecurityEvent(eventType, details, req) {
  logger.warn({
    event: 'security',
    type: eventType,
    userId: req.session?.userId,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    ...details
  });
}

// Example usage
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = await db.getUserByUsername(username);
  
  if (!user || !await bcrypt.compare(password, user.passwordHash)) {
    // Log failed login attempt
    logSecurityEvent('login_failed', {
      username: username,
      reason: 'invalid_credentials'
    }, req);
    
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Log successful login
  logSecurityEvent('login_success', {
    userId: user.id,
    username: user.username
  }, req);
  
  req.session.userId = user.id;
  res.json({ success: true });
});
```

**✅ SECURE (Comprehensive Security Logging):**
```python
import logging
import json
from datetime import datetime
from functools import wraps

# Configure structured logging
class SecurityLogger:
    def __init__(self):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        handler = logging.FileHandler('security.log')
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)
    
    def log_event(self, event_type, user_id=None, ip=None, details=None):
        """Log security event in structured format"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip,
            'details': details or {}
        }
        
        self.logger.info(json.dumps(event))
        
        # Send critical events to monitoring system
        if event_type in ['login_failed_repeated', 'privilege_escalation', 'data_breach']:
            self.send_alert(event)
    
    def send_alert(self, event):
        """Send alert to monitoring system"""
        # Integration with PagerDuty, Slack, etc.
        pass

security_logger = SecurityLogger()

def log_security_event(event_type):
    """Decorator for automatic security logging"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract request context
            request = args[0] if args else kwargs.get('request')
            
            try:
                result = func(*args, **kwargs)
                
                # Log successful operation
                security_logger.log_event(
                    event_type=f'{event_type}_success',
                    user_id=getattr(request, 'user_id', None),
                    ip=getattr(request, 'remote_addr', None),
                    details={'function': func.__name__}
                )
                
                return result
            except Exception as e:
                # Log failure
                security_logger.log_event(
                    event_type=f'{event_type}_failed',
                    user_id=getattr(request, 'user_id', None),
                    ip=getattr(request, 'remote_addr', None),
                    details={
                        'function': func.__name__,
                        'error': str(e)
                    }
                )
                raise
        
        return wrapper
    return decorator

# Usage
@app.route('/api/admin/delete-user', methods=['DELETE'])
@require_admin
@log_security_event('admin_delete_user')
def delete_user(request, user_id):
    db.delete_user(user_id)
    return {'success': True}
```

**✅ SECURE (What to Log):**
```python
# Authentication events
def log_login_attempt(username, success, reason=None):
    security_logger.log_event(
        'login_attempt',
        details={
            'username': username,  # OK to log username
            'success': success,
            'reason': reason,
            'timestamp': datetime.utcnow().isoformat()
        }
    )
    # NEVER log password!

# Access control failures
def log_access_denied(user_id, resource, required_permission):
    security_logger.log_event(
        'access_denied',
        user_id=user_id,
        details={
            'resource': resource,
            'required_permission': required_permission
        }
    )

# Input validation failures
def log_validation_failure(endpoint, field, value_type):
    security_logger.log_event(
        'validation_failure',
        details={
            'endpoint': endpoint,
            'field': field,
            'expected_type': value_type
            # Don't log the actual invalid value (might be malicious)
        }
    )

# High-value transactions
def log_transaction(user_id, amount, transaction_type):
    security_logger.log_event(
        'high_value_transaction',
        user_id=user_id,
        details={
            'amount': amount,
            'type': transaction_type,
            'timestamp': datetime.utcnow().isoformat()
        }
    )

# Configuration changes
def log_config_change(admin_id, setting, old_value, new_value):
    security_logger.log_event(
        'config_change',
        user_id=admin_id,
        details={
            'setting': setting,
            'old_value': old_value,  # Sanitize if sensitive
            'new_value': new_value   # Sanitize if sensitive
        }
    )
```

**❌ INSECURE (What NOT to Log):**
```python
# NEVER log these!

# ❌ Passwords
logger.info(f'User {username} logged in with password: {password}')

# ❌ API keys / tokens
logger.info(f'API call with key: {api_key}')

# ❌ Credit card numbers
logger.info(f'Payment with card: {card_number}')

# ❌ Session tokens
logger.info(f'Session created: {session_token}')

# ❌ PII without sanitization
logger.info(f'User email: {email}, SSN: {ssn}')

# ❌ Full request/response bodies (may contain sensitive data)
logger.info(f'Request body: {request.body}')
```

**✅ SECURE (Log Sanitization):**
```python
import re

def sanitize_for_logging(data):
    """Remove sensitive information before logging"""
    if isinstance(data, dict):
        sanitized = {}
        sensitive_keys = ['password', 'token', 'secret', 'api_key', 'credit_card']
        
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, (dict, list)):
                sanitized[key] = sanitize_for_logging(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    elif isinstance(data, list):
        return [sanitize_for_logging(item) for item in data]
    
    elif isinstance(data, str):
        # Redact patterns that look like credit cards
        data = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[CARD-REDACTED]', data)
        # Redact patterns that look like SSN
        data = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN-REDACTED]', data)
        return data
    
    return data

# Usage
user_data = {
    'username': 'john',
    'password': 'secret123',
    'email': 'john@example.com',
    'credit_card': '4111-1111-1111-1111'
}

logger.info(f'User data: {sanitize_for_logging(user_data)}')
# Output: {'username': 'john', 'password': '[REDACTED]', 'email': 'john@example.com', 'credit_card': '[REDACTED]'}
```

**✅ SECURE (Centralized Logging):**
```javascript
// Send logs to centralized logging service
const { LoggingWinston } = require('@google-cloud/logging-winston');

const logger = winston.createLogger({
  transports: [
    // Local file
    new winston.transports.File({ filename: 'combined.log' }),
    // Google Cloud Logging
    new LoggingWinston({
      projectId: 'your-project-id',
      keyFilename: '/path/to/key.json'
    })
  ]
});

// Or use ELK stack
const Elasticsearch = require('winston-elasticsearch');

logger.add(new Elasticsearch({
  level: 'info',
  clientOpts: { node: 'http://localhost:9200' },
  index: 'security-logs'
}));
```

**✅ SECURE (Anomaly Detection):**
```python
from collections import defaultdict
from datetime import datetime, timedelta

class AnomalyDetector:
    def __init__(self):
        self.failed_logins = defaultdict(list)
        self.threshold = 5
        self.window = timedelta(minutes=15)
    
    def check_failed_login(self, username, ip):
        """Detect brute force attempts"""
        now = datetime.utcnow()
        key = f'{username}:{ip}'
        
        # Clean old attempts
        self.failed_logins[key] = [
            ts for ts in self.failed_logins[key]
            if now - ts < self.window
        ]
        
        # Add current attempt
        self.failed_logins[key].append(now)
        
        # Check threshold
        if len(self.failed_logins[key]) >= self.threshold:
            security_logger.log_event(
                'brute_force_detected',
                details={
                    'username': username,
                    'ip': ip,
                    'attempts': len(self.failed_logins[key])
                }
            )
            # Trigger alert
            send_security_alert(f'Brute force detected: {username} from {ip}')
            return True
        
        return False

anomaly_detector = AnomalyDetector()
```

### Testing Checklist
- [ ] Are all authentication events logged?
- [ ] Are access control failures logged?
- [ ] Are logs in structured format (JSON)?
- [ ] Are logs centralized and monitored?
- [ ] Are sensitive data excluded from logs?
- [ ] Are alerts configured for suspicious activity?
- [ ] Is log integrity protected?
- [ ] Are logs retained for appropriate period?

---

## A10:2021 - Server-Side Request Forgery (SSRF)

### Description
SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).

### Common Vulnerabilities
- Fetching URLs without validating user input
- Allowing access to internal resources (metadata endpoints, internal APIs)
- Not implementing network segmentation
- URL parsing inconsistencies
- Redirect following to internal resources

### AI Code Generation Requirements

**ALWAYS implement:**
```
✓ Validate and sanitize all URLs from user input
✓ Use allowlist of permitted domains/protocols
✓ Disable HTTP redirects or validate redirect destinations
✓ Implement network segmentation
✓ Block access to private IP ranges
✓ Use DNS rebinding protection
✓ Validate URL schemes (allow http/https only)
✓ Implement timeout and size limits for requests
```

**NEVER do:**
```
✗ Fetch URLs directly from user input
✗ Allow file:// or other dangerous protocols
✗ Trust user-supplied redirects
✗ Skip validation of internal IPs
✗ Allow access to metadata endpoints
✗ Use URL parsing without validation
```

### Code Examples

**❌ INSECURE (Direct URL Fetch):**
```javascript
app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  
  // Attacker can access internal resources!
  // http://localhost:8080/admin
  // http://169.254.169.254/latest/meta-data/
  const response = await fetch(url);
  const data = await response.text();
  
  res.send(data);
});
```

**✅ SECURE:**
```javascript
const { URL } = require('url');

// Allowlist of permitted domains
const ALLOWED_DOMAINS = [
  'api.example.com',
  'cdn.example.com'
];

// Blocklist of private IP ranges
const PRIVATE_IP_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,  // AWS metadata
  /^::1$/,        // IPv6 localhost
  /^fe80:/,       // IPv6 link-local
  /^fc00:/,       // IPv6 private
];

function isPrivateIP(hostname) {
  // Check if hostname matches private IP patterns
  return PRIVATE_IP_RANGES.some(pattern => pattern.test(hostname));
}

function validateURL(urlString) {
  try {
    const url = new URL(urlString);
    
    // Only allow http and https
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new Error('Invalid protocol');
    }
    
    // Check against allowlist
    if (!ALLOWED_DOMAINS.includes(url.hostname)) {
      throw new Error('Domain not allowed');
    }
    
    // Block private IPs
    if (isPrivateIP(url.hostname)) {
      throw new Error('Private IP not allowed');
    }
    
    return url.href;
  } catch (error) {
    throw new Error(`Invalid URL: ${error.message}`);
  }
}

app.get('/fetch', async (req, res) => {
  try {
    const validatedURL = validateURL(req.query.url);
    
    const response = await fetch(validatedURL, {
      redirect: 'manual', // Don't follow redirects
      timeout: 5000,      // 5 second timeout
      size: 1024 * 1024   // 1MB max
    });
    
    // Check if response is redirect
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      return res.status(400).json({ error: 'Redirects not allowed' });
    }
    
    const data = await response.text();
    res.send(data);
  } catch (error) {
    res.status(400).json({ error: 'Invalid request' });
  }
});
```

**✅ SECURE (DNS Rebinding Protection):**
```python
import socket
import ipaddress
import requests
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

def is_private_ip(ip):
    """Check if IP is private/internal"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_reserved
        )
    except ValueError:
        return True  # If invalid, treat as suspicious

def validate_url(url_string):
    """Validate URL with DNS rebinding protection"""
    # Parse URL
    parsed = urlparse(url_string)
    
    # Check protocol
    if parsed.scheme not in ['http', 'https']:
        raise ValueError('Only HTTP/HTTPS allowed')
    
    # Check domain allowlist
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError('Domain not allowed')
    
    # Resolve DNS and check if IP is public
    try:
        ip = socket.gethostbyname(parsed.hostname)
    except socket.gaierror:
        raise ValueError('Cannot resolve hostname')
    
    if is_private_ip(ip):
        raise ValueError('Cannot access private IP addresses')
    
    return url_string, ip

def fetch_url(url_string):
    """Safely fetch URL with SSRF protection"""
    # Validate URL and get resolved IP
    validated_url, resolved_ip = validate_url(url_string)
    
    # Make request with additional protections
    try:
        response = requests.get(
            validated_url,
            timeout=5,
            allow_redirects=False,  # Prevent redirect-based SSRF
            stream=True,
            headers={'User-Agent': 'SafeFetcher/1.0'}
        )
        
        # Check content length
        content_length = response.headers.get('Content-Length')
        if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB
            raise ValueError('Response too large')
        
        # Verify IP hasn't changed (DNS rebinding protection)
        # Re-resolve and compare
        current_ip = socket.gethostbyname(urlparse(validated_url).hostname)
        if current_ip != resolved_ip:
            raise ValueError('DNS rebinding detected')
        
        return response.text
    
    except requests.RequestException as e:
        raise ValueError(f'Request failed: {str(e)}')

# Usage
@app.route('/fetch')
def fetch_endpoint():
    url = request.args.get('url')
    
    try:
        data = fetch_url(url)
        return {'data': data}
    except ValueError as e:
        return {'error': str(e)}, 400
```

**✅ SECURE (Webhook Validation):**
```javascript
// Common SSRF vector: webhook URLs
function validateWebhookURL(url) {
  const parsed = new URL(url);
  
  // Must be HTTPS
  if (parsed.protocol !== 'https:') {
    throw new Error('Webhooks must use HTTPS');
  }
  
  // Block cloud metadata endpoints
  const blockedHosts = [
    'metadata.google.internal',
    '169.254.169.254',  // AWS
    '100.100.100.200',  // Alibaba Cloud
  ];
  
  if (blockedHosts.includes(parsed.hostname)) {
    throw new Error('Blocked hostname');
  }
  
  // Block private IPs
  if (isPrivateIP(parsed.hostname)) {
    throw new Error('Private IPs not allowed for webhooks');
  }
  
  // Block common internal domains
  if (parsed.hostname.endsWith('.internal') || 
      parsed.hostname.endsWith('.local')) {
    throw new Error('Internal domains not allowed');
  }
  
  return parsed.href;
}

app.post('/api/webhooks', async (req, res) => {
  const { url, event } = req.body;
  
  try {
    const validatedURL = validateWebhookURL(url);
    
    // Store validated URL
    await db.saveWebhook({
      userId: req.user.id,
      url: validatedURL,
      event: event
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
```

**✅ SECURE (Network Segmentation):**
```yaml
# Docker network configuration
version: '3.8'

services:
  web:
    image: webapp:latest
    networks:
      - public
    # Web tier can only access database through backend
    # No direct database access
  
  backend:
    image: backend:latest
    networks:
      - public
      - private
    # Backend can access both networks
    environment:
      - ALLOWED_EXTERNAL_DOMAINS=api.example.com,cdn.example.com
  
  database:
    image: postgres:15
    networks:
      - private
    # Database is isolated in private network

networks:
  public:
    driver: bridge
  private:
    driver: bridge
    internal: true  # No external access
```

### Testing Checklist
- [ ] Are URLs validated before fetching?
- [ ] Is there an allowlist of permitted domains?
- [ ] Are private IP ranges blocked?
- [ ] Are redirects disabled or validated?
- [ ] Is access to cloud metadata endpoints prevented?
- [ ] Are dangerous protocols (file://, gopher://) blocked?
- [ ] Is network segmentation implemented?
- [ ] Are timeouts and size limits enforced?

---

## Quick Reference Checklist

Use this checklist when reviewing AI-generated code:

### Authentication & Session Management
- [ ] Strong password hashing (bcrypt, Argon2)
- [ ] Rate limiting on login endpoints
- [ ] Account lockout after failed attempts
- [ ] MFA available for sensitive accounts
- [ ] Session regeneration after login
- [ ] Secure session configuration (httpOnly, secure, sameSite)

### Input Validation & Injection Prevention
- [ ] All inputs validated server-side
- [ ] Parameterized queries (no string concatenation)
- [ ] Output encoding for XSS prevention
- [ ] No eval() or dynamic code execution
- [ ] File uploads validated (type, size, content)

### Access Control
- [ ] Authorization checks on every request
- [ ] Deny by default
- [ ] No direct object references without authorization
- [ ] Proper RBAC/ABAC implementation

### Cryptography
- [ ] TLS 1.2+ for all connections
- [ ] Strong encryption algorithms (AES-256)
- [ ] No hardcoded secrets
- [ ] Proper key management
- [ ] HSTS header enabled

### Error Handling & Logging
- [ ] Generic error messages to users
- [ ] Detailed errors logged server-side
- [ ] No stack traces exposed
- [ ] Security events logged
- [ ] Structured logging format

### Configuration
- [ ] Security headers configured (CSP, HSTS, etc.)
- [ ] Debug mode disabled in production
- [ ] Default credentials changed
- [ ] Unnecessary features disabled
- [ ] CORS properly configured

### Dependencies
- [ ] All dependencies up to date
- [ ] Vulnerability scanning enabled
- [ ] Unused dependencies removed
- [ ] Integrity checks for external resources (SRI)

---

## Additional Resources

- OWASP Top 10 Official: https://owasp.org/www-project-top-ten/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- CWE Top 25: https://cwe.mitre.org/top25/
- SANS Top 25: https://www.sans.org/top25-software-errors/

---

**Document Version:** 1.0  
**Last Updated:** February 2026  
**Next Review:** Quarterly (May 2026)