# Week 5 Assignment: Enterprise Access Control System

**Due**: End of Week 5 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Upload to Canvas

## 🎯 Assignment Overview

Build a comprehensive access control system that implements both Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) with dynamic policy enforcement. Your implementation should demonstrate mastery of authorization concepts, policy engines, and zero-trust principles learned this week.

## 📋 Requirements

### Core Functionality (70 points)

Your access control system must implement these features:

#### 1. Role-Based Access Control (RBAC) Engine (25 points)
- **Role hierarchy management** with inheritance (Admin > Manager > User)
- **Permission assignment** to roles with CRUD operations
- **User-role assignments** with multiple role support
- **Dynamic role evaluation** with context-aware permissions

#### 2. Attribute-Based Access Control (ABAC) Engine (25 points)
- **Policy definition language** using JSON or similar format
- **Attribute evaluation** for subject, resource, action, and environment
- **Dynamic policy evaluation** with boolean logic (AND, OR, NOT)
- **Policy conflict resolution** with explicit deny precedence

#### 3. Policy Enforcement Points (PEP) (20 points)
- **REST API protection** with middleware interceptors
- **Resource-level authorization** based on ownership and permissions
- **Action-level control** (read, write, delete, admin) per resource type
- **Audit logging** of all access decisions and policy violations

### Web API Interface (20 points)

Create a Flask-based API with these endpoints:

```
POST /api/auth/login           - Authentication endpoint
GET  /api/users                - List users (admin only)
POST /api/users                - Create user (admin only)
GET  /api/users/{id}           - Get user details (self or admin)
PUT  /api/users/{id}           - Update user (self or admin)
DELETE /api/users/{id}         - Delete user (admin only)

GET  /api/documents            - List documents (based on permissions)
POST /api/documents            - Create document (authenticated users)
GET  /api/documents/{id}       - Get document (owner or shared access)
PUT  /api/documents/{id}       - Update document (owner only)
DELETE /api/documents/{id}     - Delete document (owner or admin)

POST /api/admin/roles          - Create role (admin only)
GET  /api/admin/roles          - List all roles (admin only)
POST /api/admin/assign-role    - Assign role to user (admin only)
POST /api/admin/policies       - Create ABAC policy (admin only)
GET  /api/admin/audit          - Access audit logs (admin only)
```

### Security Features (10 points)

- **JWT-based authentication** with role claims
- **Input validation** and sanitization for all endpoints
- **Rate limiting** to prevent abuse
- **Secure error handling** without information disclosure

## 🔧 Technical Specifications

### Required Libraries
```python
from flask import Flask, request, jsonify, g
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
import sqlite3
import json
import datetime
import hashlib
import secrets
from functools import wraps
```

### File Structure
```
access_control_system.py      # Main Flask application
rbac_engine.py               # Role-based access control
abac_engine.py               # Attribute-based access control
policy_engine.py             # Combined policy evaluation
audit_logger.py              # Access logging
database.py                  # Database operations
policies/                    # Policy definition files
  ├── rbac_policies.json
  └── abac_policies.json
access_control.db           # SQLite database
README.txt                  # Implementation documentation
```

### Database Schema
```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    department TEXT,
    location TEXT,
    security_clearance TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE
);

-- Roles table
CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    parent_role_id INTEGER,
    permissions TEXT,  -- JSON array of permissions
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (parent_role_id) REFERENCES roles (id)
);

-- User roles assignment
CREATE TABLE user_roles (
    user_id INTEGER,
    role_id INTEGER,
    assigned_by INTEGER,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (role_id) REFERENCES roles (id),
    FOREIGN KEY (assigned_by) REFERENCES users (id)
);

-- Documents table (example resource)
CREATE TABLE documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    owner_id INTEGER,
    classification TEXT,  -- public, internal, confidential, secret
    department TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users (id)
);

-- Access logs
CREATE TABLE access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    resource_type TEXT,
    resource_id TEXT,
    action TEXT,
    decision TEXT,  -- allow, deny
    policy_applied TEXT,
    ip_address TEXT,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## 📝 Detailed Requirements

### 1. RBAC Engine
```python
class RBACEngine:
    def __init__(self, db_connection):
        self.db = db_connection
        
    def create_role(self, name, description, permissions, parent_role=None):
        """
        Create a new role with specified permissions
        
        Args:
            name (str): Role name
            description (str): Role description  
            permissions (list): List of permission strings
            parent_role (str): Parent role name for inheritance
            
        Returns:
            dict: Creation result with role ID or error
        """
        # Validate role doesn't exist
        # Create role with permission inheritance
        # Store in database
        
    def assign_role(self, user_id, role_name, assigned_by, expires_at=None):
        """
        Assign role to user
        
        Args:
            user_id (int): User identifier
            role_name (str): Role to assign
            assigned_by (int): User ID of administrator
            expires_at (datetime): Optional expiration
            
        Returns:
            bool: True if successful
        """
        # Validate role exists
        # Check for existing assignment
        # Create user-role relationship
        
    def check_permission(self, user_id, permission):
        """
        Check if user has specific permission through roles
        
        Args:
            user_id (int): User identifier
            permission (str): Permission to check
            
        Returns:
            bool: True if user has permission
        """
        # Get all user roles
        # Check direct permissions
        # Check inherited permissions from parent roles
        # Return boolean result
        
    def get_user_roles(self, user_id):
        """Get all active roles for user"""
        # Query user_roles table
        # Include role hierarchy
        # Return role list with permissions
```

### 2. ABAC Engine
```python
class ABACEngine:
    def __init__(self, policy_file='policies/abac_policies.json'):
        self.policies = self._load_policies(policy_file)
        
    def evaluate_policy(self, subject, resource, action, environment):
        """
        Evaluate ABAC policies for access decision
        
        Args:
            subject (dict): User attributes (role, department, clearance)
            resource (dict): Resource attributes (classification, owner, type)
            action (str): Requested action (read, write, delete)
            environment (dict): Context (time, location, network)
            
        Returns:
            dict: Decision with policy details
        """
        decisions = []
        
        for policy in self.policies:
            if self._matches_policy_scope(policy, resource, action):
                decision = self._evaluate_conditions(policy, subject, resource, environment)
                decisions.append({
                    'policy_id': policy['id'],
                    'decision': decision,
                    'policy': policy
                })
        
        # Apply conflict resolution (explicit deny wins)
        return self._resolve_conflicts(decisions)
        
    def _evaluate_conditions(self, policy, subject, resource, environment):
        """Evaluate policy conditions using boolean logic"""
        conditions = policy['conditions']
        
        # Implement AND, OR, NOT logic
        # Compare attributes with operators (==, !=, >, <, in, contains)
        # Return boolean result
        
    def add_policy(self, policy):
        """Add new ABAC policy"""
        # Validate policy structure
        # Add to policy store
        # Save to persistent storage
```

### 3. Policy Enforcement Decorator
```python
def require_permission(permission=None, resource_type=None, owner_field=None):
    """
    Decorator for API endpoint authorization
    
    Args:
        permission (str): Required permission for RBAC
        resource_type (str): Resource type for ABAC evaluation
        owner_field (str): Field name for resource ownership check
    """
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            
            # Get user and resource information
            user = get_user_by_id(current_user_id)
            resource = None
            if resource_type and 'id' in kwargs:
                resource = get_resource(resource_type, kwargs['id'])
            
            # RBAC Check
            if permission:
                rbac_result = rbac_engine.check_permission(current_user_id, permission)
                if not rbac_result:
                    log_access_decision(user, resource, request.method, 'deny', 'RBAC')
                    return jsonify({'error': 'Insufficient permissions'}), 403
            
            # ABAC Check
            if resource_type:
                abac_result = abac_engine.evaluate_policy(
                    subject=get_user_attributes(user),
                    resource=get_resource_attributes(resource),
                    action=request.method.lower(),
                    environment=get_environment_context()
                )
                
                if abac_result['decision'] == 'deny':
                    log_access_decision(user, resource, request.method, 'deny', 'ABAC')
                    return jsonify({'error': 'Access denied by policy'}), 403
            
            # Owner-based check
            if owner_field and resource:
                if getattr(resource, owner_field) != current_user_id:
                    if not rbac_engine.check_permission(current_user_id, 'admin'):
                        log_access_decision(user, resource, request.method, 'deny', 'OWNERSHIP')
                        return jsonify({'error': 'Access denied - not owner'}), 403
            
            log_access_decision(user, resource, request.method, 'allow', 'SUCCESS')
            return f(*args, **kwargs)
        return decorated_function
    return decorator
```

## 💻 Example Usage

### API Endpoints with Access Control
```python
@app.route('/api/documents', methods=['GET'])
@require_permission(permission='document:read')
def list_documents():
    """List documents based on user permissions"""
    current_user_id = get_jwt_identity()
    
    # Apply filtering based on user attributes
    if rbac_engine.check_permission(current_user_id, 'admin'):
        documents = get_all_documents()
    else:
        documents = get_user_accessible_documents(current_user_id)
    
    return jsonify({'documents': documents})

@app.route('/api/documents/<int:doc_id>', methods=['GET'])
@require_permission(resource_type='document', owner_field='owner_id')
def get_document(doc_id):
    """Get specific document with ownership/sharing check"""
    document = get_document_by_id(doc_id)
    if not document:
        return jsonify({'error': 'Document not found'}), 404
    
    return jsonify({'document': document})

@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
@require_permission(permission='document:delete', resource_type='document', owner_field='owner_id')
def delete_document(doc_id):
    """Delete document with admin or owner permission"""
    if delete_document_by_id(doc_id):
        return jsonify({'message': 'Document deleted successfully'})
    else:
        return jsonify({'error': 'Failed to delete document'}), 500
```

### ABAC Policy Examples
```json
{
  "policies": [
    {
      "id": "confidential-document-access",
      "description": "Access to confidential documents",
      "effect": "allow",
      "scope": {
        "resource_type": "document",
        "actions": ["read", "write"]
      },
      "conditions": {
        "and": [
          {
            "subject.security_clearance": {"in": ["secret", "confidential"]}
          },
          {
            "resource.classification": {"<=": "subject.security_clearance"}
          },
          {
            "environment.network": {"==": "corporate"}
          }
        ]
      }
    },
    {
      "id": "department-document-access",
      "description": "Department-specific document access",
      "effect": "allow",
      "scope": {
        "resource_type": "document",
        "actions": ["read"]
      },
      "conditions": {
        "or": [
          {
            "subject.department": {"==": "resource.department"}
          },
          {
            "subject.role": {"==": "admin"}
          }
        ]
      }
    },
    {
      "id": "after-hours-restriction",
      "description": "Restrict access to sensitive documents after hours",
      "effect": "deny",
      "scope": {
        "resource_type": "document",
        "actions": ["write", "delete"]
      },
      "conditions": {
        "and": [
          {
            "resource.classification": {"in": ["confidential", "secret"]}
          },
          {
            "environment.time": {"not_between": ["09:00", "17:00"]}
          },
          {
            "not": {
              "subject.role": {"==": "admin"}
            }
          }
        ]
      }
    }
  ]
}
```

## 📊 Grading Rubric (100 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|---------|
| **RBAC Implementation** | 25% | 25 points |
| **ABAC Implementation** | 25% | 25 points |
| **Policy Enforcement** | 20% | 20 points |
| **API Interface** | 20% | 20 points |
| **Security Practices** | 10% | 10 points |

### 5-Point Scale Criteria

**RBAC Implementation (25 points)**
- **Excellent (25)**: Complete role hierarchy, inheritance, dynamic permissions
- **Proficient (20)**: Good RBAC functionality, minor feature gaps
- **Developing (15)**: Basic RBAC works, limited hierarchy support
- **Needs Improvement (10)**: RBAC partially functional, significant issues
- **Inadequate (5)**: RBAC doesn't work properly or major flaws
- **No Submission (0)**: Missing or no attempt

**ABAC Implementation (25 points)**
- **Excellent (25)**: Comprehensive policy evaluation, complex conditions, conflict resolution
- **Proficient (20)**: Good ABAC engine, most policy features working
- **Developing (15)**: Basic ABAC functionality, simple conditions only
- **Needs Improvement (10)**: ABAC works but limited policy support
- **Inadequate (5)**: ABAC doesn't work properly or major issues
- **No Submission (0)**: Missing or no attempt

**Policy Enforcement (20 points)**
- **Excellent (20)**: Seamless API protection, comprehensive audit logging
- **Proficient (16)**: Good enforcement mechanisms, minor gaps
- **Developing (12)**: Basic enforcement works, some endpoints unprotected
- **Needs Improvement (8)**: Limited enforcement, significant gaps
- **Inadequate (4)**: Poor or no policy enforcement
- **No Submission (0)**: Missing or no attempt

**API Interface (20 points)**
- **Excellent (20)**: All endpoints functional, proper error handling, good documentation
- **Proficient (16)**: Most endpoints work well, good usability
- **Developing (12)**: Basic endpoints functional, adequate responses
- **Needs Improvement (8)**: Some endpoints work, poor error handling
- **Inadequate (4)**: Major API problems, broken functionality
- **No Submission (0)**: Missing or no attempt

**Security Practices (10 points)**
- **Excellent (10)**: Comprehensive security, audit logging, input validation
- **Proficient (8)**: Good security practices, minor vulnerabilities
- **Developing (6)**: Basic security considerations
- **Needs Improvement (4)**: Limited security practices
- **Inadequate (2)**: Poor or no security considerations
- **No Submission (0)**: Missing or no attempt

### Grade Scale
- **90-100 points (A)**: Enterprise-ready access control system
- **80-89 points (B)**: Good implementation, minor issues
- **70-79 points (C)**: Satisfactory, meets basic requirements
- **60-69 points (D)**: Below expectations, significant issues
- **Below 60 points (F)**: Unsatisfactory, major problems

## 🚀 Bonus Opportunities (+5 points each)

### 1. Zero Trust Architecture
Implement continuous verification:
```python
def continuous_authorization(user_id, resource_type):
    """Continuously verify access throughout session"""
    # Check device trust level
    # Verify network location
    # Assess behavior patterns
```

### 2. Dynamic Policy Learning
Add machine learning for policy recommendations:
```python
def analyze_access_patterns(user_id, timeframe_days=30):
    """Analyze user access patterns for policy optimization"""
    # Extract access patterns from logs
    # Identify anomalies and recommendations
```

### 3. Policy Visualization
Create policy impact visualization:
```python
def visualize_policy_coverage():
    """Generate policy coverage and conflict reports"""
    # Map policies to resources and actions
    # Identify coverage gaps and conflicts
```

## 📋 Submission Checklist

Before submitting, verify:

- [ ] **RBAC engine supports role hierarchy and inheritance**
- [ ] **ABAC engine evaluates complex policy conditions**
- [ ] **All API endpoints are properly protected**
- [ ] **Audit logging captures all access decisions**
- [ ] **Error handling doesn't leak sensitive information**
- [ ] **Database operations handle concurrent access**
- [ ] **Policy conflict resolution works correctly**
- [ ] **Code is well-structured and documented**
- [ ] **README.txt explains policy design and usage**

### Testing Your Access Control System
```bash
# Test RBAC functionality
curl -X POST http://localhost:5000/api/auth/login -d '{"username":"admin","password":"admin123"}'
curl -X GET http://localhost:5000/api/admin/roles -H "Authorization: Bearer $TOKEN"
curl -X POST http://localhost:5000/api/admin/assign-role -d '{"user_id":2,"role":"manager"}'

# Test ABAC policies
curl -X GET http://localhost:5000/api/documents -H "Authorization: Bearer $USER_TOKEN"
curl -X GET http://localhost:5000/api/documents/1 -H "Authorization: Bearer $USER_TOKEN"

# Test unauthorized access
curl -X DELETE http://localhost:5000/api/documents/1 -H "Authorization: Bearer $LIMITED_TOKEN"
```

## 📚 Resources and References

### Documentation
- **NIST RBAC Standard**: https://csrc.nist.gov/projects/role-based-access-control
- **XACML ABAC Standard**: https://docs.oasis-open.org/xacml/3.0/
- **Zero Trust Architecture**: https://csrc.nist.gov/publications/detail/sp/800-207/final

### Security Frameworks
- **OWASP Access Control**: https://owasp.org/www-community/Access_Control
- **OAuth 2.0 Resource Protection**: https://tools.ietf.org/html/rfc6749

### Example Implementation Structure
```python
# access_control_system.py
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required
from rbac_engine import RBACEngine
from abac_engine import ABACEngine
from policy_engine import PolicyEngine
from audit_logger import AuditLogger

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
jwt = JWTManager(app)

# Initialize engines
rbac_engine = RBACEngine('access_control.db')
abac_engine = ABACEngine('policies/abac_policies.json')
policy_engine = PolicyEngine(rbac_engine, abac_engine)
audit_logger = AuditLogger('access_control.db')

# Define all API routes with proper access control
if __name__ == '__main__':
    init_database()
    init_default_policies()
    app.run(debug=True, port=5000)
```

## ❓ Frequently Asked Questions

**Q: How should I handle policy conflicts between RBAC and ABAC?**  
A: Implement explicit conflict resolution - typically "deny" decisions override "allow" decisions for security.

**Q: What attributes should I include in ABAC evaluation?**  
A: Include user attributes (role, department, clearance), resource attributes (classification, owner), and environmental context (time, location, network).

**Q: How detailed should the audit logging be?**  
A: Log all access decisions with user, resource, action, decision, policy applied, and contextual information for compliance.

**Q: Should I implement policy caching for performance?**  
A: Yes, cache policy evaluation results with appropriate TTL, but ensure cache invalidation when policies change.

**Q: How do I test complex ABAC policies?**  
A: Create test scenarios with different user attributes, resource classifications, and environmental contexts to verify policy logic.

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

1. **Would this access control system scale to enterprise requirements?**
2. **Are my policies comprehensive enough to protect sensitive resources?**
3. **Does the audit logging provide sufficient forensic information?**
4. **Have I tested all policy combinations and edge cases?**
5. **Is the system resilient against common access control attacks?**

---

**Need Help?**
- Review the access control tutorial materials
- Test your policies with different user scenarios
- Check Canvas discussions for policy design patterns
- Attend office hours for architecture review

**Good luck!** This assignment will give you experience with enterprise-grade access control systems used in zero-trust architectures.