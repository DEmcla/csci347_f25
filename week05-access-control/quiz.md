# Week 5 Quiz: Access Control

**Total Points**: 25 points  
**Time Limit**: 30 minutes  
**Format**: 5 True/False (1pt each), 10 Multiple Choice (1pt each), 5 Short Answer (2pts each)

---

## Part A: True/False Questions (5 points)
*1 point each. Write T for True or F For False.*

**1.** In Role-Based Access Control (RBAC), permissions are assigned directly to users.  
**Answer**: ______

**2.** The principle of least privilege means giving users the maximum access they might ever need.  
**Answer**: ______

**3.** Mandatory Access Control (MAC) allows users to change permissions on files they own.  
**Answer**: ______

**4.** Access Control Lists (ACLs) can specify different permissions for different users on the same resource.  
**Answer**: ______

**5.** Attribute-Based Access Control (ABAC) can make access decisions based on environmental factors like time of day.  
**Answer**: ______

---

## Part B: Multiple Choice Questions (10 points)
*1 point each. Choose the best answer.*

**6.** Which access control model is based on military security classifications?
- A) Discretionary Access Control (DAC)
- B) Mandatory Access Control (MAC)
- C) Role-Based Access Control (RBAC)
- D) Attribute-Based Access Control (ABAC)

**Answer**: ______

**7.** In Unix file permissions, what does the permission "754" mean?
- A) Owner: read/write/execute, Group: read/execute, Others: read
- B) Owner: read/write, Group: read/execute, Others: read/write
- C) Owner: read/write/execute, Group: read/write, Others: read/execute
- D) Owner: read/execute, Group: read/write, Others: read/write/execute

**Answer**: ______

**8.** What is the principle of separation of duties?
- A) Each user should have a separate account
- B) Critical operations should require multiple people
- C) Duties should be separated by time
- D) Each role should have separate privileges

**Answer**: ______

**9.** Which of the following is NOT a common access control matrix element?
- A) Subjects (users)
- B) Objects (resources)
- C) Operations (permissions)
- D) Algorithms (encryption methods)

**Answer**: ______

**10.** What does "need-to-know" mean in access control?
- A) Users must know their passwords
- B) Users should only access information required for their job
- C) Administrators need to know all user activities
- D) Systems need to know user locations

**Answer**: ______

**11.** In RBAC, what is role hierarchy?
- A) Roles ranked by importance
- B) Roles can inherit permissions from other roles
- C) Roles assigned in order
- D) Roles grouped by department

**Answer**: ______

**12.** Which access control mechanism is most flexible for complex organizational requirements?
- A) DAC
- B) MAC
- C) RBAC
- D) ABAC

**Answer**: ______

**13.** What is privilege escalation?
- A) Increasing user password complexity
- B) Gaining higher access privileges than intended
- C) Promoting users to management roles
- D) Upgrading system hardware

**Answer**: ______

**14.** Which principle states that access should be explicitly granted rather than denied?
- A) Fail-safe defaults
- B) Complete mediation
- C) Least privilege
- D) Defense in depth

**Answer**: ______

**15.** What is the purpose of access control auditing?
- A) To slow down system performance
- B) To track who accessed what resources when
- C) To encrypt access logs
- D) To backup user files

**Answer**: ______

---

## Part C: Short Answer Questions (10 points)
*2 points each. Answer in 1-2 sentences.*

**16.** Explain the difference between authentication and authorization.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**17.** What is the confused deputy problem in access control?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**18.** Describe how capability-based security differs from ACL-based security.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**19.** Why is regular access review important in access control management?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**20.** What is privilege creep and how can organizations prevent it?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

---

## Answer Key (Instructor Use Only)

### Part A: True/False
1. **F** - In RBAC, permissions are assigned to roles, then roles to users
2. **F** - Least privilege means giving minimum access needed for job function
3. **F** - MAC is centrally controlled; users cannot change permissions
4. **T** - ACLs can specify different permissions per user/group
5. **T** - ABAC can use contextual attributes like time, location

### Part B: Multiple Choice
6. **B** - Mandatory Access Control (MAC)
7. **A** - Owner: rwx (7), Group: r-x (5), Others: r-- (4)
8. **B** - Critical operations should require multiple people
9. **D** - Algorithms (encryption methods)
10. **B** - Users should only access information required for their job
11. **B** - Roles can inherit permissions from other roles
12. **D** - ABAC (Attribute-Based Access Control)
13. **B** - Gaining higher access privileges than intended
14. **A** - Fail-safe defaults
15. **B** - To track who accessed what resources when

### Part C: Short Answer (Sample Answers)
16. Authentication verifies who you are (identity), while authorization determines what you can do (permissions) after your identity is confirmed.

17. The confused deputy problem occurs when a privileged program is tricked into misusing its authority to perform actions on behalf of a less privileged user, potentially bypassing access controls.

18. Capability-based security uses unforgeable tokens (capabilities) that grant specific permissions, while ACL-based security checks a list attached to each resource to determine if the requesting user has permission.

19. Regular access reviews ensure that users still need their current permissions, removing access that's no longer required due to job changes, reducing the risk of excessive privileges and insider threats.

20. Privilege creep is the gradual accumulation of excess permissions over time as users change roles. Organizations prevent it through regular access reviews, automated deprovisioning when roles change, and implementing time-limited access grants.

---

## Grading Rubric

| Section | Points | Scoring |
|---------|--------|---------|
| True/False | 5 | 1 point per correct answer |
| Multiple Choice | 10 | 1 point per correct answer |
| Short Answer | 10 | 2 points per answer: Full (2), Partial (1), Incorrect (0) |
| **Total** | **25** | |

### Short Answer Grading Guidelines:
- **2 points**: Complete, accurate answer demonstrating understanding
- **1 point**: Partially correct or incomplete answer
- **0 points**: Incorrect or no answer

### Grade Scale:
- A: 23-25 points (92-100%)
- B: 20-22 points (80-91%)
- C: 18-19 points (72-79%)
- D: 15-17 points (60-71%)
- F: Below 15 points (<60%)