# Canvas LMS Setup Guide for CSCI 347

This guide helps instructors set up Canvas for the CSCI 347 Network Security and Digital Forensics course, integrating with the GitHub-based course materials.

## 📋 Canvas Course Structure

### Module Organization
```
Module 1: Course Introduction and Setup
Module 2: Week 1 - Cryptography Basics  
Module 3: Week 2 - Hashing and Digital Signatures
Module 4: Week 3 - PKI and Certificate Management
Module 5: Week 4 - Multi-Factor Authentication
Module 6: Week 5 - Access Control and Authorization
Module 7: Week 6 - Network Security and Firewalls
Module 8: Week 7 - Security Monitoring and IDS/IPS
Module 9: Week 8 - Security Assessment
Module 10: Week 9 - Security Architecture
Module 11: Week 10 - Digital Forensics Foundations
Module 12: Week 11 - Advanced Forensics
Module 13: Week 12 - Memory Forensics
Module 14: Week 13 - Mobile and Cloud Forensics
Module 15: Week 14 - Integration and Capstone
Module 16: Major Projects
Module 17: Resources and Support
```

## 🔧 Canvas Configuration

### Course Settings
- **Course Format**: Online
- **Course Structure**: Modules
- **Navigation**: Customize to show essential tools only
- **Course Home**: Modules page
- **Course Image**: Cybersecurity/forensics themed image

### Navigation Menu Items
Keep only essential items:
- ✅ Home
- ✅ Modules  
- ✅ Assignments
- ✅ Discussions
- ✅ Grades
- ✅ Files
- ✅ People
- ✅ Settings
- ❌ Remove: Pages, Quizzes, Syllabus (content is in GitHub)

## 📚 Module Template

### Each Week Module Contains:
1. **Overview Page** - Week objectives and reading assignments
2. **GitHub Tutorial Link** - Direct link to week's tutorial.md
3. **Assignment** - Canvas assignment linked to GitHub deliverables
4. **Discussion Forum** - Week-specific help and discussion
5. **Knowledge Check Quiz** - 5-10 auto-graded questions
6. **Validation Script** - Link to automated check script

### Sample Module Structure (Week 1):
```
📁 Week 1: Cryptography Basics
   📄 Week 1 Overview
   🔗 GitHub Tutorial: Symmetric Encryption 
   📝 Assignment: Password Vault (100 points)
   💬 Discussion: Week 1 Questions & Help
   📊 Knowledge Check: Cryptography Quiz (10 points)
   ✅ Validation: Run check-week1.py
```

## 📝 Assignment Configuration

### Assignment Settings Template
- **Assignment Type**: External Tool (for GitHub integration) or File Upload
- **Points**: See individual week requirements  
- **Submission Type**: Website URL (GitHub repository link) + File Upload
- **Allowed Extensions**: .py, .md, .txt, .pdf
- **Plagiarism Detection**: Enable if institution has Turnitin/similar

### Grading Rubric Template (5-Point Scale)
```
Functionality (40% of total points)
- Excellent (5): All requirements met perfectly, handles edge cases
- Proficient (4): Most requirements met, minor issues
- Developing (3): Basic functionality, some missing features
- Needs Improvement (2): Limited functionality, major issues
- Inadequate (1): Major functionality missing or broken
- No Submission (0): No work submitted or no attempt

Code Quality (30% of total points)  
- Excellent (5): Clean, well-documented, follows best practices
- Proficient (4): Good structure, adequate documentation
- Developing (3): Basic organization, minimal documentation
- Needs Improvement (2): Poor structure, limited documentation
- Inadequate (1): Very poor structure, no documentation
- No Submission (0): No work submitted or no attempt

Security (30% of total points)
- Excellent (5): Proper security controls, follows best practices
- Proficient (4): Good security implementation, minor issues  
- Developing (3): Basic security, some vulnerabilities
- Needs Improvement (2): Poor security, significant vulnerabilities
- Inadequate (1): Major security flaws or no security consideration
- No Submission (0): No work submitted or no attempt

Example Calculation for 100-point assignment:
- Functionality: 5 × 40% = 40 points
- Code Quality: 4 × 30% = 30 points  
- Security: 5 × 30% = 30 points
- Total: 100 points
```

## 💬 Discussion Forums Setup

### Forum Categories
1. **General Course Discussion** - Course-wide questions and announcements
2. **Technical Help** - Programming and tool troubleshooting
3. **Week-Specific Forums** - One per week for focused discussions
4. **Project Collaboration** - Major project coordination and help
5. **Career and Industry** - Professional development discussions

### Discussion Forum Settings
- **Allow Threaded Discussions**: Yes
- **Require Students to Post Before Seeing Replies**: No
- **Allow Liking**: Yes
- **Sort Posts By**: Recent Activity
- **Podcast Feed**: Disabled

## 📊 Quiz Configuration

### Knowledge Check Quizzes (Weekly)
- **Points**: 10 points each
- **Questions**: 5-10 multiple choice/true-false
- **Time Limit**: 30 minutes
- **Attempts**: 2 attempts allowed
- **Show Answers**: After due date
- **Question Bank**: Import from quiz-banks/ folder

### Quiz Question Types
1. **Multiple Choice**: Concept understanding
2. **True/False**: Fact verification  
3. **Fill in the Blank**: Key terminology
4. **Matching**: Concepts to definitions
5. **Multiple Select**: Complex scenarios

## 📁 Files and Resources

### File Organization
```
📁 Files
   📁 Week Materials
      📁 Week01-Supplementary
      📁 Week02-Supplementary  
      ...
   📁 Project Templates
   📁 Reference Materials
   📁 Tools and Software
   📁 Sample Code
   📁 Practice Datasets (Forensics)
```

### File Upload Guidelines
- **GitHub Integration**: Primary materials stay on GitHub
- **Canvas Files**: Only supplementary materials that can't be on GitHub
- **Large Files**: Use external hosting (OneDrive, Google Drive) with links
- **Software**: Provide download links rather than hosting files

## 👥 Groups and Collaboration

### Group Setup (Optional)
- **Study Groups**: Self-signup, 4-5 students per group
- **Project Teams**: Instructor-assigned for major projects
- **Peer Review Groups**: Rotating groups for assignment feedback

### Collaboration Tools
- **Canvas Discussions**: Primary communication
- **Canvas Conferences**: Virtual office hours and group meetings  
- **External Integration**: Discord/Slack if preferred by students

## 📈 Gradebook Configuration

### Grade Categories
```
Category                Weight    Description
==========================================
Weekly Assignments      55%       Hands-on technical work
Python Projects         30%       3 major integration projects
Capstone Project        15%       Final comprehensive project
Knowledge Checks        Extra     Bonus points for participation
```

### Grading Policies
- **Late Policy**: See course syllabus (automated Canvas penalties)
- **Missing Assignments**: 0 points, no dropping lowest grades
- **Extra Credit**: Knowledge check quizzes and peer reviews
- **Grade Posting**: Automated when possible, manual review for major projects

## 🔄 Integration with GitHub

### Linking Strategy
1. **Canvas Assignment** → **GitHub Repository Link**  
2. **Students Submit**: GitHub repository URL + any additional files
3. **Instructor Reviews**: Clone repository for detailed feedback
4. **Grades Posted**: In Canvas with comments linking to GitHub feedback

### GitHub Classroom Integration (Optional)
- **Assignment Repositories**: Auto-created per student
- **Template Repositories**: Starter code and instructions
- **Automated Testing**: GitHub Actions for code validation
- **Pull Request Reviews**: Instructor feedback through GitHub

## 📧 Communication Setup

### Announcement Templates
```
Subject: Week X Materials Available
Content: This week we're covering [topic]. Please:
1. Complete required readings (links in module)
2. Follow GitHub tutorial: [link]
3. Submit assignment by [date]
4. Join this week's discussion forum
Questions? Post in the discussion forum or attend office hours.
```

### Email Settings
- **Course Notifications**: Enable for assignments and announcements
- **Discussion Notifications**: Student choice
- **Grade Notifications**: Enable when grades are posted
- **Reminder Notifications**: 48 hours before due dates

## 🎯 Student Success Features

### Progress Tracking
- **Module Progression**: Students can track completion
- **Assignment Calendar**: Visual due date calendar
- **Grade Trends**: Students see performance over time
- **Learning Objectives**: Clearly mapped to each week

### Support Resources
- **Getting Help Page**: Centralized support information
- **Technical Requirements**: System specs and software links
- **Troubleshooting Guide**: Common issues and solutions
- **Contact Information**: Office hours, email, discussion forums

## 🔒 Privacy and Security

### Student Privacy
- **GitHub Repositories**: Students can use private repos if preferred
- **Peer Reviews**: Anonymous feedback options
- **Discussions**: Professional conduct expectations
- **Data Protection**: Follow institutional privacy policies

### Course Security
- **Assignment Security**: Unique assignments each semester
- **Academic Integrity**: Clear policies and detection tools
- **Access Control**: Proper role assignments for TAs/graders
- **Backup Strategy**: Regular exports of course content

## 📋 Launch Checklist

### Pre-Semester Setup
- [ ] Course structure and modules created
- [ ] Assignments configured with rubrics
- [ ] Discussion forums set up
- [ ] Quiz banks imported and configured
- [ ] Files organized and uploaded
- [ ] Gradebook categories configured
- [ ] Announcements prepared
- [ ] Integration with GitHub tested

### First Week Tasks  
- [ ] Welcome announcement posted
- [ ] Student introductions forum opened
- [ ] Week 1 materials made available
- [ ] Office hours scheduled and announced
- [ ] Technical support information shared
- [ ] Course expectations clarified

### Ongoing Maintenance
- [ ] Weekly announcements
- [ ] Discussion forum monitoring
- [ ] Assignment feedback and grading
- [ ] Student progress tracking
- [ ] Technical issue resolution
- [ ] Content updates as needed

---

**Need help with Canvas setup?** Contact your institution's Canvas administrator or instructional design team.