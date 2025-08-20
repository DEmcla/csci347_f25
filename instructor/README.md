# Instructor Materials - CSCI 347

**🔒 Instructor-Only Resources**

## 📁 Directory Contents

### Canvas Integration
- **canvas/**: Canvas setup guides and configuration files
- **quiz-banks/**: Question banks for weekly quizzes in JSON format  
- **quiz-template.md**: Template for creating new quiz questions

### Assessment Materials
- **grading-examples.md**: Sample student work with grading rubrics
- **feedback-templates.md**: Standard feedback templates for common issues
- **answer-keys/**: Solution guides for assignments and quizzes (if needed)

### Course Management
- **gradebook-templates/**: Excel/CSV templates for grade tracking
- **announcement-templates/**: Standard course announcements
- **discussion-prompts/**: Weekly discussion questions and facilitation guides

## 🎯 Quick Access

### Weekly Quiz Management
```bash
# Quiz banks are in JSON format for easy import to Canvas
instructor/quiz-banks/week01-quiz-bank.json
instructor/quiz-banks/week02-quiz-bank.json
# etc.
```

### Grading Workflow
1. Review submissions via GitHub Pull Requests
2. Use grading rubrics in **grading-examples.md**
3. Provide feedback using templates in **feedback-templates.md**
4. Record grades in Canvas gradebook

### Common Instructor Tasks
- **Adding new quiz questions**: Use quiz-template.md format
- **Updating rubrics**: Modify grading-examples.md
- **Course announcements**: Adapt templates in announcement-templates/
- **Discussion facilitation**: Use prompts in discussion-prompts/

## 📊 Student Submission Tracking

### Pull Request Review Process
Students submit assignments via Pull Requests to their forked repositories:

1. **Review PR**: Check code quality, security practices, documentation
2. **Provide feedback**: Line-by-line code review comments
3. **Request changes**: If needed, ask for revisions
4. **Approve & grade**: Record final grade in Canvas
5. **Merge (optional)**: Student can merge their PR after approval

### Directory Structure Monitoring
Student assignments are organized as:
```
assignments/
├── CSCI347_f25_John_Smith/
├── CSCI347_f25_Jane_Doe/
├── CSCI347_f25_Mike_Johnson/
└── ...
```

Each student directory contains:
```
CSCI347_f25_Student_Name/
├── week01/password_vault.py, README.md, tests/, examples/
├── week02/hash_verification.py, README.md, tests/, examples/  
├── week03/certificate_analyzer.py, README.md, tests/, examples/
└── ...
```

## 🔧 Course Maintenance

### Updating Course Materials
- **Student-facing content**: Update files in root directory and week folders
- **Quick references**: Update quick-reference/ directory
- **Setup guides**: Maintain setup/ directory

### New Semester Preparation
1. Update all date references
2. Review and update reading links
3. Test all validation scripts
4. Update Canvas course with new quiz banks
5. Create new GitHub classroom or assignment system

## 🤖 AI Collaboration Disclosure

### **Human-AI Collaboration Model**
- **Human Expertise**: Provided domain knowledge, pedagogical requirements, and quality judgment
- **AI Assistance**: Handled systematic implementation, pattern recognition, and comprehensive documentation
- **Iterative Process**: Continuous feedback loops ensured educational goals and professional standards were met

### **AI as Tool Philosophy**
**AI is a tool, nothing more.** It is through the deliberate use of this tool that we are able to understand its strengths and limitations. In this course development:
- **AI Strengths**: Pattern recognition, systematic implementation, comprehensive documentation generation
- **AI Limitations**: No pedagogical judgment, no domain expertise, no understanding of student needs, tendency to over-generate content and create distractions from core objectives
- **Human Control**: All educational decisions, quality standards, and learning outcomes remained under human direction

This approach demonstrates how thoughtful AI integration can enhance educational resource development while maintaining the human expertise essential for effective teaching.

---

**Note**: Keep this directory private and do not share with students. All student-facing materials are in the main course directories.