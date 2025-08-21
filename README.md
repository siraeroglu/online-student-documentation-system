# Online Student Documentation System (OSDS)

The **Online Student Documentation System (OSDS)** is a secure and distributed web platform designed to manage student document requests efficiently.  
It enables three main roles — **Sysadmin**, **Staff**, and **Student** — to handle tasks such as student registration, document requests, payment processing, and secure document delivery.

## Key Features
- **Role-based Access Control:** Sysadmin, staff, and student modules with separate privileges.
- **Secure Data Handling:** 
  - DES encryption for student records  
  - RSA digital signatures for document authenticity  
  - 48-bit hash function for integrity
- **Workflow Automation:** Document request, approval, payment, and secure delivery processes.
- **Distributed Architecture:** Server–client model for handling concurrent requests.
- **Payment Security:** Encrypted transactions with Message Authentication Codes (MAC).

## Technology Stack
- **Backend:** Python (Flask), Werkzeug, Gunicorn  
- **Frontend:** HTML, CSS, JavaScript, jQuery, AJAX  
- **Database:** PostgreSQL (psycopg2), DBeaver for visualization  
- **Containerization:** Docker for PostgreSQL and application deployment  
- **Security:** DES, RSA digital signatures, HTTPS protocol  
- **Testing & Development:** Postman, Unittest, Browser Dev Tools, VS Code, Git/GitHub

## Architecture
The system uses a **distributed architecture**:
- **Server Host:** Handles database management, encryption, digital signing, and RESTful API endpoints.  
- **Client Host:** Provides a responsive web interface for all user roles with real-time interactions.

## Advantages
- **High Security:** DES and RSA encryption ensure data confidentiality and authenticity.  
- **Automation:** Reduces manual errors and speeds up document workflows.  
- **Accessibility:** Web-based interface accessible from any location.  
- **Scalable:** Designed to handle concurrent multi-user operations efficiently.

## Getting Started
1. Clone this repository:
   ```bash
   git clone https://github.com/<your-username>/online-student-documentation-system.git
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
3. Run the application:
   ```bash
   python app.py
