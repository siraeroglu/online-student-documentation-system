from flask import Flask, session, request, render_template, redirect, url_for, flash
from db import get_db_connection
from crypto import encrypt_des, decrypt_des, generate_rsa_key_pair, sign_with_rsa, verify_rsa_signature
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_flask_key'

# DES Key
DES_KEY = b'your_secret_key_12345678'  # Total 24 bytes

# RSA Keys
PRIVATE_KEY, PUBLIC_KEY = generate_rsa_key_pair()


### ---- HOME AND LOGIN ---- ###
@app.route('/')
def home():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    des_key = request.form['des_key'].encode()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, password, role FROM users WHERE username = %s", (username,))
    result = cur.fetchone()

    if result:
        user_id, encrypted_password, role = result
        decrypted_password = decrypt_des(des_key, bytes.fromhex(encrypted_password))
        if decrypted_password == password:
            # Set session info
            session['user_id'] = user_id
            session['role'] = role
            flash("Login successful!", "success")
            return redirect(url_for('dashboard', role=role))
        else:
            flash("Invalid password.", "danger")
    else:
        flash("User not found.", "danger")

    cur.close()
    conn.close()
    return redirect(url_for('home'))







### ---- DASHBOARD REDIRECTION ---- ###
@app.route('/dashboard')
def dashboard():
    role = session.get('role')  # Get role from session
    if role == 'admin':
        return render_template('admin_dashboard.html')
    elif role == 'staff':
        return render_template('staff_dashboard.html')
    elif role == 'student':
        return redirect(url_for('view_student_requests'))  # View student requests
    else:
        return "Unauthorized access!", 403








### ---- ADMIN FUNCTIONS ---- ###
@app.route('/add_user', methods=['POST'])
def add_user():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Şifreyi DES ile şifrele
        encrypted_password = encrypt_des(DES_KEY, password).hex()

        # Kullanıcıyı users tablosuna ekle ve ID'sini döndür
        cur.execute("""
            INSERT INTO users (username, password, role)
            VALUES (%s, %s, %s) RETURNING id
        """, (username, encrypted_password, role))
        user_id = cur.fetchone()[0]

        # Eğer kullanıcı "student" ise students tablosuna da ekle
        if role == 'student':
            cur.execute("""
                INSERT INTO students (id, name, gpa, cgpa)
                VALUES (%s, %s, NULL, NULL)
            """, (user_id, username))

        # Eğer kullanıcı "staff" ise staff tablosuna da ekle
        elif role == 'staff':
            cur.execute("""
                INSERT INTO staff (id, name, position)
                VALUES (%s, %s, 'Unknown')
            """, (user_id, username))

        # Veritabanını güncelle
        conn.commit()
        flash(f"{role.capitalize()} successfully added. ID: {user_id}", "success")
    except Exception as e:
        print(f"Error: {e}")
        flash("Error adding user.", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('dashboard', role='admin'))


@app.route('/update_des_key', methods=['POST'])
def update_des_key():
    new_key = request.form['new_key']
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Yeni DES Key'i veritabanına kaydet
        cur.execute("INSERT INTO keys (key_type, key_value) VALUES ('DES', %s)", (new_key,))
        conn.commit()
        flash("DES key successfully updated.", "success")
    except Exception as e:
        print(f"Error: {e}")
        flash("Error updating DES key.", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('dashboard', role='admin'))








### ---- STAFF FUNCTIONS ---- ###

@app.route('/update_grades', methods=['POST'])
def update_grades():
    if 'role' not in session or session['role'] != 'staff':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('home'))

    student_id = request.form['student_id']
    gpa = request.form['gpa']
    cgpa = request.form['cgpa']

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE students SET gpa = %s, cgpa = %s WHERE id = %s", (gpa, cgpa, student_id))
        conn.commit()
        flash("Student grades updated.", "success")
    except Exception as e:
        print(f"Error updating grades: {e}")
        flash("Error updating grades.", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('dashboard', role='staff'))


@app.route('/view_requests', methods=['GET'])
def view_requests():
    if 'role' not in session or session['role'] != 'staff':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('home'))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT r.id, s.name, r.document_type, r.status 
            FROM requests r
            JOIN students s ON r.student_id = s.id
        """)
        requests = cur.fetchall()
    except Exception as e:
        print(f"Error fetching requests: {e}")
        requests = []
    finally:
        cur.close()
        conn.close()

    return render_template('staff_requests.html', requests=requests)


@app.route('/process_request', methods=['POST'])
def process_request():
    if 'role' not in session or session['role'] != 'staff':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('home'))

    request_id = request.form['request_id']
    status = request.form['status']

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("UPDATE requests SET status = %s WHERE id = %s", (status, request_id))
        if status == 'approved':
            amount = 100.00
            cur.execute("""
                INSERT INTO invoices (request_id, amount, payment_status) 
                VALUES (%s, %s, 'unpaid') RETURNING id
            """, (request_id, amount))
            invoice_id = cur.fetchone()[0]

            invoice_data = f"Invoice-{invoice_id}-{amount}"
            signature = sign_with_rsa(PRIVATE_KEY, invoice_data.encode())
            cur.execute("INSERT INTO keys (key_type, key_value) VALUES ('RSA-Signature', %s)", (signature.hex(),))
            flash(f"Invoice created and signed with RSA. Invoice ID: {invoice_id}", "success")

        conn.commit()
        flash("Request successfully processed.", "success")
    except Exception as e:
        print(f"Error processing request: {e}")
        flash("Error processing request.", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('view_requests'))


@app.route('/view_invoices', methods=['GET'])
def view_invoices():
    if 'role' not in session or session['role'] != 'staff':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('home'))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT i.id, r.id AS request_id, s.name, i.amount, i.payment_status 
            FROM invoices i
            JOIN requests r ON i.request_id = r.id
            JOIN students s ON r.student_id = s.id
        """)
        invoices = cur.fetchall()
    except Exception as e:
        print(f"Error fetching invoices: {e}")
        invoices = []
    finally:
        cur.close()
        conn.close()

    return render_template('staff_invoices.html', invoices=invoices)


@app.route('/deliver_document/<int:request_id>', methods=['POST'])
def deliver_document(request_id):
    if 'role' not in session or session['role'] != 'staff':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('home'))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT payment_status FROM invoices WHERE request_id = %s", (request_id,))
        result = cur.fetchone()

        if not result:
            flash("No invoice found for the given request.", "danger")
            return redirect(url_for('view_requests'))

        payment_status = result[0]
        if payment_status == 'paid':
            cur.execute("SELECT document_type FROM requests WHERE id = %s", (request_id,))
            document_type = cur.fetchone()[0]
            document_data = f"Document-{request_id}-{document_type}"
            signature = sign_with_rsa(PRIVATE_KEY, document_data.encode())
            flash("Document successfully delivered.", "success")
            print(f"Document: {document_data}, Signature: {signature.hex()}")
        else:
            flash("Document cannot be delivered. Payment not made.", "danger")
    except Exception as e:
        print(f"Error delivering document: {e}")
        flash("Error delivering document.", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('view_requests'))

@app.route('/view_receipt/<int:request_id>', methods=['GET'])
def view_receipt(request_id):
    if 'role' not in session or session['role'] != 'staff':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('home'))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT receipt_path FROM invoices WHERE request_id = %s", (request_id,))
        result = cur.fetchone()
        if result and result[0]:
            receipt_path = result[0]
            return redirect(f'/{receipt_path}')  # Redirect to the file
        else:
            flash("No receipt uploaded for this request.", "danger")
    except Exception as e:
        print(f"Error viewing receipt: {e}")
        flash("An error occurred while fetching the receipt.", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('view_requests'))

@app.route('/update_keys', methods=['POST'])
def update_keys():
    if 'role' not in session or session['role'] != 'staff':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('home'))

    new_des_key = request.form['new_des_key'].encode()
    new_private_key, new_public_key = generate_rsa_key_pair()

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("INSERT INTO keys (key_type, key_value) VALUES ('DES', %s)", (new_des_key.hex(),))
        cur.execute("INSERT INTO keys (key_type, key_value) VALUES ('RSA-Private', %s)", (new_private_key.private_bytes().hex(),))
        cur.execute("INSERT INTO keys (key_type, key_value) VALUES ('RSA-Public', %s)", (new_public_key.public_bytes().hex(),))
        conn.commit()
        flash("DES and RSA keys updated successfully.", "success")
    except Exception as e:
        print(f"Error updating keys: {e}")
        flash("Error updating keys.", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('dashboard'))
    







### ---- STUDENT FUNCTIONS ---- ###

# DES Key and RSA Keys
DES_KEY = b'your_secret_key_12345678'
PRIVATE_KEY, PUBLIC_KEY = generate_rsa_key_pair()

# Student creates document request
@app.route('/request_document', methods=['POST'])
def request_document():
    if 'user_id' not in session or session['role'] != 'student':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('home'))

    document_type = request.form['document_type']
    current_user_id = session['user_id']  # Dynamic session ID

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Create request
        cur.execute("INSERT INTO requests (student_id, document_type, status) VALUES (%s, %s, 'pending') RETURNING id",
                    (current_user_id, document_type))
        request_id = cur.fetchone()[0]

        # Create invoice
        cur.execute("INSERT INTO invoices (request_id, amount, payment_status) VALUES (%s, %s, 'unpaid')",
                    (request_id, 75.00))  # Example document fee
        conn.commit()
        flash(f"Your document request has been successfully received. Request ID: {request_id}", "success")
    except Exception as e:
        print(f"Error: {e}")
        flash("An error occurred during the document request.", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('view_student_requests'))


# Student views requested documents and invoices
@app.route('/view_student_requests')
def view_student_requests():
    if 'user_id' not in session or session['role'] != 'student':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('home'))

    current_user_id = session['user_id']

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT r.id, r.document_type, r.status, i.payment_status, i.amount
            FROM requests r
            LEFT JOIN invoices i ON r.id = i.request_id
            WHERE r.student_id = %s
        """, (current_user_id,))
        requests = cur.fetchall()
    except Exception as e:
        print(f"Error: {e}")
        flash("An error occurred while fetching your requests.", "danger")
        requests = []
    finally:
        cur.close()
        conn.close()

    return render_template('student_requests.html', requests=requests)

# Student pays the invoice


import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/pay_invoice/<int:request_id>', methods=['POST'])
def pay_invoice(request_id):
    if 'user_id' not in session or session['role'] != 'student':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('home'))

    if 'receipt' not in request.files:
        flash("No receipt file uploaded.", "danger")
        return redirect(url_for('view_student_requests'))

    file = request.files['receipt']
    if file.filename == '':
        flash("No file selected.", "danger")
        return redirect(url_for('view_student_requests'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        receipt_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(receipt_path)

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                UPDATE invoices 
                SET payment_status = 'paid', receipt_path = %s 
                WHERE request_id = %s
            """, (receipt_path, request_id))
            conn.commit()
            flash("Your payment and receipt have been successfully uploaded.", "success")
        except Exception as e:
            print(f"Error: {e}")
            flash("An error occurred during the payment.", "danger")
        finally:
            cur.close()
            conn.close()
    else:
        flash("Invalid file type. Allowed types: png, jpg, jpeg, pdf.", "danger")

    return redirect(url_for('view_student_requests'))


# Student verifies and shows the RSA signed document
@app.route('/verify_document/<int:request_id>', methods=['POST'])
def verify_document(request_id):
    if 'user_id' not in session or session['role'] != 'student':
        flash("Yetkisiz erişim!", "danger")
        return redirect(url_for('home'))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT i.payment_status, r.document_path 
            FROM invoices i 
            JOIN requests r ON i.request_id = r.id 
            WHERE i.request_id = %s
        """, (request_id,))
        result = cur.fetchone()

        if result and result[0] == 'paid':  # Check if payment is completed
            document_path = result[1]
            if document_path:  # Check if the document is ready
                flash("Document successfully displayed.", "success")
                return render_template('verified_document.html', document_path=document_path)
            else:
                flash("Document is not ready yet.", "warning")
        else:
            flash("Document cannot be displayed without payment.", "danger")
    except Exception as e:
        print(f"Error verifying document: {e}")
        flash("An error occurred while verifying the document.", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('view_student_requests'))


@app.route('/logout')
def logout():
    # Kullanıcı oturumunu temizle
    session.clear()
    flash("You have been logged out.", "success")
    # Doğru yönlendirme
    return redirect(url_for('home'))  # Eğer route'unuzun adı 'home' ise








### ---- MAIN ---- ###
if __name__ == '__main__':
    app.run(debug=True)
