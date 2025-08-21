from db import get_db_connection
from crypto import encrypt_des

# DES Key (admin tarafından belirlenmiş olmalı)
DES_KEY = b'your_secret_key_12345678' 

# Kullanıcı Ekleme Fonksiyonu
def add_user(username, password, role):
    conn = get_db_connection()
    cur = conn.cursor()
    encrypted_password = encrypt_des(DES_KEY, password).hex()  # Şifreleme
    cur.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                (username, encrypted_password, role))
    conn.commit()
    cur.close()
    conn.close()
    print(f"Kullanıcı eklendi: {username} ({role})")

# Kullanıcıları ekleyin
add_user('admin', 'adminpass', 'admin')
add_user('staff1', 'staffpass', 'staff')
add_user('student1', 'studentpass', 'student')
add_user('student1', '19921978', 'student')
