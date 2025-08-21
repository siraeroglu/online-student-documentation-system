import psycopg2

def get_db_connection():
    conn = psycopg2.connect(
        host="localhost",
        database="osds",
        user="postgres",  # PostgreSQL kullanıcı adınız
        password="19921978"  # PostgreSQL şifreniz
    )
    return conn
