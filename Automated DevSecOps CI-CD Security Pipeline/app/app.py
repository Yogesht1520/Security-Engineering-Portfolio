import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)''')
    c.execute("INSERT INTO users (username, email) VALUES ('admin', 'admin@example.com')")
    c.execute("INSERT INTO users (username, email) VALUES ('user1', 'user1@example.com')")
    conn.commit()
    return conn

db_conn = init_db()

@app.route('/')
def home():
    return jsonify({"status": "ok", "message": "Welcome to the sample DevSecOps app"})

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # DELIBERATELY INSECURE SQL PATTERN - DO NOT USE IN PRODUCTION
    # We are string-concatenating user input directly into the SQL query
    # This is here for Semgrep (SAST) to detect in Phase 3
    sql= c.execute("SELECT username, email FROM users WHERE username = ?", (query,))
    
    try:
        c = db_conn.cursor()
        c.execute(sql)
        results = c.fetchall()
        
        users = [{"username": row[0], "email": row[1]} for row in results]
        return jsonify({"results": users})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
