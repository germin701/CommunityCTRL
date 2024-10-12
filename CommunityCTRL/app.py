from flask import Flask, render_template, g
import sqlite3

app = Flask(__name__)


# Helper function to get a database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('instance/database.db')
    return db


# Route to display user data on the homepage
@app.route('/')
def home():
    db = get_db()
    cur = db.execute('SELECT * FROM user')
    users = cur.fetchall()
    return render_template('index.html', users=users)


if __name__ == '__main__':
    app.run(debug=True)
