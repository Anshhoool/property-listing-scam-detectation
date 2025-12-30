import sqlite3


conn = sqlite3.connect('listings.db')
c = conn.cursor()


c.execute('''
CREATE TABLE IF NOT EXISTS listings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    price TEXT,
    beds TEXT,
    baths TEXT,
    description TEXT,
    image TEXT,
    contact_email TEXT
)
''')

conn.commit()
conn.close()
print(" Database and table created successfully!")
