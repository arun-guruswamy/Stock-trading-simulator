from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash

shares = "try"

db = SQL("sqlite:///finance.db")

if not type(shares) is int:
    print(shares)
        