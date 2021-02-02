import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    index = []
    grand_total = 0
    user_id = session["user_id"]
    symbols = db.execute("SELECT company, SUM(number_of_shares) FROM purchases WHERE user_id = ? GROUP BY company", user_id)
    for symbol in symbols:
        lookup_info = lookup(symbol['company'])
        lookup_info['shares'] = symbol['SUM(number_of_shares)']
        total_value = symbol['SUM(number_of_shares)'] * lookup_info['price']
        lookup_info['total'] = usd(total_value)
        index.append(lookup_info)
        grand_total += total_value
    balance = int(db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash'])
    grand_total += balance
    return render_template("index.html", index=index, balance=usd(balance), grand_total=usd(grand_total))
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        user_id = session["user_id"]
        if len(symbol) == 0:
            return apology("Please type a symbol")
        if lookup(symbol) == None:
            return apology("Symbol does not exist")
        if not shares.isnumeric():
            return apology("Please enter a positive number")
        shares = int(shares)
        if shares < 0:
            return apology("Please enter a positive number")
        info = lookup(symbol)
        current_price = info["price"]
        company = info["symbol"]
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash']
        if (shares * current_price) > user_cash:
            return apology("Not enough funds")
        purchase = shares * current_price
        balance = user_cash - purchase
        db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, user_id)
        db.execute("INSERT INTO purchases (user_id, company, price, number_of_shares) VALUES(?, ?, ?, ?)", user_id, company, current_price, shares)
        return redirect("/")
#        return render_template("buy.html", total=usd(purchase), m="Purchase successful! Total:")
    else:
        return render_template("buy.html")
    """Buy shares of stock"""
    return apology("TODO")


@app.route("/history")
@login_required
def history():
    transactions = db.execute("SELECT * FROM purchases")
    for transaction in transactions:
        if int(transaction['number_of_shares']) < 0:
            transaction['type'] = "Sold"
        else:
            transaction['type'] = "Bought"
    return render_template("history.html", transactions=transactions)
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        if quote == None:
            return apology("Company does not exist")
        name = quote['name']
        price = usd(quote['price'])
        return render_template("quoted.html", name=name, price=price)
    else:
        return render_template("quote.html")
    """Get stock quote."""
    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if len(password) < 8:
            return apology("Password has to be atleast 8 characters")
        password2 = request.form.get("confirmation")
        user_list = db.execute(f"SELECT username FROM users")
        for user in user_list:
            if username in user.values():
                return apology("Username already exists")
        if len(username) == 0 or len(password) == 0 or len(password2) == 0:
            return render_template("register.html", sorry="Please make sure all values are entered")
        if password != password2:
            return apology("Passwords do not match")
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))
        return redirect("/login")
    else:
        return render_template("register.html")
    """Register user"""
    return apology("TODO")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symb = request.form.get("symbol")
        i = 0
        if len(symb) == 0:
            return apology("Please pick a company")
        index = []
        user_id = session["user_id"]
        symbols = db.execute("SELECT company, SUM(number_of_shares) FROM purchases WHERE user_id = ? GROUP BY company", user_id)
        for symbol in symbols:
            lookup_info = lookup(symbol['company'])
            if lookup_info['symbol'] == symb:
                j = i
            lookup_info['shares'] = symbol['SUM(number_of_shares)']
            total_value = round(symbol['SUM(number_of_shares)'] * lookup_info['price'])
            lookup_info['total'] = total_value
            index.append(lookup_info)
            i += 1
        selected_company = index[j]
        shares = int(request.form.get("shares"))
        if shares < 0 or shares > selected_company['shares']:
            return apology("You do not own that many shares of that company")
        cash = int(db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash'])
        balance = cash + (shares * selected_company['price'])
        db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, user_id)
        db.execute("INSERT INTO purchases (user_id, company, price, number_of_shares) VALUES(?, ?, ?, ?)",
                    user_id, selected_company['symbol'], selected_company['price'], -(shares))
        return redirect("/")
    else:
        index = []
        user_id = session["user_id"]
        symbols = db.execute("SELECT company, SUM(number_of_shares) FROM purchases WHERE user_id = ? GROUP BY company", user_id)
        for symbol in symbols:
            lookup_info = lookup(symbol['company'])
            lookup_info['shares'] = symbol['SUM(number_of_shares)']
            total_value = round(symbol['SUM(number_of_shares)'] * lookup_info['price'])
            lookup_info['total'] = total_value
            index.append(lookup_info)
        return render_template("sell.html", index=index)
    """Sell shares of stock"""
    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
