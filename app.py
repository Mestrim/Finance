import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import re

from helpers import apology, login_required, lookup, usd, check_password_strength

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    if not session:
        return render_template("login.html")

    """Show portfolio of stocks"""
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = cash[0]["cash"]

    wallet = []
    total_stocks_value = 0
    # If str is a SELECT, then execute returns a list of zero or more dict objects, inside of which are keys and values representing a table’s fields and cells, respectively.
    rows = db.execute(
        "SELECT symbol, count FROM wallet WHERE user_id = ?", session["user_id"]
    )
    for stock in rows:
        wallet_keys = ["symbol", "count", "price", "value"]
        wallet_dict = dict.fromkeys(wallet_keys)
        wallet_dict["symbol"] = stock["symbol"]

        current_price = lookup(stock["symbol"])
        current_price = current_price["price"]
        wallet_dict["price"] = usd(current_price)

        count = stock["count"]
        wallet_dict["count"] = count

        value = current_price * count
        wallet_dict["value"] = usd(value)

        wallet.append(wallet_dict)

        total_stocks_value += current_price * count
    total = total_stocks_value + cash
    total = usd(total)
    cash = usd(cash)
    return render_template("index.html", cash=cash, total=total, wallet=wallet)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 400)

        stock = request.form.get("symbol")
        stock = lookup(stock)

        if not stock:
            return apology("Stock name dosen't exist", 400)

        stock_symbol = stock["symbol"]

        if not request.form.get("shares"):
            return apology("must provide shares number to buy", 400)

        shares = request.form.get("shares")

        if not (shares.isdecimal() and int(shares) > 0):
            return apology("Number must be a positive integer", 400)

        shares = int(shares)
        # List of dictionaries return of value current session id user
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        # Get value from key value pair from dictionary
        cash = cash[0]["cash"]
        # Stock is dictionary from html form request
        price = stock["price"]

        shares = int(shares)
        total = cash - (price * shares)
        rounded_total = round(total, 2)
        total = rounded_total

        if total < 0:
            return apology("Insufficent funds", 403)

        # If str is an INSERT, and the table into which data was inserted contains an autoincrementing PRIMARY KEY, then execute returns the value of the newly inserted row’s primary key.
        transaction_id = db.execute(
            "INSERT INTO buying_transactions (user_id) VALUES (?)", session["user_id"]
        )

        # Get last transaction ID
        # transaction_id = db.execute("SELECT transaction_id FROM buying_transactions WHERE user_id = ? ORDER BY transaction_id DESC LIMIT 1", session["user_id"])
        # transaction_id = transaction_id[0]['transaction_id']

        # add to stock purchase table
        db.execute(
            "INSERT INTO stock_purchases (transaction_id, stock_symbol, quantity, unit_price) VALUES (?, ?, ?, ?)",
            transaction_id,
            stock_symbol,
            shares,
            price,
        )
        # Update user balance
        db.execute("UPDATE users SET cash = ? WHERE id = ?", total, session["user_id"])

        # Add new stock to user wallet
        rows = db.execute(
            "SELECT symbol FROM wallet WHERE user_id = ?", session["user_id"]
        )
        for symbol in rows:
            if stock_symbol in symbol["symbol"]:
                rows = db.execute(
                    "SELECT count FROM wallet WHERE symbol = ? AND user_id = ?",
                    stock_symbol,
                    session["user_id"],
                )
                count = rows[0]["count"]
                db.execute(
                    "UPDATE wallet SET count = ? WHERE user_id = ? AND symbol = ?",
                    count + shares,
                    session["user_id"],
                    stock_symbol,
                )
                flash("Bought !")
                return redirect("/")

        db.execute(
            "INSERT INTO wallet (user_id, symbol, count) VALUES (?, ?, ?)",
            session["user_id"],
            stock_symbol,
            shares,
        )
        flash("Bought !")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = []

    purchases = db.execute(
        "SELECT purchase_datetime, stock_symbol, quantity, unit_price FROM stock_purchases WHERE transaction_id IN (SELECT transaction_id FROM buying_transactions WHERE user_id = ?)",
        session["user_id"],
    )
    for row in purchases:
        history_keys = ["time", "symbol", "count", "price", "operation"]
        history_dict = dict.fromkeys(history_keys)
        history_dict["time"] = row["purchase_datetime"]
        history_dict["symbol"] = row["stock_symbol"]
        history_dict["count"] = row["quantity"]
        history_dict["price"] = usd(row["unit_price"])
        history_dict["operation"] = "BOUGHT"
        history.append(history_dict)

    sales = db.execute(
        "SELECT sale_datetime, stock_symbol, quantity, unit_price FROM stock_sales WHERE transaction_id IN (SELECT transaction_id FROM selling_transactions WHERE user_id = ?)",
        session["user_id"],
    )
    for row in sales:
        history_keys = ["time", "symbol", "count", "price", "operation"]
        history_dict = dict.fromkeys(history_keys)
        history_dict["time"] = row["sale_datetime"]
        history_dict["symbol"] = row["stock_symbol"]
        history_dict["count"] = "-" + str(row["quantity"])
        history_dict["price"] = usd(row["unit_price"])
        history_dict["operation"] = "SOLD"
        history.append(history_dict)

    return render_template("history.html", history=history)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        # Ensure password confirmation was submitted
        if (
            not request.form.get("password")
            or not request.form.get("confirmation")
            or not request.form.get("newpassword")
        ):
            return apology("must provide passwords", 403)

        elif not (request.form.get("newpassword") == request.form.get("confirmation")):
            return apology("passwords not match", 403)

        # Query database for password
        rows = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])

        # Ensure password exists
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid password", 403)

        new_hash = generate_password_hash(request.form.get("confirmation"))
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?", new_hash, session["user_id"]
        )

        # Redirect user to home page
        flash("Password changed !")
        return redirect("/")
    return render_template("changepassword.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        if request.form.get("symbol") is None:
            return apology("invalid symbol", 400)

        company = request.form.get("symbol")
        company = lookup(company)

        if not company or company is None:
            return apology("stock symbol not exist", 400)

        symbol = company["symbol"]
        price = usd(company["price"])

        return render_template("quoted.html", symbol=symbol, price=price)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("must provide password", 400)

        elif not (request.form.get("password") == request.form.get("confirmation")):
            return apology("passwords not match", 400)

        # Example usage
        password_to_check = request.form.get("confirmation")
        if not check_password_strength(password_to_check):
            return apology("Password not meet criteria", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username not exists
        if len(rows) != 0:
            return apology("username already exist", 400)

        # Add user to database
        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("confirmation"))
        db.execute("INSERT INTO users (username, hash) VALUES (? , ?)", username, hash)

        # Login user
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]

        # Redirect user to login page
        flash("Register succesful !")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        if session:
            return apology("Please log out", 521)
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    wallet = []
    rows = db.execute("SELECT symbol FROM wallet WHERE user_id = ?", session["user_id"])
    n = 0
    for symbol in rows:
        symbol = rows[n]["symbol"]
        wallet.append(symbol)
        n += 1

    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("choose stock to sell", 403)

        if symbol not in wallet:
            return apology("stock not own", 403)

        shares = request.form.get("shares")
        if not shares:
            return apology("provide share number", 403)

        if not shares.isdecimal() or int(shares) <= 0:
            return apology("Number must be positive integer", 403)

        shares = int(shares)
        rows = db.execute(
            "SELECT count FROM wallet WHERE user_id = ? AND symbol = ?",
            session["user_id"],
            symbol,
        )
        count = rows[0]["count"]
        if count < shares:
            return apology("not enough stocks", 400)

        stock = lookup(symbol)
        price = stock["price"]
        total = price * shares
        count = count - shares

        # If str is an INSERT, and the table into which data was inserted contains an autoincrementing PRIMARY KEY, then execute returns the value of the newly inserted row’s primary key.
        transaction_id = db.execute(
            "INSERT INTO selling_transactions (user_id) VALUES (?)", session["user_id"]
        )
        # Get last transaction ID

        # transaction_id = db.execute("SELECT transaction_id FROM selling_transactions WHERE user_id = ? ORDER BY transaction_id DESC LIMIT 1", session["user_id"])
        # transaction_id = transaction_id[0]['transaction_id']

        # add to stock purchase table
        db.execute(
            "INSERT INTO stock_sales (transaction_id, stock_symbol, quantity, unit_price) VALUES (?, ?, ?, ?)",
            transaction_id,
            symbol,
            shares,
            price,
        )

        # update wallet
        db.execute(
            "UPDATE wallet SET count = ? WHERE user_id = ? AND symbol = ?",
            count,
            session["user_id"],
            symbol,
        )

        # Update user balance
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = cash[0]["cash"]
        total = cash + total
        rounded_total = round(total, 2)
        total = rounded_total
        db.execute("UPDATE users SET cash = ? WHERE id = ?", total, session["user_id"])
        db.execute(
            "DELETE FROM wallet WHERE count = 0 AND user_id = ?", session["user_id"]
        )
        flash("Sold !")
        return redirect("/")

    return render_template("sell.html", wallet=wallet)


@app.route("/addcash", methods=["GET", "POST"])
@login_required
def addcash():
    if request.method == "POST":
        cash = request.form.get("cash")

        if not cash:
            return apology("Provide cash to add", 403)

        pattern = r"^\d{0,7}(\d{1,2}([.,]\d{1,2})?)?$"
        # Use re.match to check if the value matches the pattern
        is_valid = bool(re.match(pattern, cash))
        if not is_valid:
            return apology("Invalid number", 403)

        cash = cash.replace(",", ".")
        cash = float(cash)

        if cash <= 0:
            return apology("Number must be greater than 0", 403)

        db.execute(
            "INSERT INTO cash_transactions(user_id, amount) VALUES (?,?)",
            session["user_id"],
            cash,
        )
        currentcash = db.execute(
            "SELECT cash FROM users WHERE id=?", session["user_id"]
        )
        currentcash = currentcash[0]["cash"]
        currentcash += cash
        db.execute(
            "UPDATE users SET cash = ? WHERE id =?", currentcash, session["user_id"]
        )

        flash("Cash added !")
        return redirect("/")
    else:
        currentcash = db.execute(
            "SELECT cash FROM users WHERE id=?", session["user_id"]
        )
        currentcash = usd(currentcash[0]["cash"])
        return render_template("addcash.html", currentcash=currentcash)
