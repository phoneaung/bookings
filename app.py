import datetime
import os
from flask import Flask, flash, redirect, render_template, request, session
from cs50 import sql
from werkzeug.security import check_password_hash, generate_password_hash

# configure application
app = Flask(__name__)

# configure cs50 library to use sqlite database
db = SQL("sqlite:///bookings.db")

# API keys 

# log in
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
    

# log out
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


# register
@app.route("/register")
def register():
    # forget any user id
    session.clear()

    if request.method == "GET":
        return render_template("register.html")
    
    else:
        username = request.form.get("username")
        password = request.form.get("passwor")
        confirmation = request.form.get("confirmation")

        # If username is not provided, render apology page
        if not username:
            return apology("Provide username!", 403)

        # If password is not provided, render apology page
        if not password:
            return apology("Provide username", 403)

        # Make sure passwords are matched
        if not confirmation:
            return apology("Passwords is not matched!", 403)

        hash = generate_password_hash(password)

        # Query database to make sure username is not already taken. If the username is good to go, insert username and password hash into database
        try:
            new_user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except:
            return apology("Username is already taken!", 403)

        session["user_id"] = new_user

        # Redirect to login page after the account has been created
        return redirect("/")


