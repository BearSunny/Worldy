# Set up Flask application
import os
from flask import Flask, flash, request, jsonify, render_template, redirect, url_for, session
from flask_session import Session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
import pymongo
from pymongo import MongoClient
import jwt
import cloudinary
import cloudinary.uploader
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from helpers import login_required

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Connect to MongoDB
client = MongoClient("connection_string_here")
db = client["your_database_name"]
users_collection = db["users"]

# JWT secret key #TODO

# Cloudinary config #TODO

@app.route("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Please fill in all fields!")
            return redirect("/login")

        # Get user's data from MongoDB database
        user = users_collection.find_one({"email": email})

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid username and/or password")
            return redirect("/login")
        
        # Remember which user has logged in
        session["user_id"] = str(user["_id"])

        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Sign user up"""
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if not username or not email or not password:
            flash("Please fill in all fields!")
            return redirect("/signup")
        
        user = users_collection.find_one({"username": username})

        if user:
            flash("This username already exists!")
            return redirect("/signup")
        
        hash_pass = generate_password_hash(password)
        
        userDatabase = {
            "username" : username,
            "email" : email,
            "password_hash" : hash_pass
        }
        users_collection.insert_one(userDatabase)
        flash("Account created successfully! Please log in.")
        return redirect("/login") 
    else:
        return render_template("signup.html")


@app.route("/login/google", methods=["GET", "POST"])
def google_login():
    """Log_in using Google"""


@app.route("/authorize/google", methods=["GET", "POST"])
def google_auth():
    """Authorize users"""