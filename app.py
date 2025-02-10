# Set up Flask application
import os
from flask import Flask, flash, request, jsonify, render_template, redirect, url_for, session
from flask_session import Session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
from datetime import timedelta
from datetime import timezone
import pymongo
from pymongo import MongoClient
import jwt
import cloudinary
import cloudinary.uploader
import requests
from authlib.integrations.flask_client import OAuth
from api_key import *
import cloudinary
from cloudinary.uploader import upload

from helpers import login_required

app = Flask(__name__)
app.secret_key = 'minh173'

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Google Auth Configuration
app.config['GOOGLE_CLIENT_ID'] = CLIENT_ID  
app.config['GOOGLE_CLIENT_SECRET'] = CLIENT_SECRET  
app.secret_key = 'minh17sunny3'  

# Connect to MongoDB
client = MongoClient("mongodb+srv://minh:RlQqxKyuAhhhms4C@cluster0.hlktt.mongodb.net/user_data?retryWrites=true&w=majority")
db = client["user_data"]
users_collection = db["users"]
posts_collection = db["posts"] # Track uploaded photos and blogs

# Google Authentication
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope' : 'openid profile email'},
)

# Cloudinary config
cloudinary.config(
    cloud_name = "dqbpvc8a7",
    api_key = "476672167887836",
    api_secret = "WATdRqlyXx0DuelbjGRYAKyehNo",
    secure = True
)

@app.route("/")
# This is the sign-up/login/login-with-google page
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        remember = request.form.get("remember") # Checkbox

        if not email or not password:
            flash("Please fill in all fields!")
            return render_template("login.html")

        # Get user's data from MongoDB database
        user = users_collection.find_one({"email": email})

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid username and/or password")
            return render_template("login.html")
        
        # Remember which user has logged in
        session["user_id"] = str(user["_id"])

        # Remember users for 30 days
        if remember:
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=30)
        
        return redirect("/main")
    else:
        return render_template("login.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Reset password"""
    if request.method == "POST":
        email = request.form.get("email")
        new_password = request.form.get("new_password")

        if not email or not new_password:
            flash("Please fill in all fields!")
            return render_template("reset_password.html")
        
        user = users_collection.find_one({"email" : email})
        if user:
            hash_password = generate_password_hash(new_password)
            users_collection.update_one({"email": email}, {"$set": {"password_hash": hash_password}})
        else:
            flash("User with this email does not exist!")
            return redirect("/signup")
    else:
        return render_template("reset_password.html")


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
            return render_template("signup.html")
        
        user = users_collection.find_one({"username": username})

        if user:
            flash("This username already exists!")
            return render_template("signup.html")
        
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


@app.route("/login/google")
def google_login():
    """Log_in using Google"""
    try:
        redirect_uri = url_for('google_authorize', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        flash(f"Error during login: {str(e)}")
        return redirect(url_for('login'))


@app.route("/authorize/google")
def google_authorize():
    """Authorize users for Google"""
    try:
        token = google.authorize_access_token()
        userinfo_endpoint = google.server_metadata['userinfo_endpoint']
        resp = google.get(userinfo_endpoint)
        user_info = resp.json()
        username = user_info['email']

        # Connect to MongoDB
        user = users_collection.find_one({"email" : username})
        if not user:
            new_user = {
                "username": user_info.get("name", ""),
                "email": user_info["email"],
            }
            users_collection.insert_one(new_user)
            user = new_user
            
        session["username"] = username
        session["oauth_token"] = token

        return redirect("/main")
    except Exception as e:
        flash(f"Authentication failed: {str(e)}")
        return redirect("/login")


@app.route("/main")
# This is the map visualization page
@login_required
def main():
    return render_template("main.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/create_post", methods=["POST"])
@login_required
def create_post():
    try:
        user_id = session.get("user_id")
        photo_url = request.form.get('secure_url')
        
        if not photo_url:
            photo = request.files.get('photo')
            if photo:
                upload_result = cloudinary.uploader.upload(photo)
                photo_url = upload_result.get('secure_url')
        else:
            return jsonify({"success": False, "error": "No photo provided."}), 400
        
        blog_text = request.form.get('blog')
        lat = request.form.get('lat')
        lng = request.form.get('lng')

        existing_post = posts_collection.find_one({
                "user_id": user_id,
                "location.lat": lat,
                "location.lng": lng
        })

        if existing_post:
            return jsonify({"success": False, "error": "You have already posted at this location"}), 400
        else:
        # Create post in database
            post = {
                "user_id": user_id,  # If you're tracking users
                "photo_url": photo_url,
                "blog_text": blog_text,
                "location": {
                    "lat": float(lat) if lat else None,
                    "lng": float(lng) if lng else None
                },
                "created_at": datetime.datetime.now(timezone.utc) # Get the current date and time
            }
            # Insert into MongoDB
            result = posts_collection.insert_one(post)
            post["_id"] = str(result.inserted_id)

        return jsonify({
            "success": True,
            "title": "New Memory",  
            "blog_text": post["blog_text"],
            "photo_url": post["photo_url"]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


if __name__ == "__main__":
    app.run(debug=True)