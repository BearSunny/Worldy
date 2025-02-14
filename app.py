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
from bson import ObjectId
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
    client_kwargs={'scope' :[ 
                        'openid profile email', 
                        'https://www.googleapis.com/auth/userinfo.email'],
                    'prompt': 'select_account'}
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
        
        return redirect("/landing")
    else:
        return render_template("login.html")


@app.route("/landing")
@login_required
def landing():
    return render_template("landing.html")


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
            "password_hash" : hash_pass,
            "friends": [],
            "friend_requests": {
                "sent": [],
                "received": []
            }
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
        session.clear()
        redirect_uri = url_for('google_authorize', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)
    except Exception as e:
        flash(f"Error during login: {str(e)}")
        return redirect(url_for('login'))


@app.route("/authorize/google")
def google_authorize():
    """Authorize users for Google"""
    try:
        token = oauth.google.authorize_access_token()
        userinfo_endpoint = google.server_metadata['userinfo_endpoint']
        resp = google.get(userinfo_endpoint)
        user_info = resp.json()
        username = user_info['email']
        email = user_info['email']

        # Connect to MongoDB
        user = users_collection.find_one({"email" : email})

        if not user:
            new_user = {
                "username": user_info.get("name", email.split('@')[0]),
                "email": email,
                "friends": [],
                "friend_requests": {
                    "sent": [],
                    "received": []
                }
            }
            result = users_collection.insert_one(new_user)
            user_id = str(result.inserted_id)
        else:
            user_id = str(user["_id"])
            
        session["user_id"] = user_id

        return redirect("/landing")
    except Exception as e:
        flash(f"Authentication failed: {str(e)}")
        return redirect("/login")


@app.route("/main")
@login_required
# This is the map visualization page
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
        photo_url = request.form.get('photo_url')
        
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
                "location.lat": float(lat),
                "location.lng": float(lng)
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
            "photo_url": post["photo_url"],
            "lat": post["location"]["lat"],
            "lng": post["location"]["lng"]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/get_post", methods=["GET"])
@login_required
def get_post():
    try:
        user_id = session.get("user_id")
        posts = list(posts_collection.find({"user_id" : user_id}))

        for post in posts:
            post["_id"] = str(post["_id"])

        return jsonify({"success": True, "posts" : posts})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/friends")
@login_required
def friends():
    user_id = session.get("user_id")
    return render_template("friends.html", current_user_id=user_id)


@app.route('/search_users_by_email')
@login_required
def search_users_by_email():
    email = request.args.get('email', '').lower().strip()
    
    if not email:
        return jsonify({"error": "Please enter an email address"}), 400
        
    # Look for exact email match
    user = users_collection.find_one(
        {"email": email},
        {"email": 1}
    )
    
    if user:
        return jsonify({
            "users": [{
                "id": str(user["_id"]),
                "email": user["email"]
            }]
        })
    
    return jsonify({"users": []})


@app.route("/send_friend_request", methods=["POST"])
@login_required
def send_friend_request():
    data = request.json
    sender_id = ObjectId(data.get("sender_id"))
    receiver_id = ObjectId(data.get("receiver_id"))

    # Check if users exist
    sender = users_collection.find_one({"_id" : sender_id})
    receiver = users_collection.find_one({"_id" : receiver_id})

    if not sender or not receiver:
        return jsonify({"error":"User not found"}), 404

    # Check if they're already friends
    if receiver_id in sender.get("friends", []):
        return jsonify({"error":"Already friends"}), 400
    
    # Check if request already sent
    if receiver_id in sender.get("friend_requests", {}).get("sent", []):
        return jsonify({"error":"Request already sent!"}), 400

    # Update sender's sent requests
    users_collection.update_one(
        {"_id" : sender_id},
        {
            "$push":{"friend_requests.sent" : receiver_id},
            "$setOnInsert":{"friend_requests.received":[]}
        },
        upsert=True
    )

    # Update receiver's received request
    users_collection.update_one(
        {"_id":receiver_id},
        {
            "$push":{"friend_requests.received" : sender_id},
            "$setOnInsert":{"friend_requests.sent":[]}
        },
        upsert=True
    )

    return jsonify({"message":"Request sent successfully"}), 200


@app.route("/accept_friend_request", methods=["POST"])
@login_required
def accept_friend_request():
    data = request.json
    accepter_id = ObjectId(data.get("accepter_id"))
    requester_id = ObjectId(data.get("requester_id"))

    # Verify the request exists
    accepter = users_collection.find_one({
        "_id":accepter_id,
        "friend_requests.received":requester_id
    })
    if not accepter:
        return jsonify({"error":"Friend request not found"}), 404

    # Add both users to each other's friends lists and remove the request
    users_collection.update_one(
        {"_id":accepter_id},
        {
            "$push": {"friends":requester_id},
            "$pull": {"friend_requests.received":requester_id}
        }
    )

    users_collection.update_one(
        {"_id":requester_id},
        {
            "$push": {"friends":accepter_id},
            "$pull": {"friend_requests.sent":accepter_id}
        }
    )

    return jsonify({"message":"Friend request accepted"}), 200


@app.route("/reject_friend_request", methods=["POST"])
@login_required
def reject_friend_request():
    data = request.json
    rejecter_id = ObjectId(data.get("rejecter_id"))
    requester_id = ObjectId(data.get("requester_id"))

    # Add both users to each other's friends lists and remove the request
    users_collection.update_one(
        {"_id":rejecter_id},
        {
            "$pull": {"friend_requests.received":requester_id}
        }
    )

    users_collection.update_one(
        {"_id":requester_id},
        {
            "$pull": {"friend_requests.sent":rejecter_id}
        }
    )

    return jsonify({"message":"Friend request rejected"}), 200


@app.route("/get_friends/<user_id>", methods=["GET"])
@login_required
def get_friends(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    # Get friend details
    friends = list(users_collection.find(
        {"_id": {"$in": user.get("friends", [])}},
        {"username": 1, "email":1},
    ))
    
    return jsonify({
        "friends": [
            {
                "id": str(friend["_id"]),
                "username": friend["username"],
                "email": friend["email"]
            }
            for friend in friends
        ]
    }), 200


@app.route("/get_friend_requests/<user_id>", methods=["GET"])
@login_required
def get_friend_requests(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Get details of users who sent requests
    received_requests = list(users_collection.find(
        {"_id": {"$in": user.get("friend_requests", {}).get("received", [])}},
        {"email": 1}
    ))
    
    return jsonify({
        "received_requests": [
            {
                "id": str(request["_id"]),
                "email": request["email"]
            }
            for request in received_requests
        ]
    }), 200


@app.route("/get_user_pins/<user_id>")
@login_required
def get_user_pins(user_id):
    # Ensure the requester is friends with this user
    current_user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if str(user_id) not in [str(friend_id) for friend_id in current_user.get("friends", [])]:
        return jsonify({"error": "Not authorized to view this user's pins"}), 403

    user_pins = posts_collection.find({"user_id": user_id})
    pins = []
    for pin in user_pins:
        pins.append({
            "id": str(pin["_id"]),
            "lat": pin["location"]["lat"],
            "lng": pin["location"]["lng"],
            "blog_text": pin.get("blog_text"),
            "photo_url": pin.get("photo_url")
        })
    return jsonify({"posts":pins})


if __name__ == "__main__":
    app.run(debug=True)