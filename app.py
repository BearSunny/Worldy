# Set up Flask application
from flask import Flask, request, jsonify
from flask_cors import CORS
import pymongo
import jwt
import cloudinary.uploader

app = Flask(__name__)

# MongoDB setup #TODO

# JWT secret key #TODO

# Cloudinary config #TODO

@app.route('/')
def home():
    return "Hello, World!"