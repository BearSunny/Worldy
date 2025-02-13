# WORLDY

WORLDY is a web application that lets users connect, manage relationships, and share their life moments by posting blogs and photos on an interactive map. Whether you're exploring your own memories or discovering your friends' adventures, WORLDY brings your experiences to life on a global scale.

## Features

- **User Authentication**
  - Sign-up and login with email/password.
  - Google OAuth for streamlined access.
- **Interactive Map Visualization**
  - Explore a world map powered by [Leaflet.js](https://leafletjs.com/).
  - Search for locations with an autocomplete feature using the Nominatim API.
- **Location-Based Blogging**
  - Add pins by clicking on the map or selecting search results.
  - Share memories with photo uploads (via [Cloudinary](https://cloudinary.com/)) and short blog posts.
- **Relationship Management**
  - Send, accept, and reject friend requests.
  - Manage your friend list on a dedicated page.
  - Use a "Friends" dropdown to filter map pins by friend or switch back to your own pins.
- **Responsive Design**
  - Modern, responsive UI for desktop and mobile devices.

## Tech Stack

- **Backend:**  
  - Flask  
  - MongoDB (via PyMongo)  
  - Flask-Session, Flask-CORS  
  - Google OAuth via Authlib  
  - Cloudinary for image uploads

- **Frontend:**  
  - HTML, CSS, JavaScript  
  - [Leaflet.js](https://leafletjs.com/) for map visualization  
  - Font Awesome for icons

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/BearSunny/Worldy.git
   cd worldy

2. **Create and Activate a Virtual Environment:**
    python -m venv venv
    # On macOS/Linux:
    source venv/bin/activate
    # On Windows:
    venv\Scripts\activate

3. **Install dependencies:**
    pip install -r requirements.txt

4. **Configuration:**

- API Keys & Secrets:
    - Create an api_key.py file to store your Google OAuth CLIENT_ID and CLIENT_SECRET along with any other API keys.
- MongoDB Connection:
    - Update the MongoDB connection string in your main application file with your credentials.
- Cloudinary Setup:
    - Confirm your Cloudinary credentials are correctly set in your configuration.
- Secret Key:
    - Update the secret key in your application configuration (e.g., in app.py).

5. **Run:**
    py app.py
