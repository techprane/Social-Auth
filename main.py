from fastapi import FastAPI, Request, Depends
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware 
from pymongo import MongoClient

app = FastAPI()

# Add SessionMiddleware to manage sessions for OAuth
app.add_middleware(SessionMiddleware, secret_key="your-secret-key")  

config = Config('.env')
oauth = OAuth(config)

# MongoDB Connection
MONGO_URI = config("MONGO_URI")  # Add MONGO_URI to your .env file
client = MongoClient(MONGO_URI)
db = client.get_database("socialLoginDB")
users_collection = db.get_collection("users")

# OAuth2 Configuration
google = oauth.register(
    name='google',
    client_id=config('CLIENT_ID'),
    client_secret=config('CLIENT_SECRET'),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'}
)

@app.get('/login')
async def login(request: Request):
    redirect_uri = config('REDIRECT_URI')
    return await google.authorize_redirect(request, redirect_uri)

@app.get('/auth/callback')
async def auth_callback(request: Request):
    try:
        # Authenticate and fetch user info
        token = await google.authorize_access_token(request)
        response = await google.get('userinfo')
        user_info = response.json()

        # Check if the user already exists in the database
        existing_user = users_collection.find_one({"email": user_info["email"]})
        if not existing_user:
            # Add new user to the database
            new_user = {
                "email": user_info["email"],
                "name": user_info["name"],
                "profile_picture": user_info["picture"]
            }
            users_collection.insert_one(new_user)
        else:
            # Update existing user details
            users_collection.update_one(
                {"_id": existing_user["_id"]},
                {"$set": {
                    "name": user_info["name"],
                    "profile_picture": user_info["picture"]
                }}
            )

        return {"message": "User authenticated successfully", "user_info": user_info}
    except Exception as e:
        return {"error": str(e)}
