from fastapi import FastAPI, Request, Depends
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from pymongo import MongoClient
import logging


app = FastAPI()

config = Config('.env')
oauth = OAuth(config)

# Add SessionMiddleware to manage sessions for OAuth
app.add_middleware(SessionMiddleware, secret_key=config('SECRET_KEY'))

# logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# MongoDB Connection
MONGO_URI = config("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client[config("MONGO_DB_NAME", default="socialLoginDB")]
users_collection = db[config("MONGO_COLLECTION_NAME", default="users")]

# OAuth2 Configuration
google = oauth.register(
    name='google',
    client_id=config('GOOGLE_CLIENT_ID'),
    client_secret=config('GOOGLE_CLIENT_SECRET'),
    access_token_url=config('GOOGLE_ACCESS_TOKEN_URL'),
    authorize_url=config('GOOGLE_AUTHORIZE_URL'),
    api_base_url=config('GOOGLE_API_BASE_URL'),
    userinfo_endpoint=config('GOOGLE_USERINFO_ENDPOINT'),
    client_kwargs={'scope': 'openid email profile'}
)

linkedin = oauth.register(
    name='linkedin',
    client_id=config('LINKEDIN_CLIENT_ID'),
    client_secret=config('LINKEDIN_CLIENT_SECRET'),
    authorize_url=config('LINKEDIN_AUTHORIZE_URL'),
    access_token_url=config('LINKEDIN_ACCESS_TOKEN_URL'),
    userinfo_endpoint=config('LINKEDIN_USERINFO_ENDPOINT'),
    client_kwargs={"scope": "email"},
)

github = oauth.register(
    name='github',
    client_id=config('GITHUB_CLIENT_ID'),
    client_secret=config('GITHUB_CLIENT_SECRET'),
    authorize_url=config('GITHUB_AUTHORIZE_URL'),
    access_token_url=config('GITHUB_ACCESS_TOKEN_URL'),
    userinfo_endpoint=config('GITHUB_USERINFO_ENDPOINT'),
)

@app.get('/login/{provider}')
async def login(request: Request, provider: str):
    if provider not in ['google', 'linkedin', 'github']:
        return {"error": "Unsupported provider"}
    
    oauth_provider = oauth.create_client(provider)

    # Assign redirect_uri based on the provider
    if provider == 'linkedin':
        redirect_uri = config('LINKEDIN_REDIRECT_URI')
    else:
        redirect_uri = config('REDIRECT_URI')  # Default for other providers
    
        logger.debug(f"Redirect URI: {redirect_uri}")
    return await oauth_provider.authorize_redirect(request, redirect_uri)



@app.get('/auth/callback/{provider}')
async def auth_callback(request: Request, provider: str):
    try:
        if provider not in ['google', 'linkedin', 'github']:
            return {"error": "Unsupported provider"}
        
        oauth_provider = oauth.create_client(provider)
        token = await oauth_provider.authorize_access_token(request)
        user_info = (await oauth_provider.get('userinfo')).json()

        # Save or update user in MongoDB
        existing_user = users_collection.find_one({"email": user_info["email"]})
        if not existing_user:
            new_user = {
                "email": user_info["email"],
                "name": user_info.get("name"),
                "profile_picture": user_info.get("picture"),
            }
            users_collection.insert_one(new_user)
        else:
            users_collection.update_one(
                {"_id": existing_user["_id"]},
                {"$set": {
                    "name": user_info.get("name"),
                    "profile_picture": user_info.get("picture"),
                }}
            )
        return {"message": "User authenticated successfully", "user_info": user_info}

    except Exception as e:
        logger.error(f"Error in {provider} OAuth: {str(e)}")
        return {"error": "Authentication failed. Please try again."}

@app.get('/auth/callback/linkedin')
async def linkedin_auth_callback(request: Request):
    try:
        oauth_provider = oauth.create_client('linkedin')
        token = await oauth_provider.authorize_access_token(request)
        user_response = await oauth_provider.get('me', token=token)
        email_response = await oauth_provider.get(
            "emailAddress?q=members&projection=(elements*(handle~))", token=token
        )

        return {"message": "LinkedIn authentication successful"}

    except Exception as e:
        logger.error(f"Error in LinkedIn OAuth: {str(e)}")
        return {"error": str(e)}
