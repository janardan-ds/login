from fastapi import FastAPI, HTTPException, Form, BackgroundTasks, Request, Depends
from datetime import datetime, timedelta
from passlib.context import CryptContext
from pydantic import BaseModel
from jose import JWTError, jwt
import pymongo
import smtplib
import re
import string
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional


app = FastAPI()


origins = [
    # Add the list of allowed origins (domains) here
    # For example, for all origins, you can use "*"
    # Replace with the actual frontend URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # You can specify specific HTTP methods here (e.g., ["GET", "POST"])
    allow_headers=["*"],  # You can specify specific HTTP headers here
)

# MongoDB Configuration
MONGO_URI = ""
client = pymongo.MongoClient(MONGO_URI)
db = client["login"]
users_collection = db["users"]

# Security Configurations
SECRET_KEY = "ed97f13d369ec1dae7dc689290e7f4702"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 300

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Define rate limits
RATE_LIMIT_PERIOD = 60  # 60 seconds
RATE_LIMIT_REQUESTS = 5  # 5 requests per minute

# Maximum number of failed login attempts before lockout
MAX_LOGIN_ATTEMPTS = 5

# Lockout duration in minutes
LOCKOUT_DURATION = 1

# Dictionary to store failed login attempts
failed_login_attempts = {}


# JWT Token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Generate a random password
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))


# Email configuration
EMAIL_ADDRESS = "test@test.com"
EMAIL_PASSWORD = "pass"



class User(BaseModel):
    username: str


class UserInDB(User):
    hashed_password: str
    token: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


# Regular expression pattern for a simple email validation
email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {str(e)}")

def send_password_reset_email(to_email, reset_token, new_password):
    subject = "Password Reset"
    body = f"Your new password: {new_password}\n\nOR\n\nUse the following link to reset your password: http://example.com/reset?token={reset_token}"
    send_email(to_email, subject, body)

async def send_account_lock_email(to_email):
    subject = "Account Locked"
    body = """
    Your account has been locked due to multiple failed login attempts. 

    If this was not you, please contact our support team immediately.

    Regards,
    Your Team
    """
    send_email(to_email, subject, body)

def send_verification_email(to_email, verification_link):
    subject = "Verify Your Email"
    body = f"Please click on the following link to verify your email: {verification_link}"
    send_email(to_email, subject, body)


@app.post("/creds/signup/", response_model=Token)
async def signup(
        background_tasks: BackgroundTasks,
        first_name: str = Form(...),
        last_name: str = Form(...),
        company_name: str = Form(...),
        phone_number: str = Form(...),
        email: str = Form(...),
        password: str = Form(...),
        confirm_password: str = Form(...),
):
    if confirm_password!=password:
        raise HTTPException(status_code=401, detail="Password not matched")
    # Validate email format with regex
    if not re.match(email_pattern, email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    # Check if the username (email) already exists
    user_in_db = users_collection.find_one({"email": email.lower()})
    if user_in_db:
        raise HTTPException(status_code=400, detail="Email already registered with us, please use login instead")

    # Extract the domain from the email
    email_domain = email.split("@")[-1].lower()

    # Check if the email domain is in the allowed business domains
    not_allowed_mail_domains = ["gmail.com", "businesscorp.com"]
    if email_domain in not_allowed_mail_domains:
        raise HTTPException(status_code=400, detail="Only business emails are allowed")

    # Enforce password strength requirements (custom checks)

    # Hash the password
    hashed_password = pwd_context.hash(password)

    # Generate a new access token upon successful signup
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": email}, expires_delta=access_token_expires)

    # Prepare user data
    user_data = {
        "username": email.lower(),
        "hashed_password": hashed_password,
        "email": email.lower(),
        "first name": first_name.lower(),
        "last_name": last_name.lower(),
        "company_name": company_name.lower(),
        "phone_number": phone_number,
        "token": access_token,
        "signup_completed": False,
        "email_verified": False
    }

    # Insert the user data into the database
    users_collection.insert_one(user_data)

    verification_token = secrets.token_urlsafe()
    
    # Save the verification token in the database
    users_collection.update_one({"username": email.lower()}, {"$set": {"verification_token": verification_token}})

    # Send a verification email (you should modify the send_email function accordingly)
    verification_link = f"https://api.sdronsteroids.com/creds/verify-email/?token={verification_token}"
    background_tasks.add_task(send_verification_email, email, verification_link)

    return Token(access_token=access_token, token_type="bearer")

@app.get("/creds/verify-email/")
async def verify_email(token: str):
    user = users_collection.find_one({"verification_token": token})
    if not user:
        raise HTTPException(status_code=404, detail="Invalid or expired token")

    # Update user's verified status
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"email_verified": True, "verification_token": None}})

    return {"message": "Email verified successfully"}


# Dictionary to store failed login attempts along with timestamps
failed_login_attempts = {}

@app.post("/creds/login/", response_model=Token)
@limiter.limit("10/minute", key_func=get_remote_address)
async def login(
        request: Request,
        background_tasks: BackgroundTasks,
        email: str = Form(...),
        password: str = Form(...)
):
    current_time = datetime.utcnow()

    user_in_db = users_collection.find_one({"email": email.lower()})
    if not user_in_db:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not user_in_db.get("signup_completed", False):
        return {"message": "Signup incomplete", "redirect": "signup update-next"}

    failed_attempt_count = user_in_db.get("failed_attempts_count", 0)
    last_failed_attempt_time = user_in_db.get("last_failed_attempt_time")

    if last_failed_attempt_time:
        time_diff = (current_time - last_failed_attempt_time).total_seconds() / 60

        # If lockout duration has passed, reset the failed attempt count
        if time_diff >= LOCKOUT_DURATION:
            failed_attempt_count = 0
            users_collection.update_one(
                {"email": email.lower()},
                {"$set": {
                    "failed_attempts_count": 0,
                    "last_failed_attempt_time": None
                }}
            )

        elif failed_attempt_count >= MAX_LOGIN_ATTEMPTS:
            remaining_lockout_time = LOCKOUT_DURATION - time_diff
            background_tasks.add_task(send_account_lock_email, email)
            raise HTTPException(status_code=401, detail=f"Account locked. Try again after {remaining_lockout_time:.0f} minutes.")

    if not pwd_context.verify(password, user_in_db["hashed_password"]):
        # Increment failed login attempts
        new_failed_attempt_count = failed_attempt_count + 1
        users_collection.update_one(
            {"email": email.lower()},
            {"$set": {
                "failed_attempts_count": new_failed_attempt_count,
                "last_failed_attempt_time": current_time
            }}
        )
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Reset failed login attempts after successful login
    users_collection.update_one(
        {"email": email.lower()},
        {"$set": {
            "failed_attempts_count": 0,
            "last_failed_attempt_time": None
        }}
    )

    # Generate a new access token upon successful login
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": email}, expires_delta=access_token_expires)

    # Update the token in the database for the user
    users_collection.update_one({"email": email.lower()}, {"$set": {"token": access_token}})

    return {"access_token": access_token, "token_type": "bearer"}



@app.post("/creds/reset-password/")
async def reset_password(background_tasks: BackgroundTasks, email: str = Form(...)):
    user_in_db = users_collection.find_one({"email": email.lower()})
    if user_in_db is None:
        raise HTTPException(status_code=400, detail="Email not found")

    # Generate a new access token for the reset link (optional)
    reset_token = create_access_token(data={"sub": email}, expires_delta=timedelta(hours=1))

    # Generate a random password for the user
    new_password = generate_random_password()
    # Update the user's password with the new password
    users_collection.update_one({"username": email}, {"$set": {"hashed_password": pwd_context.hash(new_password)}})

    background_tasks.add_task(send_password_reset_email, email, reset_token, new_password)

    return {"message": "Password will be sent if the account exists"}

@app.get("/creds/logout/")
async def logout(request: Request):
    # Get the user's token from the request headers
    token = request.headers.get("Authorization", None)
    if not token:
        raise HTTPException(status_code=401, detail="Token not found")

    # Check if the token exists in the database
    user_in_db = users_collection.find_one({"token": token})
    if not user_in_db:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Remove the token from the user's record in the database (logout)
    users_collection.update_one({"_id": user_in_db["_id"]}, {"$unset": {"token": ""}})

    return {"message": "Logged out successfully"}

@app.get("/creds/check-token/")
async def check_token(request: Request):
    # Get the user's token from the request headers
    token = request.headers.get("Authorization", None)
    if not token:
        raise HTTPException(status_code=401, detail="Token not found")

    # Check if the token exists in the database
    user_in_db = users_collection.find_one({"token": token})
    if not user_in_db:
        raise HTTPException(status_code=401, detail="Token does not exist")

    return {"message": "Token exists"}


# Dependency to get the current user from the token
async def get_current_user(request: Request):
    token = request.headers.get("Authorization")
    if not token:
        raise HTTPException(status_code=401, detail="Token not found")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token malformed")
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    user_in_db = users_collection.find_one({"username": username})
    if user_in_db is None:
        raise HTTPException(status_code=404, detail="User not found")

    user = UserInDB(**user_in_db)
    return user


@app.put("/creds/update-details/")
async def update_details(
        request: Request,
        company_name: str = Form(...),
        industry: str = Form(...),
        website_url: str = Form(...),
        linkedin_url: str = Form(...),
        current_user: UserInDB = Depends(get_current_user)  # Assuming you have a dependency that gets the current user
):
    update_data = {}

    update_data["company_name"] = company_name.capitalize()
    update_data["industry"] = industry.lower()
    update_data["website"] = website_url.lower()
    update_data["linkedin"] = linkedin_url.lower()

    if not update_data:
        raise HTTPException(status_code=400, detail="No update data provided")

    users_collection.update_one({"username": current_user.username}, {"$set": update_data})

    return {"message": "Saved"}

@app.put("/creds/update-details-2/")
async def update_details(
        request: Request,
        company_description: str = Form(...),
        achievements: str = Form(...),
        problems: str = Form(...),
        solutions: str = Form(...),
        current_user: UserInDB = Depends(get_current_user)  # Assuming you have a dependency that gets the current user
):
    update_data = {}
    update_data["company description"] = company_description.capitalize()
    update_data["achivements"] = achievements.lower()
    update_data["problems"] = problems.lower()
    update_data["solutions"] = solutions.lower()
    update_data["signup_completed"] = True

    if not update_data:
        raise HTTPException(status_code=400, detail="No update data provided")
    users_collection.update_one({"username": current_user.username}, {"$set": update_data})
    return {"message": "Submitted"}

@app.put("/creds/update-password/")
async def update_password(
        request: Request,
        old_password: str = Form(...),
        new_password: str = Form(...),
        current_user: UserInDB = Depends(get_current_user)  # Assuming you have a dependency that gets the current user
):
    # Verify old password
    if not pwd_context.verify(old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Old password is incorrect")

    # Hash the new password
    hashed_new_password = pwd_context.hash(new_password)

    # Update the user's password with the new password
    users_collection.update_one({"username": current_user.username}, {"$set": {"hashed_password": hashed_new_password}})

    return {"message": "Password updated successfully"}

def serialize_mongo_document(document):
    if document and "_id" in document:
        document["_id"] = str(document["_id"])
    return document

@app.get("/creds/user-info/")
async def get_user_info(access_token: str):
    try:
        if access_token is None:
            raise HTTPException(status_code=401, detail="Token malformed")

        # Fetch user details from the database
        user_in_db = users_collection.find_one({"token": access_token})
        if user_in_db is None:
            raise HTTPException(status_code=404, detail="User not found")

        # Serialize the MongoDB document and remove sensitive data
        user_data = serialize_mongo_document(user_in_db)
        user_data.pop('hashed_password', None)
        user_data.pop('token', None)
        user_data.pop('_id', None)
        return user_data

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

