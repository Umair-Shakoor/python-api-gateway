from fastapi import FastAPI, Request, HTTPException, Depends
import httpx
import jwt
from jwt import PyJWTError
from pydantic import BaseModel
from collections import defaultdict
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing_extensions import Annotated
import time
app = FastAPI()
# Secret key for JWT token
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

# Rate limiting configuration
RATE_LIMIT = 5  # max requests
RATE_LIMIT_WINDOW = 60  # time window in seconds

# Store request counts and timestamps
request_counts = defaultdict(lambda: [0, time.time()])

class User(BaseModel):
    username: str
    password: str

fake_users_db = {
    "user1": User(username="user1", password="password1"),
    "user2": User(username="user2", password="password2"),
}

# Function to create JWT token
def create_jwt_token(username: str):
    payload = {"sub": username}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# Function to verify JWT token
def decode_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return username
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")

# OAuth2 password bearer flow for token creation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Secure function to get current user
def get_current_user(token: str = Depends(oauth2_scheme)):
    return decode_jwt_token(token)

# Define your backend services here
services = {
    "service1": "http://localhost:8001",
    "service2": "http://localhost:8002",
}

def rate_limit(ip: str):
    current_time = time.time()
    count, first_request_time = request_counts[ip]
    
    # If the time window has passed, reset the count and time
    if current_time - first_request_time > RATE_LIMIT_WINDOW:
        request_counts[ip] = [1, current_time]
    else:
        if count + 1 > RATE_LIMIT:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        else:
            request_counts[ip][0] += 1

@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = fake_users_db.get(form_data.username)
    if not user or form_data.password != user.password:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {"access_token": create_jwt_token(user.username), "token_type": "bearer"}



@app.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
async def proxy(service: str, path: str, request: Request, current_user: str = Depends(get_current_user)):
    if service not in services:
        raise HTTPException(status_code=404, detail="Service not found")

    client_ip = request.client.host
    rate_limit(client_ip)  # Call rate limit function here
    
    url = f"{services[service]}/{path}"
    method = request.method

    headers = dict(request.headers)
    headers.pop("host", None)  # Remove the host header if present

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.request(
                method=method,
                url=url,
                params=request.query_params,
                headers=headers,
                json=await request.json() if method in ["POST", "PUT", "PATCH"] else None,
            )
            return response.json() if response.headers.get("content-type") == "application/json" else response.text
    except httpx.RequestError as exc:
        raise HTTPException(status_code=500, detail=f"Error requesting {exc.request.url!r}.")
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
