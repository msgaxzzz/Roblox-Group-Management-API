import os
import secrets
import string
import logging
import json
from typing import Optional, List, Union
import asyncio
import random
import time

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, Query, Path, Security, Body
from fastapi.security import APIKeyQuery, APIKeyHeader
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_404_NOT_FOUND
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
API_KEY_FILE = "api_key.txt"

BROWSER_PROFILES = [
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
        "sec_ch_ua_platform": '"Windows"',
    },
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
        "sec_ch_ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
        "sec_ch_ua_platform": '"Windows"',
    },
    {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
        "sec_ch_ua_platform": '"macOS"',
    }
]

def generate_api_key(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def load_or_create_api_key() -> str:
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as f: key = f.read().strip()
        if len(key) >= 32: logging.info("API key loaded from file."); return key
    key = generate_api_key()
    with open(API_KEY_FILE, "w") as f: f.write(key)
    logging.info(f"New API key generated and saved: {key}")
    return key

ROBLOSECURITY_COOKIE = os.getenv("ROBLOSECURITY")
APP_PORT = int(os.getenv("PORT", 8000))
if not ROBLOSECURITY_COOKIE: raise ValueError("ROBLOSECURITY environment variable not set!")
API_KEY = load_or_create_api_key()

class RobloxAPIError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code; self.message = message
        super().__init__(f"Roblox API Error {status_code}: {message}")

class RobloxClient:
    def __init__(self, cookie: str):
        self._cookie = cookie
        self._csrf_token: Optional[str] = None
        
        profile = random.choice(BROWSER_PROFILES)
        self._base_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,application/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': profile["user_agent"],
            'Sec-Ch-Ua': profile["sec_ch_ua"],
            'Sec-Ch-Ua-Platform': profile["sec_ch_ua_platform"],
        }
        
        self._base_cookies = {
            ".ROBLOSECURITY": self._cookie,
            "RBXEventTrackerV2": f"CreateDate={time.strftime('%m/%d/%Y %I:%M:%S %p')}&rbxid=&browserid={random.randint(100000000, 999999999)}",
            "GuestData": f"UserID=-{random.randint(100000000, 999999999)}",
        }
        
        self._last_url: Optional[str] = None

        self._session = httpx.AsyncClient(
            cookies=self._base_cookies,
            headers=self._base_headers,
            timeout=30.0,
            follow_redirects=True,
            http2=True,
        )
        logging.info(f"RobloxClient initialized. Identity: {profile['user_agent']}")
        logging.info("Mode: Paranoid (HTTP/2, Dynamic Identity, Referer Tracking, Human Pacing, Realistic Cookies)")

    async def close_session(self): await self._session.aclose()

    async def _get_csrf_token(self):
        info_url = "https://auth.roblox.com/v2/logout"
        logging.info("Attempting to refresh CSRF token...")
        try:
            api_headers = self._base_headers.copy()
            api_headers['Content-Type'] = 'application/json'
            if self._last_url: api_headers['Referer'] = self._last_url
            
            response = await self._session.post(info_url, headers=api_headers)
            if response.status_code == 403 and "x-csrf-token" in response.headers:
                self._csrf_token = response.headers["x-csrf-token"]
                logging.info(f"Successfully refreshed CSRF token. HTTP Version: {response.http_version}")
            else:
                raise RobloxAPIError(response.status_code, f"Failed to get CSRF token. Unexpected response: {response.text}")
        except httpx.RequestError as e:
            raise RobloxAPIError(503, f"Network error when trying to get CSRF token: {e}")

    async def request(self, method: str, url: str, **kwargs):
        if method.upper() not in ["GET", "HEAD", "OPTIONS"] and self._csrf_token is None:
            await self._get_csrf_token()
            await self._human_delay()

        api_headers = self._base_headers.copy()
        api_headers['Accept'] = 'application/json, text/plain, */*'
        api_headers['Sec-Fetch-Site'] = 'same-origin'
        
        if self._last_url:
            api_headers['Referer'] = self._last_url

        if "json" in kwargs:
             api_headers['Content-Type'] = 'application/json;charset=UTF-8'

        if self._csrf_token and method.upper() not in ["GET", "HEAD", "OPTIONS"]:
            api_headers["x-csrf-token"] = self._csrf_token

        extra_headers = kwargs.pop("headers", {})
        api_headers.update(extra_headers)
        
        try:
            response = await self._session.request(method, url, headers=api_headers, **kwargs)
            if response.is_success and method.upper() == 'GET':
                self._last_url = url
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403 and ("Token Validation Failed" in e.response.text or "Authorization has been denied" in e.response.text):
                logging.warning("CSRF token validation failed. Retrying with a new token...")
                await self._get_csrf_token()
                await self._human_delay()
                api_headers["x-csrf-token"] = self._csrf_token
                response = await self._session.request(method, url, headers=api_headers, **kwargs)
                if response.is_success and method.upper() == 'GET': self._last_url = url
                response.raise_for_status()
            else:
                try:
                    error_details = e.response.json()
                    error_message = error_details.get("errors", [{}])[0].get("message", e.response.text)
                except (json.JSONDecodeError, IndexError, KeyError):
                    error_message = e.response.text
                raise RobloxAPIError(e.response.status_code, error_message)
        
        if not response.text: return None
        return response.json()

    async def _human_delay(self):
        delay = random.uniform(0.4, 1.2)
        await asyncio.sleep(delay)

    async def _get_authenticated_user_id(self) -> int:
        logging.info("Fetching authenticated user ID...")
        try:
            response = await self.request("GET", "https://users.roblox.com/v1/users/authenticated")
            if response and response.get("id"):
                user_id = response["id"]
                logging.info(f"Authenticated user ID: {user_id}")
                return user_id
            raise RobloxAPIError(401, "Could not retrieve authenticated user ID. The ROBLOSECURITY cookie might be invalid or expired.")
        except RobloxAPIError as e:
            logging.error(f"Roblox API Error fetching authenticated user ID: {e.status_code} - {e.message}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error fetching authenticated user ID: {e}", exc_info=True)
            raise RobloxAPIError(500, f"An unexpected error occurred while fetching authenticated user ID: {e}")

class RankUpdatePayload(BaseModel): rank: int = Field(..., gt=0, le=255, description="The target rank value (1-255).")
class PayoutRecipient(BaseModel): recipientId: int; recipientType: str = Field("User", description="Must be 'User'."); amount: int = Field(..., gt=0, description="Amount of Robux to pay.")
class PayoutPayload(BaseModel): PayoutType: str = Field("FixedAmount", description="Must be 'FixedAmount'."); Recipients: List[PayoutRecipient]
class UserActionPayload(BaseModel): userId: int = Field(..., description="The target user's ID.")
class StatusResponse(BaseModel): status: str; detail: Optional[str] = None

class MultiUserRankPayload(BaseModel):
    users: List[Union[int, str]] = Field(..., description="A list of user IDs or usernames to rank.")
    rank: int = Field(..., gt=0, le=255, description="The target rank value (1-255).")

class SingleUserRankResult(BaseModel):
    user_identifier: Union[int, str] = Field(..., description="The original identifier provided for the user.")
    user_id: Optional[int] = Field(None, description="The resolved Roblox user ID, if successful.")
    status: str = Field(..., description="Status of the operation for this user (success, skipped, failed).")
    detail: str = Field(..., description="Detailed message about the outcome for this user.")
    success: bool = Field(..., description="True if the operation for this user was successful or skipped.")

class MultiUserRankResponse(BaseModel):
    overall_status: str = Field(..., description="Overall status of the batch operation (success, partial_success, failure).")
    results: List[SingleUserRankResult] = Field(..., description="A list of results for each user processed.")

class SingleUserKickResult(BaseModel):
    user_id: int = Field(..., description="The Roblox user ID.")
    username: Optional[str] = Field(None, description="The Roblox username, if available.")
    status: str = Field(..., description="Status of the operation for this user (success, skipped, failed).")
    detail: str = Field(..., description="Detailed message about the outcome for this user.")
    success: bool = Field(..., description="True if the operation for this user was successful or skipped.")

class MultiUserKickResponse(BaseModel):
    overall_status: str = Field(..., description="Overall status of the batch operation (success, partial_success, failure, skipped_all).")
    total_members_attempted: int = Field(..., description="Total number of members found and attempted to kick.")
    successful_kicks: int = Field(..., description="Number of members successfully kicked.")
    skipped_members: int = Field(..., description="Number of members skipped (e.g., owner, bot itself).")
    failed_kicks: int = Field(..., description="Number of members that failed to be kicked.")
    results: List[SingleUserKickResult] = Field(..., description="A list of results for each user processed.")


api_key_query = APIKeyQuery(name="api_key", auto_error=False, description="Browser-friendly API Key (in URL).")
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False, description="Standard API Key (in request header).")
async def get_api_key(key_from_query: str = Security(api_key_query), key_from_header: str = Security(api_key_header)):
    if key_from_header and secrets.compare_digest(key_from_header, API_KEY): return key_from_header
    if key_from_query and secrets.compare_digest(key_from_query, API_KEY): return key_from_query
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid or missing API Key.")

app = FastAPI(
    title="Roblox Group Management API",
    description="The most advanced pure-Python masquerading API for Roblox group management.",
    version="4.9.6"
)
roblox_client = RobloxClient(ROBLOSECURITY_COOKIE)
keep_alive_task = None
csrf_refresher_task = None

async def csrf_token_refresher():
    await asyncio.sleep(10) 
    while True:
        sleep_duration = random.uniform(290, 310) 
        logging.info(f"[CSRF-Refresher] Next scheduled refresh in {sleep_duration / 60:.2f} minutes.")
        await asyncio.sleep(sleep_duration)
        try:
            logging.info("[CSRF-Refresher] Performing scheduled CSRF token refresh.")
            await roblox_client._get_csrf_token()
        except Exception as e:
            logging.error(f"[CSRF-Refresher] An unexpected error occurred during scheduled refresh: {e}", exc_info=True)

async def _keep_alive_action_visit_home():
    logging.info("[Keep-Alive] Action: Visiting roblox.com/home")
    response = await roblox_client._session.get("https://www.roblox.com/home")
    response.raise_for_status()
    logging.info(f"[Keep-Alive] Home page visit successful. HTTP Version: {response.http_version}")
    roblox_client._last_url = "https://www.roblox.com/home"

async def _keep_alive_action_check_transactions():
    logging.info("[Keep-Alive] Action: Checking transactions page")
    await roblox_client.request("GET", "https://economy.roblox.com/v2/users/1/transactions?transactionType=summary")

async def _keep_alive_action_get_auth_user():
    logging.info("[Keep-Alive] Action: Pinging authenticated user endpoint")
    await roblox_client.request("GET", "https://users.roblox.com/v1/users/authenticated")

async def session_keep_alive():
    await asyncio.sleep(15)
    possible_actions = [_keep_alive_action_visit_home, _keep_alive_action_check_transactions, _keep_alive_action_get_auth_user]
    while True:
        try:
            action = random.choice(possible_actions)
            await action()
            await roblox_client._human_delay()
            logging.info("[Keep-Alive] Action successful. Session appears active.")
        except Exception as e:
            logging.error(f"[Keep-Alive] An unexpected error occurred: {e}", exc_info=True)
        sleep_duration = random.uniform(900, 1500)
        logging.info(f"[Keep-Alive] Next check in {sleep_duration / 60:.2f} minutes.")
        await asyncio.sleep(sleep_duration)

@app.on_event("startup")
async def startup_event():
    global keep_alive_task, csrf_refresher_task
    loop = asyncio.get_event_loop()
    logging.info("Starting session keep-alive background task.")
    keep_alive_task = loop.create_task(session_keep_alive())
    logging.info("Starting periodic CSRF token refresher task (5 min interval).")
    csrf_refresher_task = loop.create_task(csrf_token_refresher())

@app.on_event("shutdown")
async def shutdown_event():
    if keep_alive_task:
        logging.info("Stopping session keep-alive background task.")
        keep_alive_task.cancel()
        try: await keep_alive_task
        except asyncio.CancelledError: logging.info("Keep-alive task successfully cancelled.")
    
    if csrf_refresher_task:
        logging.info("Stopping CSRF token refresher task.")
        csrf_refresher_task.cancel()
        try: await csrf_refresher_task
        except asyncio.CancelledError: logging.info("CSRF refresher task successfully cancelled.")

    await roblox_client.close_session()
    logging.info("RobloxClient session closed.")

@app.exception_handler(RobloxAPIError)
async def roblox_api_exception_handler(request: Request, exc: RobloxAPIError):
    try: roblox_details = json.loads(exc.message)
    except (json.JSONDecodeError, TypeError): roblox_details = exc.message
    return JSONResponse(status_code=502, content={"status": "error", "detail": f"Roblox API Error: {exc.status_code}", "roblox_response": roblox_details})

async def _get_id_from_username(username: str) -> int:
    await roblox_client._human_delay()
    url = "https://users.roblox.com/v1/usernames/users"
    payload = {"usernames": [username], "excludeBannedUsers": True}
    logging.info(f"Resolving username '{username}' to ID...")
    try:
        response = await roblox_client.request("POST", url, json=payload)
        if response and response.get("data") and len(response["data"]) > 0:
            user_id = response["data"][0]["id"]
            logging.info(f"Resolved username '{username}' to ID: {user_id}")
            return user_id
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=f"User with username '{username}' not found.")
    except RobloxAPIError as e:
        raise HTTPException(status_code=502, detail=f"Failed to resolve username from Roblox API. Reason: {e.message}")

async def resolve_user_identifier(user_identifier: str = Path(..., description="The user's ID or username.")) -> int:
    if user_identifier.isdigit(): return int(user_identifier)
    return await _get_id_from_username(user_identifier)

async def _get_group_roles(group_id: int) -> List[dict]:
    await roblox_client._human_delay()
    roles_url = f"https://groups.roblox.com/v1/groups/{group_id}/roles"
    logging.info(f"Fetching all roles for group {group_id}.")
    try:
        response_data = await roblox_client.request("GET", roles_url)
        if not response_data or "roles" not in response_data:
            raise HTTPException(status_code=502, detail="Could not retrieve roles from Roblox API, or response was malformed.")
        return response_data["roles"]
    except RobloxAPIError as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch group roles from Roblox. Reason: {e.message}")

async def _get_user_current_role(group_id: int, user_id: int) -> dict:
    await roblox_client._human_delay()
    url = f"https://groups.roblox.com/v2/users/{user_id}/groups/roles"
    logging.info(f"Fetching current role for user {user_id} in group {group_id}.")
    try:
        response_data = await roblox_client.request("GET", url)
        if not response_data or "data" not in response_data:
             raise HTTPException(status_code=404, detail=f"Could not retrieve role for user {user_id} in group {group_id}.")
        for group_data in response_data["data"]:
            if group_data.get("group", {}).get("id") == group_id:
                if group_data.get("role") is None: 
                    return {"name": "Guest", "rank": 0}
                return group_data["role"]
        return {"name": "Guest", "rank": 0}
    except RobloxAPIError as e:
        if e.status_code == 400:
            raise HTTPException(status_code=404, detail=f"User with ID {user_id} does not exist.")
        raise HTTPException(status_code=502, detail=f"Failed to fetch user's role from Roblox. Reason: {e.message}")

@app.get("/groups/{group_id}", tags=["Information"])
async def get_group_info(group_id: int = Path(..., description="The ID of the group to query."), _=Security(get_api_key)):
    """
    Gets public information about a group, such as its name, owner, member count, and description.
    This endpoint does not require the authenticated user to be a member of the group.
    """
    logging.info(f"Fetching basic information for group {group_id}.")
    await roblox_client._human_delay()
    url = f"https://groups.roblox.com/v1/groups/{group_id}"
    return await roblox_client.request("GET", url)

@app.get("/groups/{group_id}/users/{user_identifier}/role", tags=["Information"])
async def get_user_role_in_group(group_id: int, user_id: int = Depends(resolve_user_identifier), _=Security(get_api_key)):
    """
    Gets a specific user's current role and rank within a group. Essential for bot permission checks.
    """
    logging.info(f"Explicitly fetching role for user {user_id} in group {group_id}.")
    return await _get_user_current_role(group_id, user_id)

@app.get("/groups/{group_id}/roles", tags=["Information"])
async def get_group_roles(group_id: int = Path(..., description="The ID of the group."), _=Security(get_api_key)):
    """
    Gets a list of all roles in a group, including their ID, name, and rank (0-255).
    """
    return await _get_group_roles(group_id)

@app.post("/groups/{group_id}/users/{user_identifier}/promote", response_model=StatusResponse, tags=["Ranking"])
async def promote_user(group_id: int, user_id: int = Depends(resolve_user_identifier), _=Security(get_api_key)):
    all_roles = await _get_group_roles(group_id) 
    await roblox_client._human_delay() 
    current_role = await _get_user_current_role(group_id, user_id)
    current_rank_value = current_role.get("rank", 0)
    
    if current_rank_value == 0: raise HTTPException(status_code=400, detail="User is not in the group and cannot be promoted.")
    if current_rank_value == 255: raise HTTPException(status_code=400, detail="Cannot promote the group owner.")
    
    sorted_roles = sorted([r for r in all_roles if r.get("rank", 0) > 0], key=lambda r: r["rank"])
    
    next_role = next((role for role in sorted_roles if role["rank"] > current_rank_value), None)
    if next_role is None: raise HTTPException(status_code=400, detail="User is already at the highest promotable rank.")
    
    await roblox_client._human_delay() 
    set_rank_url = f"https://groups.roblox.com/v1/groups/{group_id}/users/{user_id}"
    await roblox_client.request("PATCH", set_rank_url, json={"roleId": next_role["id"]})
    return {"status": "success", "detail": f"User {user_id} successfully promoted from '{current_role.get('name', 'N/A')}' (Rank {current_rank_value}) to '{next_role['name']}' (Rank {next_role['rank']})."}

@app.post("/groups/{group_id}/users/{user_identifier}/demote", response_model=StatusResponse, tags=["Ranking"])
async def demote_user(group_id: int, user_id: int = Depends(resolve_user_identifier), _=Security(get_api_key)):
    all_roles = await _get_group_roles(group_id)
    await roblox_client._human_delay()
    current_role = await _get_user_current_role(group_id, user_id)
    current_rank_value = current_role.get("rank", 0)

    if current_rank_value == 0: raise HTTPException(status_code=400, detail="User is not in the group and cannot be demoted.")
    if current_rank_value == 255: raise HTTPException(status_code=400, detail="Cannot demote the group owner.")
    
    sorted_roles = sorted([r for r in all_roles if r.get("rank", 0) > 0], key=lambda r: r["rank"], reverse=True)
    
    previous_role = next((role for role in sorted_roles if role["rank"] < current_rank_value), None)
    if previous_role is None: raise HTTPException(status_code=400, detail="User is already at the lowest rank.")
    
    await roblox_client._human_delay()
    set_rank_url = f"https://groups.roblox.com/v1/groups/{group_id}/users/{user_id}"
    await roblox_client.request("PATCH", set_rank_url, json={"roleId": previous_role["id"]})
    return {"status": "success", "detail": f"User {user_id} successfully demoted from '{current_role.get('name', 'N/A')}' (Rank {current_rank_value}) to '{previous_role['name']}' (Rank {previous_role['rank']})."}

@app.patch("/groups/{group_id}/users/{user_identifier}/rank", response_model=StatusResponse, tags=["Ranking"])
async def set_user_rank(group_id: int, payload: RankUpdatePayload, user_id: int = Depends(resolve_user_identifier), _=Security(get_api_key)):
    roles = await _get_group_roles(group_id)
    await roblox_client._human_delay()
    target_role = next((role for role in roles if role.get("rank") == payload.rank), None)
    if not target_role: raise HTTPException(status_code=404, detail=f"No role with rank '{payload.rank}' found in group {group_id}.")
    
    set_rank_url = f"https://groups.roblox.com/v1/groups/{group_id}/users/{user_id}"
    await roblox_client.request("PATCH", set_rank_url, json={"roleId": target_role["id"]})
    return {"status": "success", "detail": f"User {user_id} rank successfully updated to {payload.rank} (Role: '{target_role['name']}')."}

@app.delete("/groups/{group_id}/users/{user_identifier}", response_model=StatusResponse, tags=["Membership"])
async def kick_user_from_group(group_id: int, user_id: int = Depends(resolve_user_identifier), _=Security(get_api_key)):
    url = f"https://groups.roblox.com/v1/groups/{group_id}/users/{user_id}"
    await roblox_client.request("DELETE", url)
    return {"status": "success", "detail": f"User {user_id} has been successfully kicked from group {group_id}."}

@app.get("/groups/{group_id}/members", tags=["Membership"])
async def get_group_members(group_id: int, limit: int = Query(100, ge=10, le=100), cursor: Optional[str] = Query(None), sort_order: str = Query("Asc", enum=["Asc", "Desc"]), _=Security(get_api_key)):
    url = f"https://groups.roblox.com/v1/groups/{group_id}/users?limit={limit}&sortOrder={sort_order}"
    if cursor: url += f"&cursor={cursor}"
    return await roblox_client.request("GET", url)

@app.get("/groups/{group_id}/roles/{role_id}/users", tags=["Membership"])
async def get_members_in_role(group_id: int, role_id: int, limit: int = Query(100, ge=10, le=100), cursor: Optional[str] = Query(None), sort_order: str = Query("Asc", enum=["Asc", "Desc"]), _=Security(get_api_key)):
    url = f"https://groups.roblox.com/v1/groups/{group_id}/roles/{role_id}/users?limit={limit}&sortOrder={sort_order}"
    if cursor: url += f"&cursor={cursor}"
    return await roblox_client.request("GET", url)

@app.get("/groups/{group_id}/join-requests", tags=["Membership"])
async def get_join_requests(group_id: int, limit: int = Query(100, ge=10, le=100), cursor: Optional[str] = Query(None), sort_order: str = Query("Asc", enum=["Asc", "Desc"]), _=Security(get_api_key)):
    url = f"https://groups.roblox.com/v1/groups/{group_id}/join-requests?limit={limit}&sortOrder={sort_order}"
    if cursor: url += f"&cursor={cursor}"
    return await roblox_client.request("GET", url)

@app.post("/groups/{group_id}/join-requests/accept", response_model=StatusResponse, tags=["Membership"])
async def accept_group_join_request(group_id: int, payload: UserActionPayload, _=Security(get_api_key)):
    url = f"https://groups.roblox.com/v1/groups/{group_id}/join-requests/users/{payload.userId}"
    await roblox_client.request("POST", url, json={})
    return {"status": "success", "detail": f"Accepted join request for user {payload.userId} in group {group_id}."}

@app.post("/groups/{group_id}/join-requests/decline", response_model=StatusResponse, tags=["Membership"])
async def decline_group_join_request(group_id: int, payload: UserActionPayload, _=Security(get_api_key)):
    url = f"https://groups.roblox.com/v1/groups/{group_id}/join-requests/users/{payload.userId}"
    await roblox_client.request("DELETE", url)
    return {"status": "success", "detail": f"Declined join request for user {payload.userId} in group {group_id}."}

@app.get("/groups/{group_id}/revenue/summary/{time_period}", tags=["Finance"])
async def get_group_funds(group_id: int, time_period: str = Path(..., enum=["Day", "Week", "Month", "Year"]), _=Security(get_api_key)):
    url = f"https://economy.roblox.com/v1/groups/{group_id}/revenue/summary/{time_period}"
    return await roblox_client.request("GET", url)

@app.post("/groups/{group_id}/payouts", response_model=StatusResponse, tags=["Finance"])
async def make_payout(group_id: int, payload: PayoutPayload, _=Security(get_api_key)):
    url = f"https://groups.roblox.com/v1/groups/{group_id}/payouts"
    await roblox_client.request("POST", url, json=payload.dict())
    return {"status": "success", "detail": "Payout request processed successfully."}

@app.get("/groups/{group_id}/audit-log", tags=["Auditing"])
async def get_audit_log(group_id: int, action_type: str = Query("All"), user_id: Optional[int] = Query(None), limit: int = Query(100, ge=10, le=100), cursor: Optional[str] = Query(None), sort_order: str = Query("Asc", enum=["Asc", "Desc"]), _=Security(get_api_key)):
    url = f"https://groups.roblox.com/v1/groups/{group_id}/audit-log?limit={limit}&sortOrder={sort_order}&actionType={action_type}"
    if user_id: url += f"&userId={user_id}"
    if cursor: url += f"&cursor={cursor}"
    return await roblox_client.request("GET", url)

@app.post("/groups/{group_id}/mass-rank", response_model=MultiUserRankResponse, tags=["Ranking"])
async def set_multiple_user_ranks(
    group_id: int = Path(..., description="The ID of the group."),
    payload: MultiUserRankPayload = Body(..., description="List of users to rank and the target rank."),
    _=Security(get_api_key)
):
    """
    Sets a specific rank for multiple users within a group.
    
    The bot (the authenticated account via ROBLOSECURITY cookie) must have the necessary
    permissions to rank users in the target group.
    
    **Constraints:**
    - Cannot set a rank higher than the bot's own rank in the group (unless the bot is the group owner).
    - Cannot set the rank to 255 (Owner) unless the bot itself is the group owner.
    - Cannot modify the rank of users who are currently ranked higher than the bot.
    - Users not in the group will be skipped or result in an error if their username cannot be resolved.
    - The authenticated bot itself will be skipped if included in the list.
    """
    logging.info(f"Received mass rank request for group {group_id} to rank {payload.rank} for {len(payload.users)} users.")
    results: List[SingleUserRankResult] = []

    try:
        authenticated_user_id = await roblox_client._get_authenticated_user_id()
    except RobloxAPIError as e:
        raise HTTPException(status_code=500, detail=f"Failed to identify the bot's own user ID: {e.message}")

    try:
        bot_current_role = await _get_user_current_role(group_id, authenticated_user_id)
        bot_rank = bot_current_role.get("rank", 0)
    except HTTPException as e:
        if "Could not retrieve role for user" in e.detail or "User with ID" in e.detail:
             raise HTTPException(status_code=403, detail=f"The authenticated account (ID: {authenticated_user_id}) is not a member of group {group_id} or could not fetch its role. Cannot perform ranking operations.")
        raise HTTPException(status_code=e.status_code, detail=f"Failed to get bot's role in group {group_id}: {e.detail}")
    
    if bot_rank == 0:
        raise HTTPException(status_code=403, detail=f"The authenticated account (ID: {authenticated_user_id}) is not ranked in group {group_id}. Cannot perform ranking operations as a guest.")
    
    logging.info(f"Bot's current rank in group {group_id}: {bot_rank}")

    all_roles = await _get_group_roles(group_id)
    target_role = next((role for role in all_roles if role.get("rank") == payload.rank), None)
    
    if not target_role:
        raise HTTPException(status_code=404, detail=f"No role with target rank '{payload.rank}' found in group {group_id}. Please ensure the target rank exists.")

    if payload.rank > bot_rank and bot_rank != 255:
        raise HTTPException(status_code=403, detail=f"Target rank ({payload.rank}) is higher than the bot's current rank ({bot_rank}). The bot cannot promote users to a rank higher than its own.")
    
    if payload.rank == 255 and bot_rank != 255:
        raise HTTPException(status_code=403, detail="Cannot set users to owner rank (255) unless the bot itself is the group owner.")

    for user_id_or_username in payload.users:
        user_result = SingleUserRankResult(
            user_identifier=user_id_or_username,
            status="failed",
            detail="Initial status.",
            success=False
        )
        try:
            current_user_id = None
            if isinstance(user_id_or_username, int):
                current_user_id = user_id_or_username
            else:
                try:
                    current_user_id = await _get_id_from_username(str(user_id_or_username))
                except HTTPException as e:
                    user_result.detail = f"Username '{user_id_or_username}' not found or could not be resolved: {e.detail}"
                    logging.warning(user_result.detail)
                    results.append(user_result)
                    continue

            user_result.user_id = current_user_id
            
            current_user_role = {"name": "Guest", "rank": 0} 
            try:
                current_user_role = await _get_user_current_role(group_id, current_user_id)
            except HTTPException as e:
                if "Could not retrieve role for user" in e.detail or "User with ID" in e.detail:
                    current_user_role = {"name": "Not In Group", "rank": 0}
                    logging.info(f"User {current_user_id} not found in group {group_id} (or not resolvable within group context), assuming rank 0.")
                else:
                    raise 

            current_user_rank = current_user_role.get("rank", 0)

            if current_user_id == authenticated_user_id:
                user_result.detail = f"User {current_user_id} is the authenticated bot itself. Skipping ranking operation for self."
                user_result.status = "skipped"
                user_result.success = True
                logging.info(user_result.detail)
                results.append(user_result)
                continue

            if current_user_rank == 255:
                user_result.detail = f"User {current_user_id} is the group owner (Rank 255) and cannot be ranked by this API."
                user_result.status = "skipped"
                user_result.success = True
                logging.warning(user_result.detail)
                results.append(user_result)
                continue
            
            if current_user_rank > bot_rank:
                user_result.detail = f"User {current_user_id} is currently rank {current_user_rank}, which is higher than the bot's rank ({bot_rank}). Cannot modify this user's rank."
                user_result.status = "skipped"
                user_result.success = True
                logging.warning(user_result.detail)
                results.append(user_result)
                continue

            if current_user_rank == payload.rank:
                user_result.status = "skipped"
                user_result.success = True
                user_result.detail = f"User {current_user_id} is already at target rank {payload.rank} ('{target_role['name']}')."
                logging.info(user_result.detail)
                results.append(user_result)
                continue

            logging.info(f"Attempting to set rank for user {current_user_id} from {current_user_rank} ('{current_user_role.get('name', 'N/A')}') to {payload.rank} ('{target_role['name']}') in group {group_id}.")
            await roblox_client._human_delay()
            set_rank_url = f"https://groups.roblox.com/v1/groups/{group_id}/users/{current_user_id}"
            await roblox_client.request("PATCH", set_rank_url, json={"roleId": target_role["id"]})
            
            user_result.status = "success"
            user_result.success = True
            user_result.detail = f"User {current_user_id} successfully ranked to {payload.rank} ('{target_role['name']}')."
            logging.info(user_result.detail)

        except HTTPException as e:
            user_result.detail = f"API Error for {user_id_or_username}: {e.detail}"
            logging.error(f"API Error for user {user_id_or_username}: {e.detail}")
        except RobloxAPIError as e:
            user_result.detail = f"Roblox API Error ({e.status_code}) for {user_id_or_username}: {e.message}"
            logging.error(f"Roblox API Error for user {user_id_or_username}: {e.status_code} - {e.message}")
        except Exception as e:
            user_result.detail = f"Unexpected error for {user_id_or_username}: {str(e)}"
            logging.error(f"Unexpected error for user {user_id_or_username}: {str(e)}", exc_info=True)
        finally:
            results.append(user_result)

    success_count = sum(1 for r in results if r.success)
    failure_count = sum(1 for r in results if not r.success and r.status != 'skipped')
    
    overall_status = "success"
    if failure_count > 0 and success_count > 0:
        overall_status = "partial_success"
    elif failure_count > 0 and success_count == 0:
        overall_status = "failure"
    elif success_count == 0 and len(payload.users) > 0 and failure_count == 0:
        overall_status = "skipped_all"
    elif len(payload.users) == 0:
        overall_status = "success"

    logging.info(f"Mass rank operation finished for group {group_id}. Overall status: {overall_status}. Successful/Skipped: {success_count}, Failed: {failure_count}.")
    return MultiUserRankResponse(overall_status=overall_status, results=results)

@app.post("/groups/{group_id}/kick-all", response_model=MultiUserKickResponse, tags=["Membership"])
async def kick_all_members(
    group_id: int = Path(..., description="The ID of the group from which to kick all members."),
    _=Security(get_api_key)
):
    """
    Kicks all members from a Roblox group, excluding the group owner and the bot itself.
    
    The bot (the authenticated account via ROBLOSECURITY cookie) must have the necessary
    permissions to kick members in the target group.
    
    **Constraints:**
    - Cannot kick the group owner (rank 255).
    - Cannot kick the authenticated bot itself.
    - Cannot kick users who are currently ranked higher than the bot.
    - The bot must be a member of the group and have appropriate permissions.
    """
    logging.info(f"Received request to kick all members from group {group_id}.")
    results: List[SingleUserKickResult] = []
    total_members_attempted = 0
    successful_kicks = 0
    skipped_members = 0
    failed_kicks = 0

    try:
        authenticated_user_id = await roblox_client._get_authenticated_user_id()
    except RobloxAPIError as e:
        raise HTTPException(status_code=500, detail=f"Failed to identify the bot's own user ID: {e.message}. Cannot proceed with kicking.")

    try:
        bot_current_role = await _get_user_current_role(group_id, authenticated_user_id)
        bot_rank = bot_current_role.get("rank", 0)
    except HTTPException as e:
        if "Could not retrieve role for user" in e.detail or "User with ID" in e.detail:
             raise HTTPException(status_code=403, detail=f"The authenticated account (ID: {authenticated_user_id}) is not a member of group {group_id} or could not fetch its role. Cannot perform kicking operations.")
        raise HTTPException(status_code=e.status_code, detail=f"Failed to get bot's role in group {group_id}: {e.detail}")
    
    if bot_rank == 0:
        raise HTTPException(status_code=403, detail=f"The authenticated account (ID: {authenticated_user_id}) is not ranked in group {group_id}. Cannot perform kicking operations as a guest.")
    
    logging.info(f"Bot's current rank in group {group_id}: {bot_rank}")

    cursor: Optional[str] = None
    while True:
        logging.info(f"Fetching members page for group {group_id}, cursor: {cursor}")
        try:
            members_page = await roblox_client.request("GET", f"https://groups.roblox.com/v1/groups/{group_id}/users?limit=100&sortOrder=Asc&cursor={cursor or ''}")
            await roblox_client._human_delay()
        except RobloxAPIError as e:
            logging.error(f"Roblox API Error fetching members page (cursor: {cursor}): {e.status_code} - {e.message}")
            break

        if not members_page or "data" not in members_page or not members_page["data"]:
            logging.info("No more members data or empty page returned.")
            break

        for member_data in members_page["data"]:
            user_id = member_data["user"]["userId"]
            username = member_data["user"]["username"]
            member_rank = member_data["role"]["rank"]
            total_members_attempted += 1

            kick_result = SingleUserKickResult(
                user_id=user_id,
                username=username,
                status="failed",
                detail="Initial status.",
                success=False
            )

            if user_id == authenticated_user_id:
                kick_result.status = "skipped"
                kick_result.success = True
                kick_result.detail = f"User {user_id} ('{username}') is the authenticated bot itself. Skipping kick operation for self."
                skipped_members += 1
                logging.info(kick_result.detail)
                results.append(kick_result)
                continue

            if member_rank == 255:
                kick_result.status = "skipped"
                kick_result.success = True
                kick_result.detail = f"User {user_id} ('{username}') is the group owner (Rank 255). Cannot kick owner."
                skipped_members += 1
                logging.warning(kick_result.detail)
                results.append(kick_result)
                continue
            
            if member_rank > bot_rank and bot_rank != 255:
                 kick_result.status = "skipped"
                 kick_result.success = True
                 kick_result.detail = f"User {user_id} ('{username}') is currently rank {member_rank}, which is higher than the bot's rank ({bot_rank}). Cannot kick this user due to insufficient permissions."
                 skipped_members += 1
                 logging.warning(kick_result.detail)
                 results.append(kick_result)
                 continue


            logging.info(f"Attempting to kick user {user_id} ('{username}') from group {group_id}.")
            try:
                await roblox_client._human_delay()
                await roblox_client.request("DELETE", f"https://groups.roblox.com/v1/groups/{group_id}/users/{user_id}")
                kick_result.status = "success"
                kick_result.success = True
                kick_result.detail = f"User {user_id} ('{username}') successfully kicked."
                successful_kicks += 1
                logging.info(kick_result.detail)
            except RobloxAPIError as e:
                kick_result.detail = f"Roblox API Error ({e.status_code}) for {user_id} ('{username}'): {e.message}"
                failed_kicks += 1
                logging.error(f"Roblox API Error kicking user {user_id}: {e.status_code} - {e.message}")
            except Exception as e:
                kick_result.detail = f"Unexpected error for {user_id} ('{username}'): {str(e)}"
                failed_kicks += 1
                logging.error(f"Unexpected error kicking user {user_id}: {str(e)}", exc_info=True)
            finally:
                results.append(kick_result)
        
        cursor = members_page.get("nextPageCursor")
        if not cursor:
            break

    overall_status = "success"
    if failed_kicks > 0 and (successful_kicks > 0 or skipped_members > 0):
        overall_status = "partial_success"
    elif failed_kicks > 0 and successful_kicks == 0 and skipped_members == 0:
        overall_status = "failure"
    elif total_members_attempted == skipped_members and total_members_attempted > 0:
        overall_status = "skipped_all"
    elif total_members_attempted == 0:
        overall_status = "success"

    logging.info(f"Mass kick operation finished for group {group_id}. Overall status: {overall_status}. Total members found/attempted: {total_members_attempted}, Kicked: {successful_kicks}, Skipped: {skipped_members}, Failed: {failed_kicks}.")
    
    return MultiUserKickResponse(
        overall_status=overall_status,
        total_members_attempted=total_members_attempted,
        successful_kicks=successful_kicks,
        skipped_members=skipped_members,
        failed_kicks=failed_kicks,
        results=results
    )
    
if __name__ == "__main__":
    print("--- Roblox Group Management API [Paranoid Masquerade Edition - v4.9.6] ---")
    print("Starting server...")
    print(f"Listening on: http://0.0.0.0:{APP_PORT}")
    print(f"API Documentation available at: http://127.0.0.1:{APP_PORT}/docs")
    print(f"Your API Key is: {API_KEY}")
    print("-----------------------------------")
    uvicorn.run(app, host="0.0.0.0", port=APP_PORT)