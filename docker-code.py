from fastapi import FastAPI, Query, HTTPException
from pydantic import BaseModel
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import os
import json
import logging
import random
import asyncio
from typing import Optional, Dict, Any
from starlette.status import HTTP_403_FORBIDDEN, HTTP_429_TOO_MANY_REQUESTS

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI(
title="Chrome Remote Controller for Roblox API",
description="A FastAPI service to control Chrome via Selenium WebDriver for Roblox API operations.",
version="1.0.0"
)

初始化 Selenium WebDriver

def init_driver():
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")
chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")

driver = webdriver.Remote(  
    command_executor="http://localhost:4444/wd/hub",  
    options=chrome_options  
)  
driver.implicitly_wait(10)  
   
driver.get("https://www.roblox.com")  
roblox_cookie = os.getenv("ROBLOSECURITY")  
if not roblox_cookie:  
    driver.quit()  
    raise ValueError("ROBLOSECURITY environment variable not set!")  
driver.add_cookie({"name": ".ROBLOSECURITY", "value": roblox_cookie})  
driver.add_cookie({  
    "name": "RBXEventTrackerV2",  
    "value": f"CreateDate={time.strftime('%m/%d/%Y %I:%M:%S %p')}&rbxid=&browserid={random.randint(100000000, 999999999)}"  
})  
driver.add_cookie({  
    "name": "GuestData",  
    "value": f"UserID=-{random.randint(100000000, 999999999)}"  
})  
  
logging.info("Selenium WebDriver initialized with cookies.")  
return driver

driver = init_driver()
csrf_token: Optional[str] = None

class RobloxAPIRequest(BaseModel):
method: str = "GET"
url: str
headers: Optional[Dict[str, str]] = None
body: Optional[Dict[str, Any]] = None

class RobloxAPIResponse(BaseModel):
status: int
body: Any
headers: Dict[str, str]

async def human_delay():
delay = random.uniform(0.4, 1.2)
await asyncio.sleep(delay)

async def get_csrf_token():
global csrf_token
logging.info("Attempting to refresh CSRF token...")
try:
loop = asyncio.get_event_loop()
def sync_get_csrf():
script = """
return fetch('https://auth.roblox.com/v2/logout', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
credentials: 'include'
}).then(response => {
if (response.status === 403) {
return response.headers.get('x-csrf-token');
}
return response.text().then(text => { throw { status: response.status, text: text }; });
});
"""
csrf = driver.execute_script(script)
if csrf:
return csrf
raise Exception("No CSRF token found")
csrf_token = await loop.run_in_executor(None, sync_get_csrf)
logging.info(f"Successfully refreshed CSRF token: {csrf_token}")
except Exception as e:
logging.error(f"Failed to get CSRF token: {str(e)}")
raise HTTPException(status_code=503, detail=f"Failed to get CSRF token: {str(e)}")

@app.on_event("startup")
async def startup_event():
global csrf_token
# wair
await get_csrf_token()
# wait
async def csrf_refresher():
while True:
await asyncio.sleep(random.uniform(290, 310))
logging.info("[CSRF-Refresher] Performing scheduled CSRF token refresh.")
try:
await get_csrf_token()
except Exception as e:
logging.error(f"[CSRF-Refresher] Failed to refresh CSRF token: {str(e)}")
asyncio.create_task(csrf_refresher())

@app.on_event("shutdown")
async def shutdown_event():
driver.quit()
logging.info("Selenium WebDriver session closed.")

@app.get("/")
async def root():
return {"message": "Chrome controller ready"}

@app.get("/open_url")
async def open_url(url: str = Query(...)):
try:
driver.get(url)
await human_delay()
return {"status": "success", "url": url}
except Exception as e:
raise HTTPException(status_code=500, detail=f"Failed to open URL: {str(e)}")

@app.post("/api_request", response_model=RobloxAPIResponse)
async def execute_api_request(request: RobloxAPIRequest):
"""
Execute a Roblox API request using Chrome via Selenium.
"""
global csrf_token
if request.method.upper() not in ["GET", "HEAD", "OPTIONS"] and csrf_token is None:
await get_csrf_token()
await human_delay()

try:  
    loop = asyncio.get_event_loop()  
    def sync_request():  
        headers = request.headers or {  
            "Accept": "application/json, text/plain, */*",  
            "Content-Type": "application/json;charset=UTF-8" if request.body else "text/plain",  
            "Referer": "https://www.roblox.com"  
        }  
        if request.method.upper() not in ["GET", "HEAD", "OPTIONS"] and csrf_token:  
            headers["X-CSRF-TOKEN"] = csrf_token  
          
        script = f"""  
            return fetch('{request.url}', {{  
                method: '{request.method}',  
                headers: {json.dumps(headers)},  
                body: {json.dumps(request.body) if request.body else "undefined"},  
                credentials: 'include'  
            }}).then(response => {{  
                return response.text().then(text => {{  
                    return {{  
                        status: response.status,  
                        headers: Object.fromEntries(response.headers.entries()),  
                        body: text  
                    }};  
                }});  
            }}).catch(error => {{  
                throw {{ status: 500, text: error.message }};  
            }});  
        """  
        response = driver.execute_script(script)  
        try:  
            response["body"] = json.loads(response["body"])  
        except json.JSONDecodeError:  
            pass  # 保留原始文本  
        return response  
      
    response = await loop.run_in_executor(None, sync_request)  
    await human_delay()  
      
    if response["status"] == 403 and ("Token Validation Failed" in str(response["body"]) or "Authorization has been denied" in str(response["body"])):  
        logging.warning("CSRF token validation failed. Retrying with a new token...")  
        await get_csrf_token()  
        headers = request.headers or {}  
        headers["X-CSRF-TOKEN"] = csrf_token  
        response = await loop.run_in_executor(None, lambda: driver.execute_script(f"""  
            return fetch('{request.url}', {{  
                method: '{request.method}',  
                headers: {json.dumps(headers)},  
                body: {json.dumps(request.body) if request.body else "undefined"},  
                credentials: 'include'  
            }}).then(response => {{  
                return response.text().then(text => {{  
                    return {{  
                        status: response.status,  
                        headers: Object.fromEntries(response.headers.entries()),  
                        body: text  
                    }};  
                }});  
            }});  
        """))  
        try:  
            response["body"] = json.loads(response["body"])  
        except json.JSONDecodeError:  
            pass  
      
    if response["status"] == 429:  
        raise HTTPException(status_code=HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")  
      
    return RobloxAPIResponse(  
        status=response["status"],  
        body=response["body"],  
        headers=response["headers"]  
    )  
except Exception as e:  
    raise HTTPException(status_code=500, detail=f"API request failed: {str(e)}")

