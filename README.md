# Roblox-Group-Management-API

This is a powerful, security-focused, and stealthy Roblox Group Management API written entirely in Python. It runs a local web server that wraps complex Roblox group operations into simple, secure RESTful API endpoints, allowing for easy automation of your group's administration.

The core design philosophy of this project is the "Paranoid Masquerade Mode," which aims to minimize the risk of detection by Roblox's anti-bot systems by deeply emulating the behavior of a real human user browsing the site.

Core Features: Why This is Different
Feature	This Project (Paranoid Mode)	Traditional / Simple Scripts
Browser Simulation	High-Fidelity Mimicry: Dynamically rotates between various browser identities (User-Agents) and sends matching sec-ch-ua headers.	Basic or None: Typically uses a single, static User-Agent, which is easy to fingerprint.
Session Management	Smart Keep-Alive: Includes background tasks to automatically keep the session alive and periodically refresh the CSRF token by simulating harmless activity, dramatically extending cookie lifetime.	Passive Usage: The Cookie and CSRF token expire quickly, causing the script to fail frequently.
Request Protocol	Modern HTTP/2: Uses httpx to send requests over HTTP/2, perfectly matching the behavior of modern browsers like Chrome and Edge.	Outdated HTTP/1.1: A clear sign of a non-browser, automated tool.
Behavioral Pattern	Human-like Pacing: Inserts small, randomized delays before and after sensitive operations to mimic human reaction times and avoid triggering rate limits.	Instantaneous: Executes requests at machine speed, a classic red flag for bot detection.
Risk Profile	Low Risk	High Risk
Features List (API Endpoints)

This API provides comprehensive group management functionality.

Information

GET /groups/{group_id}: Get public information about a group (name, owner, member count, etc.).

GET /groups/{group_id}/users/{user_identifier}/role: Get a specific user's role and rank within the group.

GET /groups/{group_id}/roles: Get a list of all roles in the group (ID, name, rank).

Ranking

POST /groups/{group_id}/users/{user_identifier}/promote: Promote a user by one rank.

POST /groups/{group_id}/users/{user_identifier}/demote: Demote a user by one rank.

PATCH /groups/{group_id}/users/{user_identifier}/rank: Set a user's rank to a specific value (1-255).

POST /groups/{group_id}/mass-rank: (Advanced) Set a rank for multiple users at once, with detailed reporting for each user.

Membership

DELETE /groups/{group_id}/users/{user_identifier}: Kick a single user from the group.

POST /groups/{group_id}/kick-all: (Advanced) Kick all kickable members from a group (automatically skips the owner, the bot itself, and higher-ranked members).

GET /groups/{group_id}/join-requests: View pending join requests.

POST /groups/{group_id}/join-requests/accept: Accept a user's join request.

POST /groups/{group_id}/join-requests/decline: Decline a user's join request.

GET /groups/{group_id}/members: Get a paginated list of all group members.

GET /groups/{group_id}/roles/{role_id}/users: Get a paginated list of members in a specific role.

Finance

GET /groups/{group_id}/revenue/summary/{time_period}: Get the group's revenue summary.

POST /groups/{group_id}/payouts: Make Robux payouts to group members.

Auditing

GET /groups/{group_id}/audit-log: Get the group's audit log to track administrative actions.

Installation and Setup
1. Prerequisites

Python 3.7 or newer must be installed.

2. Install Dependencies

Open your terminal or command prompt and run the following command:

pip install -r requirements.txt

3. How to Get Your .ROBLOSECURITY Cookie

⚠️ Security Warning: Your .ROBLOSECURITY cookie provides full access to your Roblox account. It is as sensitive as your password. NEVER share it with anyone. This script will only use it on your own computer.

Here is how to find it using a web browser (steps are for Chrome/Edge):

Open your browser and log in to your Roblox account.

After logging in, press F12 to open the Developer Tools.

Go to the "Application" tab.

On the left-hand menu, expand the "Cookies" section and click on https://www.roblox.com.

A table of cookies will appear. Find the cookie with the name .ROBLOSECURITY.

Click on it. In the panel below, find the "Cookie Value" field.

Copy the entire value. It will be a very long string that starts with _|WARNING:-DO-NOT-SHARE-THIS....

4. Configure the Script

In the same folder as the script, create a new file named exactly .env.

Open the .env file and add the following line:

Generated code
ROBLOSECURITY=PASTE_YOUR_COOKIE_VALUE_HERE
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
IGNORE_WHEN_COPYING_END

Replace PASTE_YOUR_COOKIE_VALUE_HERE with the cookie value you just copied.

Save and close the file.

5. Run the Server

In your terminal, run the script:

Generated bash
python your_script_name.py
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

The server will start, and you will see the server address and your unique API Key printed in the console.

How to Use the API

Get Your API Key: The first time you run the script, it will print your API key to the console and save it in api_key.txt.

Authorize Requests: Every API request must include this key. You have two options:

Header (Recommended): x-api-key: YOUR_API_KEY

Query Parameter: ?api_key=YOUR_API_KEY

Interactive Docs: Once the server is running, navigate to http://127.0.0.1:8000/docs. This will open an interactive API documentation (Swagger UI) where you can explore and test every endpoint directly from your browser.

Example using curl

To get information about a group:

Generated bash
curl -X GET "http://127.0.0.1:8000/groups/1234567" \
     -H "x-api-key: your_api_key_here"
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END
Security Considerations

API Key Protection: All endpoints are protected by the auto-generated API key.

Local Execution: The entire service, including your sensitive .ROBLOSECURITY cookie, runs only on your local machine. Your credentials are never sent to any third-party server.

Evasion: The "Paranoid Masquerade" design is intended to protect your Roblox account from detection, but no method is foolproof.

Disclaimer

This tool is intended for educational and research purposes only. The use of automation tools may be against Roblox's Terms of Service. The user assumes all risks associated with the use of this tool, including but not limited to account restrictions or termination. The developer assumes no liability.
