import aiohttp
import asyncio
import json
import time
import csv
import re
import uuid
import random
from datetime import datetime
from urllib.parse import quote
import pandas as pd

# ================== INSTAGRAM APP ==================
INSTAGRAM_APP_ID = "936619743392459"

# ================== ACCOUNTS POOL ==================
INSTAGRAM_ACCOUNTS = [
    {"username": "hapiha3446", "password": "Janmejaya@123"},
    {"username": "lobosi2727", "password": "Janmejaya@123"},
    {"username": "jabona8996", "password": "Janmejaya@123"},
    {"username": "ditesov175", "password": "Janmejaya@123"},
]

# Track state per account: failures, disabled, last error
ACCOUNT_STATE = {}


def init_account_state():
    global ACCOUNT_STATE
    ACCOUNT_STATE = {
        acc["username"]: {
            "fail_count": 0,
            "disabled": False,
            "last_error": None,
        }
        for acc in INSTAGRAM_ACCOUNTS
    }


init_account_state()


def mark_account_failure(username: str, error_code: str, error_message: str):
    state = ACCOUNT_STATE.get(username)
    if not state:
        return
    state["fail_count"] += 1
    state["last_error"] = f"{error_code}: {error_message}"

    error_code = (error_code or "").lower()
    suspicious_keywords = [
        "checkpoint",
        "two_factor",
        "2fa",
        "suspicious",
        "challenge",
        "login_required",
        "ip_block",
        "proxy",
    ]
    should_disable = (
        any(k in error_code for k in suspicious_keywords)
        or any(k in (error_message or "").lower() for k in suspicious_keywords)
        or state["fail_count"] >= 3
    )
    if should_disable:
        state["disabled"] = True
        print(f"🚫 Disabling account {username} due to repeated/blocking errors.")


def reset_all_accounts():
    for u, st in ACCOUNT_STATE.items():
        st["disabled"] = False
        st["fail_count"] = 0
        st["last_error"] = None
    print("🔄 All accounts re-enabled (all were disabled).")


def get_random_account():
    active_accounts = [
        acc for acc in INSTAGRAM_ACCOUNTS
        if not ACCOUNT_STATE.get(acc["username"], {}).get("disabled", False)
    ]
    if not active_accounts:
        reset_all_accounts()
        active_accounts = INSTAGRAM_ACCOUNTS[:]
    acc = random.choice(active_accounts)
    print(f"🎯 Selected account for this run: {acc['username']}")
    return acc["username"], acc["password"]


# ================== PROXY CONFIG (ALWAYS ON) ==================

PROXY_USER = "7666f3d986239b03740f"
PROXY_PASS = "dadc72a9517e4335"
PROXY_HOST = "gw.dataimpulse.com"
PROXY_PORT = 823
PROXY_URL = f"http://{PROXY_USER}:{PROXY_PASS}@{PROXY_HOST}:{PROXY_PORT}"


def proxy_kwargs():
    return {"proxy": PROXY_URL} if PROXY_URL else {}


# ================== SCRAPER CLASS ==================


class InstagramCommentScraperFixed:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session_id = None
        self.csrf_token = None
        self.cookies = {}
        self.scraped_users = {}

    def get_headers(self):
        headers = {
            "x-ig-app-id": INSTAGRAM_APP_ID,
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "https://www.instagram.com",
            "Referer": "https://www.instagram.com/",
        }
        if self.csrf_token:
            headers["X-CSRFToken"] = self.csrf_token
        return headers

    async def login(self):
        print("=" * 60)
        print(f"🔐 Logging in to Instagram USING PROXY as {self.username}...")
        print("=" * 60)

        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)

        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                trust_env=True
            ) as session:
                # STEP 1: open login page
                try:
                    async with session.get(
                        "https://www.instagram.com/accounts/login/",
                        headers=self.get_headers(),
                        **proxy_kwargs(),
                    ) as resp:
                        if resp.status != 200:
                            msg = f"Failed to open login page: HTTP {resp.status}"
                            print("❌", msg)
                            return {"ok": False, "error_code": "http_error", "message": msg}
                        for cookie in resp.cookies.values():
                            self.cookies[cookie.key] = cookie.value
                        self.csrf_token = self.cookies.get("csrftoken")
                except Exception as e:
                    msg = f"Exception opening login page: {repr(e)}"
                    print("❌", msg)
                    return {"ok": False, "error_code": "network_error", "message": msg}

                if not self.csrf_token:
                    msg = "Failed to retrieve CSRF token"
                    print("❌", msg)
                    return {"ok": False, "error_code": "no_csrf", "message": msg}

                # STEP 2: login POST
                timestamp = int(time.time())
                enc_password = f"#PWD_INSTAGRAM_BROWSER:0:{timestamp}:{self.password}"
                payload = {
                    "username": self.username,
                    "enc_password": enc_password,
                    "queryParams": "{}",
                    "optIntoOneTap": "false"
                }
                headers = self.get_headers()
                headers["Content-Type"] = "application/x-www-form-urlencoded"

                try:
                    async with session.post(
                        "https://www.instagram.com/accounts/login/ajax/",
                        data=payload,
                        headers=headers,
                        **proxy_kwargs(),
                    ) as resp:
                        text = await resp.text()
                        http_status = resp.status
                        try:
                            data = json.loads(text)
                        except Exception:
                            data = {}

                        if http_status != 200:
                            msg = f"Login HTTP error: {http_status} body={text[:400]}"
                            print("❌", msg)
                            error_code = data.get("message") or "http_error"
                            return {"ok": False, "error_code": error_code, "message": msg}

                        if data.get("two_factor_required"):
                            msg = "Two-factor required for this account."
                            print("❌", msg)
                            return {
                                "ok": False,
                                "error_code": "two_factor_required",
                                "message": msg,
                            }

                        if data.get("message") == "checkpoint_required":
                            msg = f"Checkpoint required. Data: {data}"
                            print("❌", msg)
                            return {
                                "ok": False,
                                "error_code": "checkpoint_required",
                                "message": msg,
                            }

                        if not data.get("authenticated"):
                            msg = f"Not authenticated: {data}"
                            print("❌", msg)
                            return {
                                "ok": False,
                                "error_code": "not_authenticated",
                                "message": msg,
                            }

                        for cookie in resp.cookies.values():
                            self.cookies[cookie.key] = cookie.value
                        self.session_id = self.cookies.get("sessionid")
                        self.csrf_token = self.cookies.get("csrftoken", self.csrf_token)

                        if not self.session_id:
                            msg = "Login OK but no sessionid cookie."
                            print("❌", msg)
                            return {
                                "ok": False,
                                "error_code": "no_sessionid",
                                "message": msg,
                            }

                        print(f"✅ Login successful as {self.username}")
                        print(f"Session ID: {self.session_id[:20]}...")
                        return {"ok": True, "error_code": None, "message": "login_ok"}

                except Exception as e:
                    msg = f"Exception during login POST: {repr(e)}"
                    print("❌", msg)
                    return {
                        "ok": False,
                        "error_code": "network_error",
                        "message": msg,
                    }

        except Exception as e:
            msg = f"Fatal login session error: {repr(e)}"
            print("❌", msg)
            return {
                "ok": False,
                "error_code": "session_error",
                "message": msg,
            }

    def extract_emails_from_bio(self, text):
        if not text:
            return []
        return re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)

    def extract_phones_from_bio(self, text):
        if not text:
            return []
        pattern = r'\+?\d{1,4}?[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
        return re.findall(pattern, text)

    def create_empty_profile(self, username):
        return {
            "username": username,
            "email": "",
            "phone": "",
            "madid": str(uuid.uuid4()),
            "fn": "",
            "ln": "",
            "zip": "",
            "ct": "",
            "st": "",
            "country": "",
            "dob": "",
            "doby": "",
            "gen": "",
            "age": "",
            "uid": "",
            "value": "",
            "fbid": "",
        }

    async def get_user_profile(self, session, username, semaphore):
        async with semaphore:
            if username in self.scraped_users:
                return self.scraped_users[username]

            url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
            try:
                async with session.get(
                    url, headers=self.get_headers(), **proxy_kwargs()
                ) as resp:
                    if resp.status != 200:
                        print(f"⚠️ Skipped {username} (status {resp.status})")
                        profile = self.create_empty_profile(username)
                        self.scraped_users[username] = profile
                        return profile

                    data = await resp.json()
                    user = data.get("data", {}).get("user", {})
                    if not user:
                        profile = self.create_empty_profile(username)
                        self.scraped_users[username] = profile
                        return profile

                    bio = user.get("biography", "") or ""
                    bio_emails = self.extract_emails_from_bio(bio)
                    bio_phones = self.extract_phones_from_bio(bio)

                    full_name = (user.get("full_name") or "").strip()
                    parts = full_name.split(" ", 1)
                    first_name = parts[0] if parts else ""
                    last_name = parts[1] if len(parts) > 1 else ""

                    profile = {
                        "username": username,
                        "email": ",".join(bio_emails),
                        "phone": ",".join(bio_phones),
                        "madid": str(uuid.uuid4()),
                        "fn": first_name,
                        "ln": last_name,
                        "zip": "",
                        "ct": "",
                        "st": "",
                        "country": user.get("country_block", ""),
                        "dob": "",
                        "doby": "",
                        "gen": "",
                        "age": "",
                        "uid": user.get("id", ""),
                        "value": "",
                        "fbid": user.get("fbid_v2", ""),
                    }

                    self.scraped_users[username] = profile
                    await asyncio.sleep(1.2)
                    return profile

            except Exception as e:
                print(f"❌ Error fetching {username}: {repr(e)}")
                profile = self.create_empty_profile(username)
                self.scraped_users[username] = profile
                return profile

    def get_post_shortcode(self, url):
        parts = url.rstrip("/").split("/")
        for i, part in enumerate(parts):
            if part in ["p", "reel", "tv"] and i + 1 < len(parts):
                return parts[i + 1].split("?")[0]
        return None

    async def scrape_post_comments(self, shortcode, max_comments=None):
        comments, after, has_next = [], None, True
        print(f"\n💬 Fetching comments for shortcode: {shortcode}")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)

        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                cookies=self.cookies,
                trust_env=True
            ) as session:
                while has_next:
                    if max_comments and len(comments) >= max_comments:
                        break

                    variables = {"shortcode": shortcode, "first": 50}
                    if after:
                        variables["after"] = after

                    url = (
                        "https://www.instagram.com/graphql/query/"
                        "?query_hash=bc3296d1ce80a24b1b6e40b1e72903f5"
                        f"&variables={quote(json.dumps(variables))}"
                    )

                    try:
                        async with session.get(
                            url, headers=self.get_headers(), **proxy_kwargs()
                        ) as resp:
                            if resp.status != 200:
                                print(f"❌ Comment fetch failed: {resp.status}")
                                break
                            data = await resp.json()
                            media = data.get("data", {}).get("shortcode_media", {})
                            if not media:
                                print("❌ No media data in response (maybe private or removed).")
                                break

                            edge_root = media.get("edge_media_to_parent_comment", {})
                            edges = edge_root.get("edges", [])

                            for edge in edges:
                                node = edge.get("node", {})
                                owner = node.get("owner", {})
                                comments.append({
                                    "uid": owner.get("id", ""),
                                    "username": owner.get("username", ""),
                                    "commentText": node.get("text", ""),
                                    "timestamp": datetime.fromtimestamp(
                                        node.get("created_at", 0)
                                    ).isoformat(),
                                })

                                if max_comments and len(comments) >= max_comments:
                                    break

                            page = edge_root.get("page_info", {})
                            has_next = page.get("has_next_page", False)
                            after = page.get("end_cursor")

                            print(f"📊 {len(comments)} comments scraped so far...")
                            await asyncio.sleep(2)

                    except Exception as e:
                        print(f"❌ Error while fetching comments page: {repr(e)}")
                        break

        except Exception as e:
            print(f"❌ Fatal error in scrape_post_comments: {repr(e)}")

        print(f"✅ Total comments: {len(comments)}")
        return comments

    async def scrape_commenters_profiles(self, comments, max_concurrent=5):
        usernames = list({c["username"] for c in comments if c.get("username")})
        print(f"\n👥 Found {len(usernames)} unique commenters")

        if not usernames:
            return []

        semaphore = asyncio.Semaphore(max_concurrent)
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=60)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            cookies=self.cookies,
            trust_env=True
        ) as session:
            tasks = [self.get_user_profile(session, u, semaphore) for u in usernames]
            profiles = await asyncio.gather(*tasks)
        return profiles


# ================== OUTPUT HELPERS ==================


def save_to_csv(profiles, filename):
    if not profiles:
        print("❌ No profiles to save.")
        return

    fieldnames = list(profiles[0].keys())
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(profiles)

    df = pd.read_csv(filename)
    df = df.iloc[:, 1:]
    df.to_csv(filename, index=False)
    print(f"\n✅ Profiles saved to {filename} (first column removed)")


# ================== MAIN PIPELINE ==================


async def run_scrape_for_post(post_url: str, max_comments: int | None = None):
    try:
        last_error = None

        for attempt in range(len(INSTAGRAM_ACCOUNTS)):
            username, password = get_random_account()
            scraper = InstagramCommentScraperFixed(username, password)

            login_result = await scraper.login()
            if not login_result["ok"]:
                mark_account_failure(
                    username,
                    login_result.get("error_code") or "login_failed",
                    login_result.get("message") or "",
                )
                last_error = f"{username}: {login_result.get('message')}"
                print(f"⚠️ Login failed for {username}, trying another account...")
                continue

            shortcode = scraper.get_post_shortcode(post_url)
            if not shortcode:
                return {"ok": False, "message": "Invalid Instagram post URL."}

            comments = await scraper.scrape_post_comments(shortcode, max_comments)
            profiles = await scraper.scrape_commenters_profiles(comments, max_concurrent=5)

            csv_file = f"instagram_{shortcode}_profiles.csv"
            json_file = f"instagram_{shortcode}_comments.json"

            save_to_csv(profiles, csv_file)
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(
                    {"comments": comments, "profiles": profiles},
                    f,
                    indent=2,
                    ensure_ascii=False,
                )

            return {
                "ok": True,
                "message": f"Scrape complete using account {username}.",
                "shortcode": shortcode,
                "total_comments": len(comments),
                "total_profiles": len(profiles),
                "csv_file": csv_file,
                "json_file": json_file,
            }

        return {
            "ok": False,
            "message": f"All accounts failed to login. Last error: {last_error}",
        }

    except Exception as e:
        print(f"❌ Unexpected error in run_scrape_for_post: {repr(e)}")
        return {
            "ok": False,
            "message": f"Unexpected error in scraper: {str(e)}",
        }
