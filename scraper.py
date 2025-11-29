import aiohttp
import asyncio
import json
import time
import csv
import re
import uuid
from datetime import datetime
from urllib.parse import quote
import pandas as pd

import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    WebDriverException,
    NoSuchWindowException,
)

INSTAGRAM_APP_ID = "936619743392459"

# ====== MULTI-ACCOUNT SETUP ======
INSTAGRAM_ACCOUNTS = [
    {"username": "hapiha3446", "password": "Janmejaya@123"},
    {"username": "lobosi2727", "password": "Janmejaya@123"},
    {"username": "jabona8996", "password": "Janmejaya@123"},
    {"username": "ditesov175", "password": "Janmejaya@123"},
    # Add more if you want
]

# Track state per account: failures, disabled, last error
ACCOUNT_STATE = {}


def init_account_state():
    """Initialize state dict for all accounts."""
    global ACCOUNT_STATE
    ACCOUNT_STATE = {
        acc["username"]: {
            "fail_count": 0,
            "disabled": False,
            "last_error": None,
        }
        for acc in INSTAGRAM_ACCOUNTS
    }


def get_next_account():
    """Pick the next enabled account with the lowest fail count."""
    enabled_accounts = [
        a for a in INSTAGRAM_ACCOUNTS if not ACCOUNT_STATE[a["username"]]["disabled"]
    ]
    if not enabled_accounts:
        return None
    # sort by fail_count so we use healthier accounts first
    enabled_accounts.sort(key=lambda a: ACCOUNT_STATE[a["username"]]["fail_count"])
    return enabled_accounts[0]


class InstagramCommentScraperFixed:
    def __init__(self, accounts):
        self.accounts = accounts
        self.session_id = None
        self.csrf_token = None
        self.cookies = {}
        self.scraped_users = {}
        self.driver = None
        self.current_account = None

    # ============== SELENIUM DRIVER HELPERS ===================

    def init_driver(self):
        """Initialize undetected Chrome driver."""
        try:
            options = uc.ChromeOptions()
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920,1080")
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-popup-blocking")

            self.driver = uc.Chrome(options=options)
            self.driver.delete_all_cookies()
            print("✅ Chrome driver initialized successfully")
        except WebDriverException as e:
            print(f"❌ Failed to initialize Chrome driver: {e}")
            self.driver = None

    def close_driver(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None

    # ============== HTTP HEADERS ===================

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

    # ============== LOGIN VIA SELENIUM ===================

    async def login(self):
        """
        Login using Selenium undetected_chromedriver.
        Rotate through accounts until one succeeds.
        """
        print("=" * 60)
        print("🔐 Logging in to Instagram USING SELENIUM with account rotation...")
        print("=" * 60)

        if not ACCOUNT_STATE:
            init_account_state()

        # Initialize driver once
        self.init_driver()
        if not self.driver:
            print("❌ Cannot start Selenium driver; aborting login.")
            return False

        try:
            while True:
                account = get_next_account()
                if not account:
                    print("❌ No available accounts (all disabled).")
                    return False

                username = account["username"]
                password = account["password"]
                self.current_account = username

                print(f"\n🎯 Selected account for this run: {username}")
                print("=" * 60)
                print(f"🔐 Logging in as {username}...")
                print("=" * 60)

                try:
                    self.driver.get("https://www.instagram.com/accounts/login/")
                    # Wait for username field
                    WebDriverWait(self.driver, 30).until(
                        EC.presence_of_element_located((By.NAME, "username"))
                    )

                    # Fill login form
                    user_input = self.driver.find_element(By.NAME, "username")
                    pass_input = self.driver.find_element(By.NAME, "password")

                    user_input.clear()
                    pass_input.clear()
                    user_input.send_keys(username)
                    pass_input.send_keys(password)

                    # Click login button
                    login_btn = self.driver.find_element(By.XPATH, "//button[@type='submit']")
                    login_btn.click()

                    # Wait for either success (cookie) or challenge
                    def session_or_challenge(drv):
                        current_url = drv.current_url
                        # If checkpoint/challenge page
                        if "challenge" in current_url or "two_factor" in current_url:
                            return "challenge"
                        cookie = drv.get_cookie("sessionid")
                        if cookie and cookie.get("value"):
                            return "session"
                        return False

                    try:
                        res = WebDriverWait(self.driver, 40).until(session_or_challenge)
                    except TimeoutException:
                        res = None

                    if res == "challenge":
                        print(f"⚠️ Account {username} hit checkpoint / 2FA / challenge.")
                        ACCOUNT_STATE[username]["fail_count"] += 1
                        ACCOUNT_STATE[username]["last_error"] = "checkpoint_or_2fa"
                        # Disable after 1 challenge to avoid lock
                        ACCOUNT_STATE[username]["disabled"] = True
                        continue

                    # Check for login error message on page
                    page_source = self.driver.page_source.lower()
                    if (
                        "incorrect password" in page_source
                        or "sorry, your password was incorrect" in page_source
                    ):
                        print(f"❌ Incorrect password for {username}.")
                        ACCOUNT_STATE[username]["fail_count"] += 1
                        ACCOUNT_STATE[username]["last_error"] = "bad_password"
                        if ACCOUNT_STATE[username]["fail_count"] >= 3:
                            ACCOUNT_STATE[username]["disabled"] = True
                        continue

                    # Check cookies
                    sess_cookie = self.driver.get_cookie("sessionid")
                    csrf_cookie = self.driver.get_cookie("csrftoken")

                    if not sess_cookie or not sess_cookie.get("value"):
                        print(
                            "❌ Login failed: No 'sessionid' cookie; "
                            "IG did not fully authenticate this session."
                        )
                        ACCOUNT_STATE[username]["fail_count"] += 1
                        ACCOUNT_STATE[username]["last_error"] = "no_sessionid"
                        if ACCOUNT_STATE[username]["fail_count"] >= 3:
                            ACCOUNT_STATE[username]["disabled"] = True
                        continue

                    # SUCCESS
                    self.cookies = {c["name"]: c["value"] for c in self.driver.get_cookies()}
                    self.session_id = self.cookies.get("sessionid")
                    self.csrf_token = self.cookies.get("csrftoken") or (
                        csrf_cookie and csrf_cookie.get("value")
                    )

                    print(f"✅ Login successful as {username}")
                    print(f"Session ID: {self.session_id[:20]}...")

                    # Reset account fail state
                    ACCOUNT_STATE[username]["fail_count"] = 0
                    ACCOUNT_STATE[username]["last_error"] = None

                    return True

                except (
                    TimeoutException,
                    NoSuchElementException,
                    WebDriverException,
                    NoSuchWindowException,
                ) as e:
                    print(f"❌ Login error for {username}: {e}")
                    ACCOUNT_STATE[username]["fail_count"] += 1
                    ACCOUNT_STATE[username]["last_error"] = str(e)
                    if ACCOUNT_STATE[username]["fail_count"] >= 3:
                        ACCOUNT_STATE[username]["disabled"] = True
                    # Try next account
                    continue

        finally:
            # Close Selenium browser; cookies are already copied
            self.close_driver()

    # ============== BIO HELPERS ===================

    def extract_emails_from_bio(self, text):
        if not text:
            return []
        return re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)

    def extract_phones_from_bio(self, text):
        if not text:
            return []
        pattern = r"\+?\d{1,4}?[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}"
        return re.findall(pattern, text)

    # ============== PROFILE SCRAPING ===================

    async def get_user_profile(self, session, username, semaphore):
        async with semaphore:
            if username in self.scraped_users:
                return self.scraped_users[username]

            url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
            try:
                async with session.get(url, headers=self.get_headers()) as resp:
                    if resp.status != 200:
                        print(f"⚠️ Skipped {username} (status {resp.status})")
                        return self.create_empty_profile(username)

                    data = await resp.json()
                    user = data.get("data", {}).get("user", {})
                    if not user:
                        return self.create_empty_profile(username)

                    bio = user.get("biography", "")
                    bio_emails = self.extract_emails_from_bio(bio)
                    bio_phones = self.extract_phones_from_bio(bio)

                    full_name = user.get("full_name", "").strip()
                    parts = full_name.split(" ", 1)
                    first_name = parts[0] if parts else ""
                    last_name = parts[1] if len(parts) > 1 else ""

                    email = bio_emails[0] if bio_emails else ""
                    phone = bio_phones[0] if bio_phones else ""

                    profile = {
                        "username": username,
                        "email": email,
                        "phone": phone,
                        "madid": str(uuid.uuid4()),
                        "fn": first_name,
                        "ln": last_name,
                        "zip": "",
                        "ct": "",
                        "st": "",
                        "country": "",
                        "dob": "",
                        "doby": "",
                        "gen": "",
                        "age": "",
                        "uid": user.get("id", ""),
                        "value": "",
                        "fbid": user.get("fbid", ""),
                    }

                    self.scraped_users[username] = profile
                    await asyncio.sleep(1.2)
                    return profile

            except Exception as e:
                print(f"❌ Error fetching {username}: {str(e)}")
                return self.create_empty_profile(username)

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

    # ============== COMMENT SCRAPING ===================

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

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, cookies=self.cookies
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

                async with session.get(url, headers=self.get_headers()) as resp:
                    if resp.status != 200:
                        print(f"❌ Comment fetch failed: {resp.status}")
                        break
                    data = await resp.json()
                    edges = (
                        data.get("data", {})
                        .get("shortcode_media", {})
                        .get("edge_media_to_parent_comment", {})
                        .get("edges", [])
                    )
                    for edge in edges:
                        node = edge.get("node", {})
                        owner = node.get("owner", {})
                        comments.append(
                            {
                                "uid": owner.get("id", ""),  # User ID of the commenter
                                "username": owner.get("username", ""),  # Commenter's username
                                "commentText": node.get("text", ""),  # Comment text
                                "timestamp": datetime.fromtimestamp(
                                    node.get("created_at", 0)
                                ).isoformat(),  # Time of comment
                            }
                        )
                    page = (
                        data.get("data", {})
                        .get("shortcode_media", {})
                        .get("edge_media_to_parent_comment", {})
                        .get("page_info", {})
                    )
                    has_next = page.get("has_next_page", False)
                    after = page.get("end_cursor")
                    print(f"📊 {len(comments)} comments scraped so far...")
                    await asyncio.sleep(2)

        print(f"✅ Total comments: {len(comments)}")
        return comments

    async def scrape_commenters_profiles(self, comments, max_concurrent=5):
        usernames = list({c["username"] for c in comments if c.get("username")})
        print(f"\n👥 Found {len(usernames)} unique commenters")

        semaphore = asyncio.Semaphore(max_concurrent)
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, cookies=self.cookies
        ) as session:
            tasks = [self.get_user_profile(session, u, semaphore) for u in usernames]
            profiles = await asyncio.gather(*tasks)
        return profiles


# ============== CSV & PUBLIC API ===================


def save_to_csv(profiles, filename):
    if not profiles:
        print("❌ No profiles to save.")
        return

    # Step 1: Write profiles to CSV
    fieldnames = list(profiles[0].keys())
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(profiles)

    # Step 2: Remove first column
    df = pd.read_csv(filename)
    df = df.iloc[:, 1:]  # Drop the first column
    df.to_csv(filename, index=False)

    print(f"\n✅ Profiles saved to {filename} (first column removed)")


async def run_scrape_for_post(post_url: str, max_comments: int | None = None) -> dict:
    """
    Public function used by app.py:
    from scraper import run_scrape_for_post

    Returns a JSON-serializable dict:
    {
        "ok": True/False,
        "message": "...",
        "shortcode": ...,
        "post_url": ...,
        "comments_count": ...,
        "profiles_count": ...,
        "csv_file": "...",
        "json_file": "...",
        "data": {
            "comments": [...],
            "profiles": [...]
        }
    }
    """
    try:
        scraper = InstagramCommentScraperFixed(INSTAGRAM_ACCOUNTS)

        # 1) Login
        logged_in = await scraper.login()
        if not logged_in:
            return {
                "ok": False,
                "message": "Login failed for all accounts. Check credentials / challenges / IP.",
            }

        # 2) Get shortcode
        shortcode = scraper.get_post_shortcode(post_url)
        if not shortcode:
            return {"ok": False, "message": "Invalid Instagram post URL."}

        # 3) Scrape comments
        comments = await scraper.scrape_post_comments(shortcode, max_comments)

        # 4) Scrape commenter profiles
        profiles = await scraper.scrape_commenters_profiles(comments, max_concurrent=5)

        # 5) Save files
        csv_file = f"instagram_{shortcode}_profiles.csv"
        json_file = f"instagram_{shortcode}_comments.json"

        save_to_csv(profiles, csv_file)
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump({"comments": comments, "profiles": profiles}, f, indent=2, ensure_ascii=False)

        return {
            "ok": True,
            "message": "Scraping completed successfully.",
            "shortcode": shortcode,
            "post_url": post_url,
            "comments_count": len(comments),
            "profiles_count": len(profiles),
            "csv_file": csv_file,
            "json_file": json_file,
            "data": {
                "comments": comments,
                "profiles": profiles,
            },
        }

    except Exception as e:
        print("❌ Error in run_scrape_for_post:", e)
        return {"ok": False, "message": str(e)}


# Optional CLI usage for testing
if __name__ == "__main__":
    async def _test():
        url = input("Enter Instagram post URL: ").strip()
        max_c = input("Max comments (blank for all): ").strip()
        max_c = int(max_c) if max_c.isdigit() else None
        res = await run_scrape_for_post(url, max_c)
        print(json.dumps(res, indent=2, ensure_ascii=False))

    asyncio.run(_test())
