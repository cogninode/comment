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

INSTAGRAM_APP_ID = "936619743392459"

# ========== MULTI-ACCOUNT ROTATION ==========
INSTAGRAM_ACCOUNTS = [
    
    {"username": "jabona8996", "password": "Janmejaya@123"},
    {"username": "ditesov175", "password": "Janmejaya@123"},
    {"username": "hapiha3446", "password": "Janmejaya@123"},
    {"username": "lobosi2727", "password": "Janmejaya@123"},
]
# ===========================================


class InstagramCommentScraperFixed:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session_id = None
        self.csrf_token = None
        self.cookies = {}
        self.scraped_users = {}
        self.last_error = None  # store last login error

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
        print(f"🔐 Logging in to Instagram as {self.username}...")
        print("=" * 60)
        self.last_error = None

        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # 1) Open login page to get CSRF
            try:
                async with session.get(
                    "https://www.instagram.com/accounts/login/",
                    headers=self.get_headers()
                ) as resp:
                    if resp.status != 200:
                        self.last_error = f"login_page_http_{resp.status}"
                        print(f"❌ Failed to open login page: {resp.status}")
                        return False
                    self.csrf_token = (
                        resp.cookies.get("csrftoken").value
                        if resp.cookies.get("csrftoken")
                        else None
                    )
            except Exception as e:
                self.last_error = f"login_page_exception:{e!r}"
                print(f"❌ Exception opening login page: {e!r}")
                return False

            if not self.csrf_token:
                self.last_error = "no_csrftoken"
                print("❌ Failed to retrieve CSRF token")
                return False

            # 2) Login AJAX POST
            timestamp = int(time.time())
            enc_password = f"#PWD_INSTAGRAM_BROWSER:0:{timestamp}:{self.password}"

            payload = {
                "username": self.username,
                "enc_password": enc_password,
                "queryParams": "{}",
                "optIntoOneTap": "false",
            }

            headers = self.get_headers()
            headers["Content-Type"] = "application/x-www-form-urlencoded"

            async with session.post(
                "https://www.instagram.com/accounts/login/ajax/",
                data=payload,
                headers=headers,
            ) as resp:
                text = await resp.text()

                if resp.status != 200:
                    # checkpoint_required usually comes here as 400
                    try:
                        j = json.loads(text)
                        msg = j.get("message")
                        self.last_error = msg or f"http_{resp.status}"
                    except Exception:
                        self.last_error = f"http_{resp.status}"
                    print(f"❌ Login failed: {resp.status}")
                    print(text[:300])
                    return False

                data = json.loads(text)
                if not data.get("authenticated"):
                    # e.g. UserInvalidCredentials or checkpoint_required via JSON
                    self.last_error = (
                        data.get("error_type")
                        or data.get("message")
                        or "not_authenticated"
                    )
                    print(f"❌ Login failed: {data}")
                    return False

                # store cookies from response
                for cookie in resp.cookies.values():
                    self.cookies[cookie.key] = cookie.value

                # make sure csrftoken is stored
                if "csrftoken" in self.cookies:
                    self.csrf_token = self.cookies["csrftoken"]

                self.session_id = self.cookies.get("sessionid")

                if not self.session_id:
                    self.last_error = "no_sessionid"
                    print("❌ Login did not return a sessionid cookie")
                    return False

                print(f"✅ Login successful as {self.username}")
                print(f"Session ID: {self.session_id[:20]}...")
                return True

    # ========== HELPERS FOR PROFILE / BIO ==========

    def extract_emails_from_bio(self, text):
        if not text:
            return []
        return re.findall(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            text,
        )

    def extract_phones_from_bio(self, text):
        if not text:
            return []
        pattern = r"\+?\d{1,4}?[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}"
        return re.findall(pattern, text)

    async def get_user_profile(self, session, username, semaphore):
        async with semaphore:
            if username in self.scraped_users:
                return self.scraped_users[username]

            url = (
                "https://www.instagram.com/api/v1/users/web_profile_info/"
                f"?username={username}"
            )
            try:
                async with session.get(url, headers=self.get_headers()) as resp:
                    if resp.status != 200:
                        print(f"⚠️ Skipped {username} (status {resp.status})")
                        return self.create_empty_profile(username)

                    data = await resp.json()
                    user = data.get("data", {}).get("user", {})
                    if not user:
                        return self.create_empty_profile(username)

                    bio = user.get("biography", "") or ""
                    bio_emails = self.extract_emails_from_bio(bio)
                    bio_phones = self.extract_phones_from_bio(bio)

                    full_name = (user.get("full_name") or "").strip()
                    parts = full_name.split(" ", 1)
                    first_name = parts[0] if parts else ""
                    last_name = parts[1] if len(parts) > 1 else ""

                    profile = {
                        "username": username,
                        "email": bio_emails[0] if bio_emails else "",
                        "phone": bio_phones[0] if bio_phones else "",
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

    # ========== COMMENTS SCRAPING ==========

    def get_post_shortcode(self, url: str | None):
        if not url:
            return None
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
                    edge_comments = (
                        data.get("data", {})
                        .get("shortcode_media", {})
                        .get("edge_media_to_parent_comment", {})
                    )

                    edges = edge_comments.get("edges", [])
                    for edge in edges:
                        node = edge.get("node", {})
                        owner = node.get("owner", {})
                        comments.append(
                            {
                                "uid": owner.get("id", ""),
                                "username": owner.get("username", ""),
                                "commentText": node.get("text", ""),
                                "timestamp": datetime.fromtimestamp(
                                    node.get("created_at", 0)
                                ).isoformat(),
                            }
                        )

                    page = edge_comments.get("page_info", {})
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


# ========== CSV SAVE HELPER (for CLI use) ==========

def save_to_csv(profiles, filename):
    if not profiles:
        print("❌ No profiles to save.")
        return

    fieldnames = list(profiles[0].keys())
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(profiles)

    # Remove first column if needed
    df = pd.read_csv(filename)
    df = df.iloc[:, 1:]
    df.to_csv(filename, index=False)

    print(f"\n✅ Profiles saved to {filename} (first column removed)")


# ========== MAIN FUNCTION USED BY FLASK (imported in app.py) ==========

async def run_scrape_for_post(post_url: str, max_comments: int | None = None):
    """
    High-level async function used by the Flask /scrape endpoint.

    - Rotates through INSTAGRAM_ACCOUNTS until one logs in.
    - Scrapes comments for the given post_url.
    - Scrapes profiles of unique commenters.
    - Returns a JSON-serializable dict.
    """
    try:
        success = False
        working_scraper: InstagramCommentScraperFixed | None = None
        login_errors = []

        print("\n================ INSTAGRAM LOGIN ROTATION ================")

        for acc in INSTAGRAM_ACCOUNTS:
            print(f"\n🎯 Trying account: {acc['username']} ...")

            scraper = InstagramCommentScraperFixed(acc["username"], acc["password"])

            if await scraper.login():
                print(f"✅ Logged in successfully using {acc['username']}")
                success = True
                working_scraper = scraper
                break
            else:
                login_errors.append({
                    "username": acc["username"],
                    "error": scraper.last_error or "login_failed",
                })
                print(f"❌ Login failed for {acc['username']}, trying next account...")

        if not success or not working_scraper:
            return {
                "ok": False,
                "message": "All Instagram accounts failed to login.",
                "login_errors": login_errors,
            }

        scraper = working_scraper

        shortcode = scraper.get_post_shortcode(post_url)
        if not shortcode:
            return {
                "ok": False,
                "message": "Invalid Instagram post URL.",
                "post_url": post_url,
            }

        comments = await scraper.scrape_post_comments(shortcode, max_comments)
        profiles = await scraper.scrape_commenters_profiles(comments, max_concurrent=5)

        return {
            "ok": True,
            "message": "Scraping completed.",
            "shortcode": shortcode,
            "post_url": post_url,
            "total_comments": len(comments),
            "total_profiles": len(profiles),
            "comments": comments,
            "profiles": profiles,
        }

    except Exception as e:
        print(f"❌ Unexpected error in run_scrape_for_post: {e!r}")
        return {
            "ok": False,
            "message": f"Unexpected error: {e}",
        }


# ========== OPTIONAL CLI ENTRYPOINT (python scraper.py) ==========

async def main():
    """
    Run scraper directly from command line:
      python scraper.py
    """
    post_url = input("Enter Instagram post URL: ").strip()
    max_comments_raw = input(
        "Enter number of comments to scrape (or press Enter for all): "
    ).strip()
    max_comments = int(max_comments_raw) if max_comments_raw.isdigit() else None

    result = await run_scrape_for_post(post_url, max_comments)

    if not result.get("ok"):
        print(f"\n❌ Scrape failed: {result.get('message')}")
        print("Login errors:", result.get("login_errors"))
        return

    comments = result["comments"]
    profiles = result["profiles"]
    shortcode = result["shortcode"]

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

    print(f"\n📁 JSON saved as {json_file}")
    print(f"📁 CSV saved as {csv_file}")
    print(f"✅ Total commenters scraped: {len(profiles)}")


if __name__ == "__main__":
    asyncio.run(main())
