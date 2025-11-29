from flask import Flask, render_template, request, jsonify
import asyncio

from scraper import run_scrape_for_post

app = Flask(__name__)



@app.route("/")
def index():
    # Renders templates/index.html
    return render_template("index.html")


@app.route("/scrape", methods=["POST"])
def scrape():
    try:
        data = request.get_json(force=True) or {}
        post_url = data.get("post_url", "").strip()
        max_comments = data.get("max_comments")

        if not post_url:
            return jsonify({"ok": False, "message": "post_url is required."}), 400

        if max_comments is not None:
            try:
                max_comments = int(max_comments)
                if max_comments <= 0:
                    max_comments = None
            except (TypeError, ValueError):
                max_comments = None

        # Run the async scraper
        result = asyncio.run(run_scrape_for_post(post_url, max_comments))

        status_code = 200 if result.get("ok") else 500
        return jsonify(result), status_code

    except Exception as e:
        print("❌ Error in /scrape:", e)
        return jsonify({"ok": False, "message": str(e)}), 500


if __name__ == "__main__":
    # Host on 0.0.0.0 if you want to access from network, here localhost:8000
    app.run(host="0.0.0.0", port=8000, debug=True)
