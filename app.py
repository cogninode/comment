from flask import Flask, render_template, request, jsonify
import asyncio

from scraper import run_scrape_for_post

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scrape", methods=["POST"])
def scrape():
    try:
        data = request.get_json(force=True) or {}
        post_url = data.get("post_url", "").strip()
        max_comments = data.get("max_comments")

        if not post_url:
            return jsonify({"ok": False, "message": "post_url is required."})

        if max_comments is not None:
            try:
                max_comments = int(max_comments)
                if max_comments <= 0:
                    max_comments = None
            except (TypeError, ValueError):
                max_comments = None

        result = asyncio.run(run_scrape_for_post(post_url, max_comments))

        return jsonify(result)

    except Exception as e:
        print("❌ Error in /scrape:", e)
        return jsonify({"ok": False, "message": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
