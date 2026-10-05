from app import create_app

app = create_app()

if __name__ == "__main__":  # local dev only; production uses gunicorn
    app.run(host="127.0.0.1", port=int(__import__("os").environ.get("PORT", 8000)), debug=False)
