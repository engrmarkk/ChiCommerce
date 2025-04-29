from dotenv import load_dotenv
from src import create_app

load_dotenv()  # Load environment variables first
app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)