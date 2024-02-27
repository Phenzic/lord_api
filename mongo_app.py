import os
from dotenv import load_dotenv

load_dotenv()

mongo_username = os.environ.get("MONGODB_USERNAME")
mongo_password = os.environ.get("MONGODB_PASSWORD")

user_uri = f"mongodb+srv://{mongo_username}:{mongo_password}@cluster1.ze89abk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster1"

vault_uri = f"mongodb+srv://{mongo_username}:{mongo_password}@cluster2.hxp8umw.mongodb.net/?retryWrites=true&w=majority&appName=Cluster2"