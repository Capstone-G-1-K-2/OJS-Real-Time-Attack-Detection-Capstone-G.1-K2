import pymysql
import os
from dotenv import load_dotenv

load_dotenv()


def get_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
	port=int(os.getenv("DB_PORT", 3306)),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "ojs_detection"),
        cursorclass=pymysql.cursors.DictCursor,
    )
