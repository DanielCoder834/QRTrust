from typing import Union
import os
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

load_dotenv()


class Item(BaseModel):
    url: str
    isGood: bool


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")

# DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
DATABASE_URL = os.getenv("DB_URL")

app = FastAPI()
engine = create_engine(DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@app.on_event("startup")
async def startup():
    # Initialize table on startup
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS urls (
                url VARCHAR(100) PRIMARY KEY,
                is_good BOOLEAN NOT NULL
            )
        """))


@app.post("/")
def addUrl(item: Item):
    # insert_query = text("""
    # INSERT INTO urls
    # VALUES (:url, :isGood)
    #     """)
    with engine.connect() as connection:
        # connection.execute(
        #     text("CREATE TABLE IF NOT EXISTS urls (url varchar(100), isGood BOOLEAN);")
        # )

        insert_query = text("""
            INSERT INTO urls 
            VALUES (:url, :isGood)
        """)

        obj = {"url": item.url, "isGood": item.isGood}
        connection.execute(insert_query, obj)
        connection.commit()
        # print(result)
    return "Success"


@app.get("/verify/{url}")
def verify(url: str):
    with engine.connect() as connection:
        result = connection.execute(
            text('SELECT * FROM urls WHERE url = :url'), {"url": url})
        row = result.fetchone()
        length = len(row)
        if length == 0:
            return {"isGood": False}
        if row:
            is_good = row[1]
            if is_good:
                return {"isGood": True}
            else:
                return {"isGood": False}
        print(len(result))
    return {"isGood": False}


# @app.get("/items/{item_id}")
# def read_item(item_id: int, q: Union[str, None] = None):
#     return {"item_id": item_id, "q": q}
