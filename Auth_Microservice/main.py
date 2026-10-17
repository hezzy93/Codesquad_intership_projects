from fastapi import FastAPI

from database import engine, Base
from models import User, RefreshToken

from routers.auth import router as auth_router

app = FastAPI(
    title="Authentication Microservice",
    version="1.0.0"
)
Base.metadata.create_all(bind=engine)


@app.get("/")
def root():
    return {
        "message": "Authentication Microservice is running"
    }


@app.get("/test-db")
def test_database():
    try:
        with engine.connect():
            return {
                "message": "Database connection successful"
            }
    except Exception as error:
        return {
            "message": "Database connection failed",
            "error": str(error)
        }


app.include_router(auth_router)