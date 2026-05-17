from fastapi import FastAPI
from app.core.database import init_db
from app.api.endpoints import router as auth_router

app = FastAPI(title="JWT Auth Service with Redis Blacklist", version="1.0.0")

@app.on_event("startup")
def on_startup():
    init_db()

app.include_router(auth_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main.py:app", host="0.0.0.0", port=8000, reload=True)