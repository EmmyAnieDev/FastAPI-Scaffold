import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import settings

app = FastAPI(
    title="--- Application API",
    description="--- Application API for house renting",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {
        "message": "--- Application API is running",
        "version": "1.0.0",
        "environment": "Production" if not settings.DEBUG else "Development"
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.APP_PORT,
        reload=False
    )