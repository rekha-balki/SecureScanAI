from fastapi import FastAPI

app = FastAPI(
    title="SecureScan AI",
    version="0.1.0-alpha"
)

@app.get("/")
def root():
    return {
        "message": "Welcome to SecureScan AI"
    }

@app.get("/health")
def health():
    return {
        "status": "UP"
    }