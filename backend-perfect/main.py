
from fastapi import FastAPI

app = FastAPI(title="2FA Authentication API")

@app.get("/")
def root():
    return {"message": "Backend funcionando"}

@app.get("/health")
def health():
    return {"status": "ok"}
