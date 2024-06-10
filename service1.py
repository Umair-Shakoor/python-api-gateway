from fastapi import FastAPI

app = FastAPI()

@app.get("/items")
async def read_items():
    return {"service": "service1", "items": ["item1", "item2", "item3"]}

@app.get("/status")
async def get_status():
    return {"service": "service1", "status": "ok"}
