from fastapi import FastAPI

app = FastAPI()  # 创建 FastAPI 实例

@app.get("/")  # 定义 GET 请求接口
def read_root():
    return {"message": "Hello, FastAPI!"}

@app.get("/items/{item_id}")  # 动态路径
def read_item(item_id: int, q: str | None = None):
    return {"item_id": item_id, "q": q}