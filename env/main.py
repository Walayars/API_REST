from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"mensaje": "¡Hola, mundo!"}

@app.get("/saludo/{Carlos}")
def saludar(Carlos: str):
    return {"mensaje": f"Hola, {Carlos}"}
