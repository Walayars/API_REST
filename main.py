from fastapi import FastAPI, Depends, HTTPException
from auth import verificar_token, requiere_rol
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from auth import SECRET_KEY, ALGORITHM, fake_users_db

app = FastAPI()

@app.post("/autenticar-usuario")
def autenticar_usuario(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    token_data = {"sub": user["username"], "role": user["role"]}
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/orquestar")
def orquestar(servicio_destino: str, parametros_adicionales: str, user = Depends(requiere_rol("Orquestador", "Administrador"))):
    return {"mensaje": f"Servicio '{servicio_destino}' orquestado con éxito."}

@app.get("/informacion-servicio/{id}")
def obtener_info_servicio(id: int, user = Depends(verificar_token)):
    return {"id": id, "info": "Información del servicio"}

@app.post("/registrar-servicio")
def registrar_servicio(nombre: str, descripcion: str, endpoints: list[str], user = Depends(requiere_rol("Administrador"))):
    return {"mensaje": f"Servicio '{nombre}' registrado."}

@app.put("/actualizar-reglas-orquestacion")
def actualizar_reglas(reglas: str, user = Depends(requiere_rol("Orquestador"))):
    return {"mensaje": "Reglas actualizadas."}

@app.post("/autorizar-acceso")
def autorizar_acceso(recursos: list[str], rol_usuario: str, user = Depends(verificar_token)):
    if rol_usuario in ["Administrador", "Orquestador"]:
        return {"autorizado": True}
    return {"autorizado": False}
