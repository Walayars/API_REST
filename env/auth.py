from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

# Clave secreta y configuración del token
SECRET_KEY = "clave_super_secreta"
ALGORITHM = "HS256"

# Simulación de base de datos
fake_users_db = {
    "admin": {
        "username": "admin",
        "password": "admin123",  # En realidad deberías hashearla
        "role": "Administrador"
    },
    "orquestador": {
        "username": "orquestador",
        "password": "orquesta123",
        "role": "Orquestador"
    }
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/autenticar-usuario")

def verificar_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # {'sub': 'admin', 'role': 'Administrador'}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

def requiere_rol(*roles):
    def validador(payload = Depends(verificar_token)):
        if payload["role"] not in roles:
            raise HTTPException(status_code=403, detail="Acceso denegado")
        return payload
    return validador
