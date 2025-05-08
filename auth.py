from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Clave secreta y configuración del token
SECRET_KEY = "clave_super_secreta"  # Asegúrate de cambiarla por algo más seguro
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Tiempo de expiración del token

# Simulación de base de datos
fake_users_db = {
    "admin": {
        "username": "admin",
        "password": "admin123",  
        "role": "Administrador"
    },
    "orquestador": {
        "username": "orquestador",
        "password": "orquesta123",
        "role": "Orquestador"
    }
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/autenticar-usuario")

# Función para verificar el token y obtener el payload
def verificar_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        expiration = payload.get("exp")
        if expiration and datetime.utcfromtimestamp(expiration) < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Token expirado")
        return payload  # Devuelve el payload (por ejemplo, {'sub': 'admin', 'role': 'Administrador'})
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

# Función para requerir roles específicos
def requiere_rol(*roles):
    def validador(payload = Depends(verificar_token)):
        if payload["role"] not in roles:
            raise HTTPException(status_code=403, detail="Acceso denegado")
        return payload
    return validador
