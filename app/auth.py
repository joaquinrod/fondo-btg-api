import os
import boto3
import requests
from jose import jwt, jwk
from jose.utils import base64url_decode
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from decimal import Decimal
from botocore.exceptions import ClientError 

# Importar módulos para calcular el SECRET_HASH (si aún lo usas)
import hmac
import hashlib
import base64

# --- Configuración de Cognito ---
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")
COGNITO_REGION = os.getenv("AWS_REGION")
COGNITO_APP_CLIENT_SECRET = os.getenv("COGNITO_APP_CLIENT_SECRET") 

if not COGNITO_USER_POOL_ID or not COGNITO_APP_CLIENT_ID:
    raise ValueError(
        "COGNITO_USER_POOL_ID and COGNITO_APP_CLIENT_ID environment variables must be set."
    )

# URL para obtener las claves de firma de Cognito
COGNITO_JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"

# Cliente de boto3 para Cognito
cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)

# --- Continuación de Depuración ---
print(f"DEBUG: Type of cognito_client: {type(cognito_client)}")
print(f"DEBUG: Does cognito_client have 'admin_confirm_user' attribute? {'admin_confirm_user' in dir(cognito_client)}")
# --- Fin de Depuración ---

# Cache para las claves JWKS
_cached_jwks: Optional[Dict] = None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Modelos Pydantic para Autenticación ---

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    roles: List[str] = []

class UserAuthenticated(BaseModel):
    username: str
    email: EmailStr 
    roles: List[str]

# class AuthUserCreate(BaseModel):
#     username: str
#     password: str
#     email: EmailStr
#     monto_inicial: Decimal
    
# --- OAuth2 Scheme ---
# Definición de OAuth2PasswordBearer para extraer el token del encabezado Authorization.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Funciones de Autenticación ---

def _get_secret_hash(username: str, client_id: str, client_secret: str) -> str:
    """
    Calcula el SECRET_HASH requerido por Cognito para App Clients con un secreto.
    """
    message = username + client_id
    dig = hmac.new(
        client_secret.encode('utf-8'), 
        msg=message.encode('utf-8'), 
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode('utf-8')

async def _get_jwks_from_cognito() -> Dict:
    """
    Obtiene y cachea el JSON Web Key Set (JWKS) del punto final público de Cognito.
    """
    global _cached_jwks
    if _cached_jwks is None:
        try:
            response = requests.get(COGNITO_JWKS_URL, timeout=10)
            response.raise_for_status()
            _cached_jwks = response.json()
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to fetch JWKS from Cognito: {e}"
            )
    return _cached_jwks

async def register_user_cognito(username: str, password: str, email: str):
    """
    Registra un nuevo usuario en el User Pool de Amazon Cognito, usando email como identificador principal.
    """
    secret_hash = None
    if COGNITO_APP_CLIENT_SECRET:
        secret_hash = _get_secret_hash(username, COGNITO_APP_CLIENT_ID, COGNITO_APP_CLIENT_SECRET)

    try:
        sign_up_params = {
            'ClientId': COGNITO_APP_CLIENT_ID,
            'Username': username,
            'Password': password,
            'UserAttributes': [
                {'Name': 'email', 'Value': email},
                # {'Name': 'custom:cliente_id', 'Value': cliente_id} 
            ]
        }
        if secret_hash:
            sign_up_params['SecretHash'] = secret_hash

        response = cognito_client.sign_up(**sign_up_params)

        # Confirmar el usuario automáticamente para desarrollo
        # cognito_client.admin_confirm_user(
        #     UserPoolId=COGNITO_USER_POOL_ID,
        #     Username=username
        # )

        # Añadir usuario a un grupo por defecto
        cognito_client.admin_add_user_to_group(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=username,
            GroupName='client'
        )
        return {"message": "User registered and confirmed successfully"}
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        error_message = e.response.get("Error", {}).get("Message")
        if error_code == 'UsernameExistsException':
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El nombre de usuario ya existe."
            )
        elif error_code == 'InvalidPasswordException':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Contraseña no cumple con los requisitos."
            )
        elif error_code == 'NotAuthorizedException' and "SECRET_HASH" in error_message:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Error de Cognito: Cliente configurado con secreto pero SECRET_HASH faltante/incorrecto. {error_message}"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error al registrar usuario en Cognito: {error_message}"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during registration: {e}"
        )
async def authenticate_user_cognito(username: str, password: str) -> Dict[str, str]:
    """
    Autentica un usuario contra Amazon Cognito User Pool.
    Devuelve access_token e id_token si la autenticación es exitosa.
    """
    secret_hash = None
    if COGNITO_APP_CLIENT_SECRET:
        secret_hash = _get_secret_hash(username, COGNITO_APP_CLIENT_ID, COGNITO_APP_CLIENT_SECRET)

    try:
        auth_params = {
            'USERNAME': username,
            'PASSWORD': password,
        }
        if secret_hash:
            auth_params['SECRET_HASH'] = secret_hash

        response = cognito_client.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters=auth_params
        )
        
        if 'AuthenticationResult' not in response:
             raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed: No authentication result found."
            )
        
        return {
            "access_token": response['AuthenticationResult']['AccessToken'],
            "id_token": response['AuthenticationResult']['IdToken']
        }
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        error_message = e.response.get("Error", {}).get("Message")
        if error_code == 'NotAuthorizedException':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas."
            )
        elif error_code == 'UserNotConfirmedException':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Usuario no confirmado. Por favor, confirma tu cuenta.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        elif error_code == 'UserNotFoundException':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error al autenticar con Cognito: {error_message}"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during authentication: {e}"
        )
    
async def verify_cognito_token(token: str) -> TokenData:
    """
    Verifica un JWT emitido por Cognito (Access Token o ID Token) y extrae los detalles.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No token provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jwks = await _get_jwks_from_cognito()
    
    try:
        headers = jwt.get_unverified_headers(token)
        kid = headers['kid']

        key = None
        for jwk_key in jwks['keys']:
            if jwk_key['kid'] == kid:
                key = jwk.construct(jwk_key)
                break
        
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: Signing key not found.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        public_key = key.to_dict()

        claims = jwt.decode(
            token,
            public_key,
            audience=COGNITO_APP_CLIENT_ID,
            issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}",
            options={
                "require": ["exp", "iat", "auth_time"],
                "verify_signature": True,
                "verify_aud": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_at_hash": False
            }
        )
        
        username = claims.get('cognito:username') or claims.get('username') 
        email = claims.get('email') 
        
        cognito_groups = claims.get('cognito:groups', [])
        
        return TokenData(username=username, email=email, roles=cognito_groups) 

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during token validation: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
# --- FastAPI Dependencies ---

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserAuthenticated:
    """
    Dependencia de FastAPI para obtener la información del usuario autenticado
    a partir de un JWT. Valida el token y devuelve un objeto UserAuthenticated.
    """
    token_data = await verify_cognito_token(token)
    if not token_data.username or not token_data.email: 
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials: User or email information missing in token.", 
            headers={"WWW-Authenticate": "Bearer"},
        )
    return UserAuthenticated(
        username=token_data.username,
        email=token_data.email, 
        roles=token_data.roles
    )

def require_role(roles: List[str]):
    """
    Factoría de dependencia de FastAPI para aplicar roles específicos a un endpoint.
    Uso: Depends(require_role(["admin", "client"]))
    """
    def role_checker(current_user: UserAuthenticated = Depends(get_current_user)):
        if not any(role in current_user.roles for role in roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions. Access denied for this role."
            )
        return current_user
    return role_checker