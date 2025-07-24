import os
import uuid
import asyncio
from datetime import datetime
from decimal import Decimal
import pytz
import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException, status, Depends, Path
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from typing import List, Optional

# Importar las funciones y modelos de autenticación
from .auth import (
    oauth2_scheme,
    authenticate_user_cognito,
    register_user_cognito,
    get_current_user,
    require_role,
    Token,
    UserAuthenticated,
)

# Importar los modelos Pydantic
from .schemas import (
    FondoBase, RespuestaFondo,
    UsuarioBase, CrearCliente, RespuestaCliente,
    CrearSubscripcionFondo, CancelarSubscripcionFondo,
    RespuestaSubscripcion, RespuestaTransaccion, RespuestaHistorialTransacciones
)


# --- Configuración de DynamoDB ---
AWS_REGION = os.getenv("AWS_REGION")
DYNAMODB_ENDPOINT_URL = os.getenv("DYNAMODB_ENDPOINT_URL")

if DYNAMODB_ENDPOINT_URL:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION, endpoint_url=DYNAMODB_ENDPOINT_URL)
    dynamodb_client = boto3.client('dynamodb', region_name=AWS_REGION, endpoint_url=DYNAMODB_ENDPOINT_URL)
else:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    dynamodb_client = boto3.client('dynamodb', region_name=AWS_REGION)

# Referencias a las tablas
customers_table  = dynamodb.Table("Clientes")
funds_table  = dynamodb.Table("Fondos")
transactions_table = dynamodb.Table("Transacciones")
subscriptions_table  = dynamodb.Table("Subscripciones")


# Define la zona horaria de Colombia
colombia_tz = pytz.timezone("America/Bogota")

app = FastAPI(
    title="Fondo BTG Pactual API",
    description="API para la gestión de fondos de inversión de clientes de BTG Pactual.",
    version="1.0.0"
)

# --- Funciones auxiliares  ---
def generar_transaccion_id(prefix: str = "TXN#") -> str:
    """Genera un ID de transacción único con timestamp."""
    timestamp_str = datetime.now(colombia_tz).strftime("%Y%m%d%H%M%S")
    return f"{prefix}{timestamp_str}#{uuid.uuid4().hex[:6].upper()}"

# --- Datos iniciales ---
@app.on_event("startup")
async def startup_event():
    print("Aplicación iniciando...")
    await asyncio.gather(
        Inicializar_clientes(),
        inicializar_fondos() 
    )

async def Inicializar_clientes():
    """
    Siembra datos iniciales de clientes en la tabla Clientes de DynamoDB.
    Ahora usa el correo electrónico como clave principal.
    """
    try:
        response = customers_table.scan(Limit=1)
        if response.get("Items"):
            print("Tabla 'Clientes' ya contiene datos, no se siembran nuevos clientes.")
            return

        print("Sembrando clientes iniciales en DynamoDB (usando email como PK)...")
        now = datetime.now(colombia_tz)
                
        customers_data = [
            {"nombre": "Alice Johnson", "correo": "alice.johnson@example.com", "monto_inicial": 1000000.0, "telefono": "+573001111111", "preferencia_notificacion": "email"},
            {"nombre": "Bob Williams", "correo": "bob.williams@example.com", "monto_inicial": 750000.0, "telefono": "+573002222222", "preferencia_notificacion": "sms"},
            {"nombre": "Charlie Brown", "correo": "charlie.brown@example.com", "monto_inicial": 2000000.0, "telefono": "+573003333333", "preferencia_notificacion": "none"},
        ]

        with customers_table.batch_writer() as batch:
            for customer_info in customers_data:
                item = {
                    "PK": f"CUSTOMER#{customer_info['correo']}", 
                    "SK": f"PROFILE#{customer_info['correo']}", 
                    "nombre": customer_info["nombre"],
                    "correo": customer_info["correo"],
                    "telefono": customer_info["telefono"],
                    "preferencia_notificacion": customer_info["preferencia_notificacion"],
                    "saldo": Decimal(str(customer_info["monto_inicial"])),
                    "creado": now.isoformat(),
                    "actualizado": now.isoformat()
                }
                batch.put_item(Item=item)
        print(f"{len(customers_data)} clientes sembrados correctamente en DynamoDB.")
    except ClientError as e:
        print(f"Error al sembrar clientes en DynamoDB: {e.response['Error']['Message']}")
        raise

async def inicializar_fondos():
    """
    Siembra los datos iniciales de los fondos en la tabla Fondos de DynamoDB
    solo si la tabla está vacía, usando los datos de la imagen.
    """
    try:
        response = funds_table.scan(Limit=1)
        if response.get("Items"):
            print("Tabla 'Fondos' ya contiene datos, no se siembran nuevos fondos.")
            return

        print("Sembrando fondos iniciales en DynamoDB...")
        now = datetime.now(colombia_tz)
        funds_data = [
            {"fondo_id": 1, "nombre": "FPV_BTG_PACTUAL_RECAUDADORA", "monto_minimo": 75000.0, "categoria": "FPV"},
            {"fondo_id": 2, "nombre": "FPV_BTG_PACTUAL_ECOPETROL", "monto_minimo": 125000.0, "categoria": "FPV"},
            {"fondo_id": 3, "nombre": "DEUDAPRIVADA", "monto_minimo": 50000.0, "categoria": "FIC"},
            {"fondo_id": 4, "nombre": "FDO-ACCIONES", "monto_minimo": 250000.0, "categoria": "FIC"},
            {"fondo_id": 5, "nombre": "FPV_BTG_PACTUAL_DINAMICA", "monto_minimo": 100000.0, "categoria": "FPV"},
        ]

        with funds_table.batch_writer() as batch:
            for fund_data in funds_data:
                item = {
                    "PK": f"FUND#{fund_data['fondo_id']}", 
                    "SK": f"INFO#{fund_data['fondo_id']}", 
                    "fondo_id": Decimal(str(fund_data["fondo_id"])),
                    "nombre": fund_data["nombre"],
                    "monto_minimo": Decimal(str(fund_data["monto_minimo"])),
                    "categoria": fund_data["categoria"],
                    "creado": now.isoformat(),
                    "actualizado": now.isoformat()
                }
                batch.put_item(Item=item)
        print(f"{len(funds_data)} fondos sembrados correctamente en DynamoDB.")
    except ClientError as e:
        print(f"Error al sembrar fondos en DynamoDB: {e.response['Error']['Message']}")
        raise

@app.get("/")
async def read_root():
    """
    Endpoint de prueba para verificar que la API está funcionando.
    """
    current_time_colombia = datetime.now(colombia_tz).strftime("%Y-%m-%d %H:%M:%S %Z%z")
    return {
        "message": "Bienvenido a la API de Fondos de BTG Pactual",
        "timestamp_colombia": current_time_colombia,
        "api_status": "Activa y funcionando"
    }

# --- Endpoints de Autenticación y Usuarios ---

@app.post("/token", response_model=Token, summary="Obtener token de autenticación")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Endpoint para que un usuario se autentique y obtenga un token JWT.
    """
    auth_result = await authenticate_user_cognito(form_data.username, form_data.password)
    
    access_token = auth_result["id_token"] #auth_result["access_token"]
    
    return Token(access_token=access_token, token_type="bearer")

@app.post("/customers", summary="Registrar nuevo usuario y crear cliente")
async def create_customer(user_data: CrearCliente):
    """
    Registra un nuevo usuario en Cognito y crea un registro de cliente asociado en DynamoDB.
    """
    now = datetime.now(colombia_tz)
    
    # Verificar si el cliente ya existe por correo electrónico
    try:
        response = customers_table.get_item(
            Key={
                "PK": f"CUSTOMER#{user_data.correo}", 
                "SK": f"PROFILE#{user_data.correo}"   
            }
        )
        if response.get("Item"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Ya existe un cliente registrado con este correo electrónico."
            )
    except ClientError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al verificar existencia del cliente: {e.response['Error']['Message']}"
        )

    # Registrar usuario en Cognito 
    try:
        await register_user_cognito(user_data.username, user_data.password, user_data.correo)
    except HTTPException as e:
        raise e # Propagar errores específicos de Cognito
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado durante el registro en Cognito: {e}"
        )

    # Crear registro de cliente en DynamoDB
    try:
        customer_item = {
            "PK": f"CUSTOMER#{user_data.correo}",
            "SK": f"PROFILE#{user_data.correo}",  
            "nombre": user_data.username, 
            "correo": user_data.correo,
            "telefono": user_data.telefono, 
            "preferencia_notificacion": user_data.preferencia_notificacion,
            "saldo": Decimal(user_data.monto_inicial), 
            "creado": now.isoformat(),
            "actualizado": now.isoformat()
        }
        customers_table.put_item(Item=customer_item)
                
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "Usuario registrado y cliente creado exitosamente."}
        )
    except ClientError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al crear el registro del cliente en DynamoDB: {e.response['Error']['Message']}"
        )

@app.get("/customers/{correo_cliente}", response_model=RespuestaCliente, summary="Obtener información de un cliente por email")
async def get_customer_by_email(
    correo_cliente: str = Path(..., description="Correo electrónico del cliente a buscar"), 
    current_user: UserAuthenticated = Depends(get_current_user) # Solo usuarios autenticados pueden ver su info o admin
):
    """
    Obtiene los detalles de un cliente por su correo electrónico.
    Solo el propio cliente o un administrador pueden acceder a esta información.
    """
    # Verificación de autorización: solo el cliente dueño del email o un admin
    if current_user.email != correo_cliente and "admin" not in current_user.roles: 
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para ver la información de este cliente."
        )

    try:
        response = customers_table.get_item(
            Key={
                "PK": f"CUSTOMER#{correo_cliente}", 
                "SK": f"PROFILE#{correo_cliente}"  
            }
        )
        item = response.get("Item")
        if not item:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cliente no encontrado."
            )
       
        return RespuestaCliente(**item)
    except ClientError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener cliente de DynamoDB: {e.response['Error']['Message']}"
        )

# --- Endpoints (Suscripciones) ---

@app.post("/subscriptions", response_model=RespuestaSubscripcion, summary="Crear una nueva suscripción (admin o cliente propio)")
async def create_subscription(
    sub_data: CrearSubscripcionFondo,
    current_user: UserAuthenticated = Depends(get_current_user)
):
    """
    Permite a un cliente suscribirse a un fondo con un monto específico.
    Requiere autenticación. Un cliente solo puede suscribir en su propio nombre.
    """
    now = datetime.now(colombia_tz)
    
    # Autorización: Admin puede suscribir para cualquiera, Cliente solo para sí mismo
    if "admin" not in current_user.roles and current_user.email != sub_data.correo_cliente:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No autorizado para crear suscripciones para otros clientes."
        )

    # 1. Obtener información del cliente
    try:
        
        client_response = customers_table.get_item(
            Key={
                "PK": f"CUSTOMER#{sub_data.correo_cliente}",
                "SK": f"PROFILE#{sub_data.correo_cliente}"
            }
        )
        cliente = client_response.get("Item")
        if not cliente:
            raise HTTPException(status_code=404, detail=f"Cliente con correo '{sub_data.correo_cliente}' no encontrado.")
        
        saldo_actual = Decimal(str(cliente["saldo"]))
    except ClientError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener cliente para suscripción: {e.response['Error']['Message']}"
        )

    # 2. Obtener información del fondo
    try:
        
        fund_response = funds_table.get_item(
            Key={
                "PK": f"FUND#{sub_data.fondo_id}",
                "SK": f"INFO#{sub_data.fondo_id}"
            }
        )
        fondo = fund_response.get("Item")
        if not fondo:
            raise HTTPException(status_code=404, detail=f"Fondo con ID '{sub_data.fondo_id}' no encontrado.")
        
        monto_minimo_fondo = Decimal(str(fondo["monto_minimo"]))
    except ClientError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener fondo para suscripción: {e.response['Error']['Message']}"
        )
    
    # 3. Validar monto mínimo del fondo y saldo disponible del cliente
    if sub_data.monto_vinculacion < monto_minimo_fondo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"El monto de vinculación ({sub_data.monto_vinculacion}) es menor al monto mínimo requerido del fondo ({monto_minimo_fondo})."
        )
        
    if saldo_actual < sub_data.monto_vinculacion:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Saldo insuficiente para la suscripción. Saldo actual: {saldo_actual}"
        )

    # 4. --- Verificar si ya existe una suscripción Activa ---
    try:
        existing_subscription_response = subscriptions_table.get_item(
            Key={
                "PK": f"CUSTOMER#{sub_data.correo_cliente}",
                "SK": f"FUND#{sub_data.fondo_id}"
            }
        )
        existing_subscription = existing_subscription_response.get("Item")

        if existing_subscription and existing_subscription.get('estado') == 'Activo':
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Ya existe una suscripción activa para este cliente y fondo."
            )
    except ClientError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al verificar suscripciones existentes: {e.response['Error']['Message']}"
        )

    # 5. Realizar la transacción de apertura y actualizar saldo
    transaccion_id = generar_transaccion_id()
    monto_vinculado = sub_data.monto_vinculacion # Usar el monto enviado por el usuario
    print("monto vinculado: {monto_vinculado}")
    try:
        dynamodb_client.transact_write_items(
            TransactItems=[
                { # 1. Actualizar el saldo del cliente (restar monto_vinculacion)
                    'Update': {
                        'TableName': customers_table.name,
                        'Key': {
                            'PK': {'S': f"CUSTOMER#{sub_data.correo_cliente}"}, 
                            'SK': {'S': f"PROFILE#{sub_data.correo_cliente}"}  
                        },
                        'UpdateExpression': 'SET saldo = saldo - :monto, actualizado = :updated_at',
                        'ExpressionAttributeValues': {
                            ':monto': {'N': str(monto_vinculado)},
                            ':updated_at': {'S': now.isoformat()}
                        },
                        'ConditionExpression': 'saldo >= :monto' # Asegurar que el saldo sea suficiente
                    }
                },
                { # 2. Crear el registro de la suscripción
                    'Put': {
                        'TableName': subscriptions_table.name,
                        'Item': {
                            'PK': {'S': f"CUSTOMER#{sub_data.correo_cliente}"}, 
                            'SK': {'S': f"FUND#{sub_data.fondo_id}"},           
                            'correo_cliente': {'S': sub_data.correo_cliente},   
                            'fondo_id': {'N': str(sub_data.fondo_id)},
                            'monto': {'N': str(monto_vinculado)},
                            'estado': {'S': 'Activo'},
                            'fecha_apertura': {'S': now.isoformat()},
                            'ultima_transaccion_id': {'S': transaccion_id}
                        },
                        # Condición para asegurar que no se sobrescribe una suscripción existente con la misma PK/SK
                        'ConditionExpression': 'attribute_not_exists(PK)'
                    }
                },
                { # 3. Registrar la transacción
                    'Put': {
                        'TableName': transactions_table.name,
                        'Item': {
                            'PK': {'S': f"CUSTOMER#{sub_data.correo_cliente}"}, 
                            'SK': {'S': f"{transaccion_id}"},              
                            'transaccion_id': {'S': transaccion_id},
                            'correo_cliente': {'S': sub_data.correo_cliente},   
                            'fondo_id': {'N': str(sub_data.fondo_id)},
                            'nombre_fondo': {'S': fondo["nombre"]},
                            'tipo_transaccion': {'S': 'Apertura'},
                            'monto': {'N': str(monto_vinculado)},
                            'fecha_transaccion': {'S': now.isoformat()},
                            'estado': {'S': 'Completada'}
                        }
                    }
                }
            ]
        )
        
        # 6. Construir y retornar la respuesta de la suscripción
        return RespuestaSubscripcion(
            correo_cliente=sub_data.correo_cliente,
            fondo_id=sub_data.fondo_id,
            monto=monto_vinculado,
            estado="Activo",
            fecha_apertura=now,
            ultima_transaccion_id=transaccion_id
        )

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'TransactionCanceledException':
            # Analizar las razones de cancelación para dar un mensaje más específico
            cancellation_reasons = e.response.get('CancellationReasons', [])
            for reason in cancellation_reasons:
                if reason.get('Code') == 'ConditionalCheckFailedException':
                    # Determinar qué condición falló
                    if 'saldo' in reason.get('Message', ''):
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Fondos insuficientes para la suscripción.")
                    if 'attribute_not_exists(PK)' in reason.get('Message', ''):
                        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Ya existe una suscripción activa para este cliente y fondo.")
            # Si no se pudo determinar la razón específica, lanzar un error genérico
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Transacción de suscripción fallida: {e.response['Error']['Message']}")
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al crear suscripción en DynamoDB: {e.response['Error']['Message']}"
        )
    except HTTPException as e:
        raise e # Re-lanzar HTTPExceptions ya definidas
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ha ocurrido un error inesperado al crear la suscripción: {e}")

@app.delete("/subscriptions/{correo_cliente}/{fondo_id}", response_model=RespuestaSubscripcion, summary="Cancelar completamente una suscripción (admin o cliente propio)")
async def delete_subscription(
    correo_cliente: str, 
    fondo_id: int,       
    current_user: UserAuthenticated = Depends(get_current_user)
):
    """
    Cancela completamente una suscripción activa de un cliente a un fondo.
    Este endpoint representa una "eliminación" lógica de la suscripción activa.
    Requiere que el cliente esté autenticado y cancele su propia suscripción.
    """
    now = datetime.now(colombia_tz)

    # Autorización: Admin puede cancelar para cualquiera, Cliente solo para sí mismo
    if "admin" not in current_user.roles and current_user.email != correo_cliente:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para cancelar la suscripción de otro cliente."
        )

    # 1. Obtener la suscripción activa
    try:
        subscription_response = subscriptions_table.get_item(
            Key={
                "PK": f"CUSTOMER#{correo_cliente}",
                "SK": f"FUND#{fondo_id}"
            }
        )
        subscription = subscription_response.get("Item")
        
        if not subscription or subscription.get("estado") == "Cancelado":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Suscripción activa no encontrada para este cliente y fondo."
            )
        
        monto_suscrito = Decimal(str(subscription["monto"]))
        # Se retira el monto completo
        monto_a_retirar = monto_suscrito 

        if monto_a_retirar <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El monto suscrito es cero o negativo, no se puede realizar la cancelación."
            )    
         
        fondo_info = funds_table.get_item(
            Key={
                "PK": f"FUND#{fondo_id}",
                "SK": f"INFO#{fondo_id}"
            }
        ).get("Item")
        if not fondo_info:
            raise HTTPException(status_code=404, detail=f"Fondo con ID '{fondo_id}' no encontrado.")
        nombre_fondo = fondo_info['nombre']
        

    except ClientError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener suscripción para cancelación: {e.response['Error']['Message']}"
        )
    except HTTPException as e:
        raise e 
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ha ocurrido un error inesperado al obtener la suscripción: {e}")

    # 2. Realizar la transacción atómica de cancelación (completa)
    transaccion_id = generar_transaccion_id()
    nuevo_monto_suscripcion = Decimal('0') 
    nuevo_estado_suscripcion = "Cancelado"
    fecha_cancelacion_iso = now.isoformat() 
    
    try:
        dynamodb_client.transact_write_items(
            TransactItems=[
                { # 1. Incrementar saldo del cliente
                    'Update': {
                        'TableName': customers_table.name,
                        'Key': {
                            'PK': {'S': f"CUSTOMER#{correo_cliente}"},
                            'SK': {'S': f"PROFILE#{correo_cliente}"}
                        },
                        'UpdateExpression': 'SET saldo = saldo + :monto_retornado, actualizado = :updated_at',
                        'ExpressionAttributeValues': {
                            ':monto_retornado': {'N': str(monto_a_retirar)},
                            ':updated_at': {'S': now.isoformat()}
                        }
                    }
                },
                { # 2. Actualizar el estado de la suscripción a 'Cancelado' y monto a cero
                    'Update': {
                        'TableName': subscriptions_table.name,
                        'Key': {
                            'PK': {'S': f"CUSTOMER#{correo_cliente}"},
                            'SK': {'S': f"FUND#{fondo_id}"}
                        },
                        'UpdateExpression': 'SET #s_monto = :nuevo_monto, #s_estado = :nuevo_estado, ultima_transaccion_id = :txn_id, fecha_cancelacion = :fecha_cancelacion',
                        'ExpressionAttributeNames': {
                            '#s_monto': 'monto',
                            '#s_estado': 'estado',
                        },
                        'ExpressionAttributeValues': {
                            ':nuevo_monto': {'N': str(nuevo_monto_suscripcion)},
                            ':nuevo_estado': {'S': nuevo_estado_suscripcion},
                            ':txn_id': {'S': transaccion_id},
                            ':fecha_cancelacion': {'S': fecha_cancelacion_iso}
                        }
                    }
                },
                { # 3. Registrar la transacción de cancelación
                    'Put': {
                        'TableName': transactions_table.name,
                        'Item': {
                            'PK': {'S': f"CUSTOMER#{correo_cliente}"},
                            'SK': {'S': f"{transaccion_id}"},
                            'transaccion_id': {'S': transaccion_id},
                            'correo_cliente': {'S': correo_cliente},
                            'fondo_id': {'N': str(fondo_id)},
                            'nombre_fondo': {'S': nombre_fondo},
                            'tipo_transaccion': {'S': 'Cancelacion'},
                            'monto': {'N': str(monto_a_retirar)},
                            'fecha_transaccion': {'S': now.isoformat()},
                            'estado': {'S': 'Completada'}
                        }
                    }
                }
            ]
        )

        # 3. Construir y retornar la respuesta de la suscripción actualizada
        return RespuestaSubscripcion(
            correo_cliente=correo_cliente,
            fondo_id=fondo_id,
            monto=nuevo_monto_suscripcion, 
            estado=nuevo_estado_suscripcion,
            fecha_apertura=datetime.fromisoformat(subscription["fecha_apertura"]),
            fecha_cancelacion=now,
            ultima_transaccion_id=transaccion_id
        )

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'TransactionCanceledException':
            cancellation_reasons = e.response.get('CancellationReasons', [])
            for reason in cancellation_reasons:
                if reason.get('Code') == 'ConditionalCheckFailedException':
                    if 'activo_previo' in reason.get('Message', ''): 
                         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La suscripción no estaba activa o ya fue cancelada.")
            raise HTTPException(status_code=500, detail=f"Error en la transacción de DynamoDB: {e.response['Error']['Message']}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error durante la transacción: {e.response['Error']['Message']}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ha ocurrido un error inesperado al cancelar la suscripción: {e}")

@app.get("/transactions/{correo_cliente}", response_model=RespuestaHistorialTransacciones, summary="Obtener el historial de transacciones de un cliente")
async def get_transaction_history(
    correo_cliente: str, 
    current_user: UserAuthenticated = Depends(get_current_user) 
):
    """
    Obtiene el historial completo de transacciones (aperturas y cancelaciones)
    para un cliente específico.
    Requiere autenticación. Un cliente solo puede ver su propio historial,
    mientras que un administrador puede ver el historial de cualquier cliente.
    """
    # Autorización: Admin puede ver el historial de cualquiera, Cliente solo el suyo
    if "admin" not in current_user.roles and current_user.email != correo_cliente:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para ver el historial de transacciones de este cliente."
        )

    try:
        # para obtener todas las transacciones de este cliente.
        response = transactions_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('PK').eq(f"CUSTOMER#{correo_cliente}") & \
                                 boto3.dynamodb.conditions.Key('SK').begins_with("TXN#")
        )
        
        items = response.get('Items', [])
        
        transacciones_list = []
        for item in items:
            transacciones_list.append(
                RespuestaTransaccion(
                    transaccion_id=item.get('transaccion_id'),
                    correo_cliente=item.get('correo_cliente'),
                    fondo_id=int(item.get('fondo_id')) if item.get('fondo_id') else None,
                    nombre_fondo=item.get('nombre_fondo'),
                    tipo_transaccion=item.get('tipo_transaccion'),
                    monto=Decimal(str(item.get('monto'))) if item.get('monto') else Decimal('0'),
                    fecha_transaccion=datetime.fromisoformat(item.get('fecha_transaccion')) if item.get('fecha_transaccion') else None,
                    estado=item.get('estado'),
                    detalle=item.get('detalle', None)
                )
            )
        
        # Devolver la lista de transacciones en el modelo de respuesta de historial
        return RespuestaHistorialTransacciones(
            correo_cliente=correo_cliente, 
            transacciones=transacciones_list
        )

    except ClientError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener historial de transacciones de DynamoDB: {e.response['Error']['Message']}"
        )
    except HTTPException as e:
        raise e # Re-lanzar HTTPExceptions ya definidas
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ha ocurrido un error inesperado al obtener el historial de transacciones: {e}")
