from pydantic import BaseModel, Field, EmailStr, PositiveFloat, PositiveInt
from typing import Optional, List
from datetime import datetime
from decimal import Decimal

# --- Modelos de Request (Entrada de datos) ---

class FondoBase(BaseModel):
    """
    Modelo base para la información de un fondo.
    """
    fondo_id: int = Field(..., gt=0, example=1, description="Identificador único del fondo")
    nombre: str = Field(..., min_length=5, max_length=150, example="FPV_BTG_PACTUAL_RECAUDADORA", description="Nombre del fondo")
    monto_minimo: Decimal = Field(..., example=75000.0, description="Monto mínimo de vinculación al fondo (COP)")
    categoria: str = Field(..., example="FPV", description="Categoría del fondo (ej. FPV, FIC)")

class UsuarioBase(BaseModel):
    """
    Modelo base para la información del usuario.
    El correo electrónico ahora actúa como el identificador principal del cliente.
    """
    # cliente_id: str = Field(..., example="CUST#12345", description="Identificador único del cliente") 
    correo: EmailStr = Field(..., example="juan.perez@example.com", description="Dirección de correo electrónico del cliente, usado como identificador principal")
    nombre: str = Field(..., min_length=3, max_length=100, example="Juan Pérez", description="Nombre completo del cliente")
    telefono: Optional[str] = Field(None, pattern=r"^\+?[1-9]\d{1,14}$", example="+573001234567", description="Número de teléfono del cliente (formato E.164)")
    preferencia_notificacion: Optional[str] = Field("none", pattern="^(email|sms|none)$", example="email", description="Preferencia de notificación (email, sms o none)")

class CrearCliente(UsuarioBase):
    """
    Modelo para la creación inicial de un cliente.
    """
    username: str = Field(..., min_length=3, max_length=50, description="Nombre de usuario")
    password: str = Field(..., min_length=8, max_length=128, description="La contraseña debe tener entre 8 y 128 caracteres")
    monto_inicial: Decimal = Field(500000.0, ge=500000.0, example=500000.0, description="Saldo inicial del cliente (COP). Mínimo 500.000 COP.")

class CrearSubscripcionFondo(BaseModel):
    """
    Modelo para la solicitud de suscripción a un fondo.
    """
    correo_cliente: EmailStr = Field(..., example="cliente@example.com", description="Correo electrónico del cliente que suscribe") 
    fondo_id: int = Field(..., gt=0, example=1, description="Identificador único del fondo al que se desea suscribir")
    monto_vinculacion: Decimal = Field(..., ge=50000.0, example=50000.0, description="Saldo inicial del cliente (COP) para abrir el fondo.")

class CancelarSubscripcionFondo(BaseModel):
    """
    Modelo para la solicitud de cancelación de una suscripción a un fondo.
    """
    correo_cliente: EmailStr = Field(..., example="cliente@example.com", description="Correo electrónico del cliente que cancela") 
    fondo_id: int = Field(..., gt=0, example=1, description="Identificador único del fondo que se desea cancelar")

# --- Modelos de Respuesta (Salida de datos) ---

class RespuestaCliente(UsuarioBase):
    """
    Modelo de respuesta para la información de un cliente.
    """
    saldo: Decimal = Field(..., ge=0.0, example=450000.0, description="Saldo actual disponible del cliente (COP)")
    creado: datetime = Field(..., description="Fecha y hora de creación del registro del cliente")
    actualizado: datetime = Field(..., description="Fecha y hora de la última actualización del registro del cliente")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class RespuestaFondo(FondoBase):
    """
    Modelo de respuesta para la información de un fondo.
    """
    creado: datetime = Field(..., description="Fecha y hora de creación del registro del fondo")
    actualizado: datetime = Field(..., description="Fecha y hora de la última actualización del registro del fondo")

class RespuestaTransaccion(BaseModel):
    """
    Modelo de respuesta para una transacción.
    """
    transaccion_id: str = Field(..., example="TXN#20250719104500#ABCDEF", description="Identificador único de la transacción")
    correo_cliente: EmailStr = Field(..., example="cliente@example.com", description="Correo electrónico del cliente asociado a la transacción") 
    fondo_id: int = Field(..., example=1, description="Identificador del fondo involucrado en la transacción")
    nombre_fondo: str = Field(..., example="FPV_BTG_PACTUAL_RECAUDADORA", description="Nombre del fondo al momento de la transacción")
    tipo_transaccion: str = Field(..., pattern="^(Apertura|Cancelacion)$", example="Apertura", description="Tipo de transacción (Apertura o Cancelacion)")
    monto: Decimal = Field(..., description="Monto de la transacción (monto vinculado o retornado)")
    fecha_transaccion: datetime = Field(..., description="Fecha y hora de la transacción")
    estado: str = Field(..., example="Completada", description="Estado de la transacción (ej. Completada, Fallida)")
    detalle: Optional[dict] = Field(None, description="Detalles adicionales o mensaje de error de la transacción")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class RespuestaSubscripcion(BaseModel):
    """
    Modelo de respuesta para una suscripción activa o cancelada.
    """
    correo_cliente: EmailStr = Field(..., example="cliente@example.com", description="Correo electrónico del cliente") 
    fondo_id: int = Field(..., example=1, description="Identificador del fondo")
    monto: Decimal = Field(..., example=75000.0, description="Monto vinculado en esta suscripción")
    estado: str = Field(..., pattern="^(Activo|Cancelado)$", example="Activo", description="Estado de la suscripción (Activo o Cancelado)")
    fecha_apertura: datetime = Field(..., description="Fecha y hora de inicio de la suscripción")
    fecha_cancelacion: Optional[datetime] = Field(None, description="Fecha y hora de cancelación de la suscripción (si aplica)")
    ultima_transaccion_id: str = Field(..., example="TXN#20250719104500#ABCDEF", description="Última transacción asociada a esta suscripción")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class RespuestaHistorialTransacciones(BaseModel):
    """
    Modelo de respuesta para el historial de transacciones de un cliente.
    """
    correo_cliente: EmailStr = Field(..., example="cliente@example.com", description="Correo electrónico del cliente") 
    transacciones: List[RespuestaTransaccion] = Field(..., description="Lista de transacciones del cliente")
