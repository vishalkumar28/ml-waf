from sqlalchemy import Column, String, Float, Boolean, DateTime, Text, Integer, JSON
from sqlalchemy.dialects.postgresql import UUID, INET, ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
import uuid

Base = declarative_base()

class RequestLog(Base):
    __tablename__ = 'request_logs'
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp  = Column(DateTime(timezone=True), server_default=func.now())
    client_ip  = Column(String(45))
    method     = Column(String(10))
    path       = Column(Text)
    query_str  = Column(Text)
    body       = Column(Text)
    user_agent = Column(Text)

class Classification(Base):
    __tablename__ = 'classifications'
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id   = Column(UUID(as_uuid=True))
    timestamp    = Column(DateTime(timezone=True), server_default=func.now())
    decision     = Column(String(20))   # BLOCK / ALLOW / BYPASS_SUSPECT
    confidence   = Column(Float)
    attack_type  = Column(String(50))
    model_ver    = Column(String(20))
    explanation  = Column(Text)
    shap_data    = Column(JSON)
    is_false_pos = Column(Boolean, default=False)

class BypassAttempt(Base):
    __tablename__ = 'bypass_attempts'
    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id        = Column(UUID(as_uuid=True))
    timestamp         = Column(DateTime(timezone=True), server_default=func.now())
    bypass_flags      = Column(JSON)
    normalized_payload = Column(Text)
    added_to_retrain  = Column(Boolean, default=True)

class RetrainQueue(Base):
    __tablename__ = 'retrain_queue'
    id       = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    payload  = Column(Text)
    label    = Column(Integer)
    source   = Column(String(50))
    added_at = Column(DateTime(timezone=True), server_default=func.now())
    used_in  = Column(String(20), nullable=True)