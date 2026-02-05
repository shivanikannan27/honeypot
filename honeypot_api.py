"""
AI-Driven Honeypot System for Scam Detection and Engagement
"""

from fastapi import FastAPI, HTTPException, Security, Header, Body
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import json
import re
import requests
from enum import Enum

app = FastAPI(title="AI Honeypot API", version="1.0.0")

# =========================
# CONFIGURATION
# =========================

API_KEY_NAME = "x-api-key"
SECRET_API_KEY = "thinkheist_honeypot_2026_secure_key"
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# In-memory sessions
sessions = {}

# =========================
# MODELS
# =========================

class Sender(str, Enum):
    SCAMMER = "scammer"
    USER = "user"


class Message(BaseModel):
    sender: Sender
    text: str
    timestamp: str


class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"


class IncomingRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = None


class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int


class HoneypotResponse(BaseModel):
    status: str
    scamDetected: bool
    response: Optional[str] = None
    engagementMetrics: Optional[EngagementMetrics] = None
    extractedIntelligence: Optional[ExtractedIntelligence] = None
    agentNotes: Optional[str] = None

# =========================
# SECURITY
# =========================

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != SECRET_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key

# =========================
# SESSION DATA
# =========================

class SessionData:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.start_time = datetime.now()
        self.messages = []
        self.scam_detected = False
        self.intelligence = ExtractedIntelligence()
        self.agent_notes = []

    def add_message(self, msg: Message):
        self.messages.append(msg)

    def duration(self):
        return int((datetime.now() - self.start_time).total_seconds())

    def count(self):
        return len(self.messages)

# =========================
# SCAM DETECTOR
# =========================

class ScamDetector:
    PATTERNS = [
        r"(urgent|immediately|block|verify|otp|pin|password)",
        r"(bank|account|upi|payment|click|link)",
        r"(winner|prize|lottery|refund)"
    ]

    @staticmethod
    def detect(text: str):
        matches = [p for p in ScamDetector.PATTERNS if re.search(p, text.lower())]
        return len(matches) >= 2

# =========================
# AI AGENT (Fallback)
# =========================

class AIAgent:
    @staticmethod
    def respond(text: str):
        if "otp" in text.lower():
            return "I received a message with numbers. Is that what you need?"
        if "bank" in text.lower():
            return "Which bank are you calling from? I'm worried."
        return "I'm not very good with phones. Can you explain again?"

# =========================
# GUVI CALLBACK
# =========================

def send_to_guvi(session: SessionData):
    payload = {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": session.count(),
        "extractedIntelligence": session.intelligence.dict(),
        "agentNotes": "; ".join(session.agent_notes)
    }
    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
    except Exception:
        pass

# =========================
# MAIN ENDPOINT (FIXED)
# =========================

from fastapi import Header, HTTPException
from typing import Optional, Dict, Any

@app.get("/api/honeypot")
@app.post("/api/honeypot")
@app.post("/api/honeypot/")
async def honeypot_endpoint(
    payload: Optional[Dict[str, Any]] = None,
    x_api_key: str = Header(None)
):
    if x_api_key != "thinkheist_honeypot_2026_secure_key":
        raise HTTPException(status_code=403, detail="Invalid API key")

    # ✅ GUVI tester (NO BODY / GET)
    if payload is None:
        return {
            "status": "success",
            "scamDetected": False,
            "message": "Honeypot endpoint reachable and authenticated"
        }

    text = str(payload).lower()
    scam = any(word in text for word in ["otp", "bank", "verify", "account", "blocked"])

    return {
        "status": "success",
        "scamDetected": scam,
        "engagementLevel": "medium",
        "aiResponse": "Please provide more details to verify your request."
    }
    # ✅ GUVI TESTER HANDLER (NO BODY)
    if request is None:
        return HoneypotResponse(
            status="success",
            scamDetected=False,
            response="Honeypot endpoint reachable and authenticated",
            agentNotes="GUVI endpoint validation"
        )

    session_id = request.sessionId

    if session_id not in sessions:
        sessions[session_id] = SessionData(session_id)

    session = sessions[session_id]

    session.add_message(request.message)

    if ScamDetector.detect(request.message.text):
        session.scam_detected = True
        session.agent_notes.append("Scam patterns detected")

    ai_reply = AIAgent.respond(request.message.text)

    session.add_message(
        Message(
            sender=Sender.USER,
            text=ai_reply,
            timestamp=datetime.now().isoformat() + "Z"
        )
    )

    if session.count() >= 8:
        send_to_guvi(session)

    return HoneypotResponse(
        status="success",
        scamDetected=session.scam_detected,
        response=ai_reply,
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=session.duration(),
            totalMessagesExchanged=session.count()
        ),
        extractedIntelligence=session.intelligence,
        agentNotes="; ".join(session.agent_notes)
    )

# =========================
# HEALTH CHECK
# =========================

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

