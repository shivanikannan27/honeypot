"""
AI-Driven Honeypot System for Scam Detection and Engagement
"""
from fastapi import FastAPI, HTTPException, Security, Header
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uvicorn
import json
import re
import requests
from enum import Enum

app = FastAPI(title="AI Honeypot API", version="1.0.0")

# API Key Security
API_KEY_NAME = "x-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# Configuration
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
SECRET_API_KEY = "thinkheist_honeypot_2026_secure_key"  # Change this in production

# In-memory session storage (use Redis/DB in production)
sessions = {}


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


class SessionData:
    """Track conversation state per session"""
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.start_time = datetime.now()
        self.messages = []
        self.scam_detected = False
        self.intelligence = ExtractedIntelligence()
        self.agent_notes = []
        self.engagement_complete = False
        
    def add_message(self, message: Message):
        self.messages.append(message)
        
    def get_duration_seconds(self):
        return int((datetime.now() - self.start_time).total_seconds())
    
    def get_message_count(self):
        return len(self.messages)


def verify_api_key(api_key: str = Security(api_key_header)):
    """Verify API key authentication"""
    if api_key != SECRET_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key


class ScamDetector:
    """AI-powered scam detection system"""
    
    SCAM_PATTERNS = [
        # Urgency indicators
        r'\b(urgent|immediately|now|today|expire|suspend|block|freeze)\b',
        # Financial terms
        r'\b(account|bank|card|upi|payment|verify|confirm|update)\b',
        # Threats
        r'\b(suspend|block|terminate|cancel|locked|unauthorized)\b',
        # Request for info
        r'\b(share|send|provide|submit|enter|click|link)\b',
        # Common scam phrases
        r'(otp|cvv|pin|password|account number)',
        r'(congratulations|winner|prize|lottery|reward)',
        r'(tax refund|government|authority|legal action)',
    ]
    
    @classmethod
    def detect_scam(cls, message_text: str) -> tuple[bool, float, list]:
        """
        Detect if message is likely a scam
        Returns: (is_scam, confidence_score, matched_patterns)
        """
        text_lower = message_text.lower()
        matched_patterns = []
        
        for pattern in cls.SCAM_PATTERNS:
            if re.search(pattern, text_lower):
                matched_patterns.append(pattern)
        
        # Calculate confidence based on pattern matches
        confidence = min(len(matched_patterns) * 0.2, 1.0)
        is_scam = len(matched_patterns) >= 2  # At least 2 patterns
        
        return is_scam, confidence, matched_patterns


class IntelligenceExtractor:
    """Extract actionable intelligence from messages"""
    
    @staticmethod
    def extract_all(text: str, existing: ExtractedIntelligence) -> ExtractedIntelligence:
        """Extract all intelligence from text"""
        
        # Bank account patterns
        bank_patterns = [
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # 16-digit
            r'\b\d{9,18}\b',  # 9-18 digit account numbers
        ]
        for pattern in bank_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                cleaned = re.sub(r'[-\s]', '', match)
                if cleaned not in existing.bankAccounts:
                    existing.bankAccounts.append(match)
        
        # UPI IDs
        upi_pattern = r'\b[\w\.-]+@[\w\.-]+\b'
        upi_matches = re.findall(upi_pattern, text.lower())
        for match in upi_matches:
            if any(x in match for x in ['upi', 'paytm', 'phonepe', 'gpay', 'ybl', 'okhdfcbank', 'okicici', 'okaxis']):
                if match not in existing.upiIds:
                    existing.upiIds.append(match)
                    # OPTIONAL: Numeric UPI mentioned explicitly (e.g., "upi id: 878960767607")
        text_lower = text.lower()
        numeric_matches = re.findall(r'\b\d{9,18}\b', text)

        if "upi" in text_lower:
           for match in numeric_matches:
               if match not in existing.upiIds:
                  existing.upiIds.append(match)

        
        # Phone numbers
        phone_pattern = r'\+?\d{1,3}[-\s]?\d{10}|\b\d{10}\b'
        phone_matches = re.findall(phone_pattern, text)
        for match in phone_matches:
            if match not in existing.phoneNumbers:
                existing.phoneNumbers.append(match)
        
        # URLs and phishing links
        url_pattern = r'https?://[^\s]+'
        url_matches = re.findall(url_pattern, text)
        for match in url_matches:
            if match not in existing.phishingLinks:
                existing.phishingLinks.append(match)
        
        # Suspicious keywords
        keywords = [
            'urgent', 'verify', 'suspend', 'block', 'otp', 'cvv', 'pin',
            'password', 'account', 'immediately', 'click', 'link', 'prize',
            'winner', 'tax refund', 'legal action', 'arrest', 'police'
        ]
        text_lower = text.lower()
        for keyword in keywords:
            if keyword in text_lower and keyword not in existing.suspiciousKeywords:
                existing.suspiciousKeywords.append(keyword)
        
        return existing


class AIAgent:
    """AI agent for engaging scammers in human-like conversation"""
    
    PERSONAS = {
        'elderly': {
            'traits': 'elderly person, not tech-savvy, concerned about money, trusting',
            'style': 'uses simple language, asks basic questions, seems worried'
        },
        'busy_professional': {
            'traits': 'busy professional, distracted, wants quick solution',
            'style': 'brief responses, multitasking, impatient but compliant'
        },
        'cautious': {
            'traits': 'cautious person, somewhat suspicious but can be convinced',
            'style': 'asks verification questions, needs reassurance'
        }
    }
    
    @classmethod
    def generate_response(cls, scammer_message: str, conversation_history: List[Message], 
                         session: SessionData) -> str:
        """
        Generate human-like response using Claude API
        This is a placeholder - integrate with actual Claude API
        """
        # Select persona (can be randomized or based on scammer type)
        persona = cls.PERSONAS['elderly']
        
        # Build conversation context
        context = cls._build_context(conversation_history, persona)
        
        # Generate response using LLM
        response = cls._call_llm(scammer_message, context, conversation_history)
        
        # Add notes about engagement strategy
        session.agent_notes.append(f"Response strategy: {cls._analyze_scammer_tactic(scammer_message)}")
        
        return response
    
    @staticmethod
    def _build_context(history: List[Message], persona: dict) -> str:
        """Build context for LLM"""
        return f"""You are playing the role of a {persona['traits']}. 
Your goal is to engage with a suspected scammer naturally and believably.

Important rules:
- Act completely human and believable
- Show concern and confusion appropriate to the persona
- Ask clarifying questions that seem natural
- DO NOT reveal you know it's a scam
- Slowly provide small pieces of information to keep engagement going
- Make realistic typos or grammar mistakes occasionally
- {persona['style']}

Keep responses SHORT (1-2 sentences max) like real SMS/chat conversations.
"""
    
    @staticmethod
    def _call_llm(message: str, context: str, history: List[Message]) -> str:
        """
        Call Claude API to generate response
        Replace this with actual Anthropic API integration
        """
        
        # Build conversation for API
        conversation = []
        for msg in history[-6:]:  # Last 6 messages for context
            role = "assistant" if msg.sender == Sender.USER else "user"
            conversation.append({"role": role, "content": msg.text})
        
        # Add current scammer message
        conversation.append({"role": "user", "content": message})
        
        # Placeholder responses (integrate actual Claude API)
        # This demonstrates the response style
        responses = AIAgent._generate_fallback_response(message, len(history))

        
        return responses
    
    @staticmethod
    def _generate_fallback_response(message: str, turn_count: int) -> str:
        """Fallback responses when API not available"""
        message_lower = message.lower()
        
        # Initial engagement
        if turn_count == 0:
            if 'block' in message_lower or 'suspend' in message_lower:
                return "Oh no! Why is my account being blocked? What happened?"
            elif 'verify' in message_lower:
                return "Verify? I'm not sure what you mean. Is something wrong?"
            elif 'prize' in message_lower or 'winner' in message_lower:
                return "Really? I won something? What is this about?"
        
        # Follow-up responses
        elif turn_count < 5:
            if 'upi' in message_lower or 'account' in message_lower:
                return "Okay... but how do I share that? I'm not good with phones."
            elif 'link' in message_lower or 'click' in message_lower:
                return "I tried clicking but nothing happened. Can you send again?"
            elif 'otp' in message_lower or 'code' in message_lower:
                return "I got some numbers on my phone. Is that what you need?"
        
        # Keep engagement going
        elif turn_count < 10:
            return "Sorry, I'm confused. Can you explain again?"
        
        # Extract more info
        else:
            if 'bank' in message_lower:
                return "Which bank are you calling from? How do I know this is real?"
            else:
                return "Okay, I'll try. What should I do exactly?"
    
    @staticmethod
    def _analyze_scammer_tactic(message: str) -> str:
        """Analyze scammer tactics"""
        message_lower = message.lower()
        tactics = []
        
        if re.search(r'\b(urgent|immediately|now|today)\b', message_lower):
            tactics.append("urgency pressure")
        if re.search(r'\b(block|suspend|cancel|terminate)\b', message_lower):
            tactics.append("threat tactics")
        if re.search(r'\b(verify|confirm|update|share)\b', message_lower):
            tactics.append("information phishing")
        if re.search(r'\b(prize|winner|reward|congratulations)\b', message_lower):
            tactics.append("reward lure")
        
        return ", ".join(tactics) if tactics else "general engagement"
    
    @staticmethod
    def should_end_engagement(session: SessionData) -> bool:
        """Decide if engagement should end"""
        # End after sufficient messages or time
        if session.get_message_count() >= 15:
            return True
        if session.get_duration_seconds() > 600:  # 10 minutes
            return True
        
        # End if good intelligence extracted
        intel = session.intelligence
        if (len(intel.bankAccounts) >= 1 or len(intel.upiIds) >= 1 or 
            len(intel.phishingLinks) >= 1 or len(intel.phoneNumbers) >= 2):
            if session.get_message_count() >= 8:
                return True
        
        return False


def send_to_guvi(session: SessionData):
    """Send final results to GUVI evaluation endpoint"""
    payload = {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": session.get_message_count(),
        "extractedIntelligence": {
            "bankAccounts": session.intelligence.bankAccounts,
            "upiIds": session.intelligence.upiIds,
            "phishingLinks": session.intelligence.phishingLinks,
            "phoneNumbers": session.intelligence.phoneNumbers,
            "suspiciousKeywords": session.intelligence.suspiciousKeywords
        },
        "agentNotes": "; ".join(session.agent_notes)
    }
    
    try:
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        print(f"✓ Sent to GUVI: {response.status_code}")
        return response.status_code == 200
    except Exception as e:
        print(f"✗ Failed to send to GUVI: {e}")
        return False


@app.post("/api/honeypot", response_model=HoneypotResponse)
async def honeypot_endpoint(
    request: IncomingRequest,
    api_key: str = Security(verify_api_key)
):
    """
    Main honeypot endpoint - receives messages and engages scammers
    """
    
    # Get or create session
    session_id = request.sessionId
    if session_id not in sessions:
        sessions[session_id] = SessionData(session_id)
    
    session = sessions[session_id]
    
    # Add incoming message to session
    session.add_message(request.message)
    
    # Extract intelligence from scammer message
    session.intelligence = IntelligenceExtractor.extract_all(
        request.message.text, 
        session.intelligence
    )
    
    # Detect scam (only on first message or if not yet detected)
    if not session.scam_detected:
        is_scam, confidence, patterns = ScamDetector.detect_scam(request.message.text)
        
        if is_scam:
            session.scam_detected = True
            session.agent_notes.append(f"Scam detected with {confidence:.2f} confidence")
        else:
            # Not a scam - return simple response
            return HoneypotResponse(
                status="success",
                scamDetected=False,
                response=None,
                agentNotes="No scam intent detected"
            )
    
    # Check if engagement should end
    if AIAgent.should_end_engagement(session):
        session.engagement_complete = True
        
        # Send final results to GUVI
        send_to_guvi(session)
        
        # Return final response
        return HoneypotResponse(
            status="success",
            scamDetected=True,
            response=None,  # No more responses
            engagementMetrics=EngagementMetrics(
                engagementDurationSeconds=session.get_duration_seconds(),
                totalMessagesExchanged=session.get_message_count()
            ),
            extractedIntelligence=session.intelligence,
            agentNotes="; ".join(session.agent_notes)
        )
    
    # Generate AI response
    ai_response = AIAgent.generate_response(
        request.message.text,
        request.conversationHistory,
        session
    )
    
    # Add AI response to session
    user_message = Message(
        sender=Sender.USER,
        text=ai_response,
        timestamp=datetime.now().isoformat() + "Z"
    )
    session.add_message(user_message)
    
    # Return response
    return HoneypotResponse(
        status="success",
        scamDetected=True,
        response=ai_response,
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=session.get_duration_seconds(),
            totalMessagesExchanged=session.get_message_count()
        ),
        extractedIntelligence=session.intelligence,
        agentNotes="; ".join(session.agent_notes[-3:])  # Last 3 notes
    )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.get("/sessions/{session_id}")
async def get_session(session_id: str, api_key: str = Security(verify_api_key)):
    """Get session details (for debugging)"""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = sessions[session_id]
    return {
        "sessionId": session_id,
        "messageCount": session.get_message_count(),
        "durationSeconds": session.get_duration_seconds(),
        "scamDetected": session.scam_detected,
        "intelligence": session.intelligence
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)