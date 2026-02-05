"""
Enhanced Honeypot API with Claude Integration
This version uses the actual Anthropic Claude API for realistic AI responses
"""
import os
from typing import List, Dict


# === CLAUDE API INTEGRATION ===

def generate_ai_response_with_claude(
    scammer_message: str,
    conversation_history: List[Dict],
    persona: str = "elderly"
) -> str:
    """
    Generate realistic human response using Claude API
    
    Args:
        scammer_message: The latest message from the scammer
        conversation_history: Previous messages in the conversation
        persona: Type of persona to use (elderly, professional, cautious)
    
    Returns:
        Human-like response from the AI agent
    """
    
    # System prompt based on persona
    system_prompts = {
        "elderly": """You are roleplaying as an elderly person (65+) who is not tech-savvy.

CRITICAL RULES:
- NEVER reveal you know this is a scam
- Act exactly like a confused elderly person
- Keep responses SHORT (1-2 sentences, SMS-style)
- Make occasional typos: "realy", "recieve", "confussed"
- Show concern: "oh no", "oh dear", "I'm worried"
- Ask simple questions: "what does that mean?", "how do I do that?"
- Be trusting but confused about technology

Examples:
Scammer: "Your account will be blocked"
You: "Oh no! Why will it be blocked? I didnt do anything wrong."

Scammer: "Share your UPI ID"
You: "UPI ID? I'm not sure what that is. Is it my phone number?"

Keep it natural and believable!""",

        "professional": """You are a busy professional (35-45) who is multitasking.

CRITICAL RULES:
- NEVER reveal you know this is a scam
- Be brief and impatient
- Keep responses VERY SHORT (often fragments)
- Show you're busy: "in a meeting", "can't talk"
- Fast typing = occasional typos
- Want quick solutions

Examples:
"ok fine just tell me what to do"
"cant talk now. send link?"
"whats the issue. account number?"

Keep it rushed and distracted!""",

        "cautious": """You are a cautious person who asks verification questions.

CRITICAL RULES:
- NEVER reveal you know this is a scam  
- Be skeptical but not hostile
- Ask for proof: "how do I know this is real?"
- Keep responses SHORT (1-2 sentences)
- Need reassurance before sharing info

Examples:
"How do I know you're really from the bank?"
"Can I call the bank directly to verify this?"
"Why didn't I get an email about this?"

Keep it careful and questioning!"""
    }
    
    # Build conversation for API
    messages = []
    
    # Add history (last 8 messages for context)
    for msg in conversation_history[-8:]:
        role = "assistant" if msg.get("sender") == "user" else "user"
        messages.append({
            "role": role,
            "content": msg.get("text", "")
        })
    
    # Add current scammer message
    messages.append({
        "role": "user",
        "content": scammer_message
    })
    
    # Call Claude API
    try:
        import requests
        
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise Exception("ANTHROPIC_API_KEY not set")
        
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01"
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 100,  # Keep responses short
                "temperature": 0.9,  # More human-like variation
                "system": system_prompts.get(persona, system_prompts["elderly"]),
                "messages": messages
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            # Extract text from response
            for item in data.get("content", []):
                if item.get("type") == "text":
                    return item.get("text", "").strip()
        
        raise Exception(f"API returned {response.status_code}")
        
    except Exception as e:
        print(f"Claude API error: {e}")
        # Fallback to rule-based response
        return generate_fallback_response(scammer_message, len(conversation_history))


def generate_fallback_response(message: str, turn_count: int) -> str:
    """Fallback when Claude API is unavailable"""
    
    message_lower = message.lower()
    
    # Initial responses (turn 0)
    if turn_count == 0:
        if 'block' in message_lower or 'suspend' in message_lower:
            return "Oh no! Why will my account be blocked? I dint do anything."
        elif 'verify' in message_lower:
            return "Verify what exactly? Im confussed about this."
        elif 'prize' in message_lower or 'winner' in message_lower:
            return "Really?? I won something? What is this about?"
        elif 'refund' in message_lower:
            return "Refund? How much is it? What do I need to do?"
        return "What is this message about? I dont understand."
    
    # Early engagement (turns 1-4)
    elif turn_count <= 4:
        if 'upi' in message_lower or 'id' in message_lower:
            return "UPI ID? I dont know what that is. Is it like my account number?"
        elif 'account' in message_lower or 'number' in message_lower:
            return "My account number? Let me find my bank book... one minute"
        elif 'link' in message_lower or 'click' in message_lower:
            return "I tried clicking but nothing is happening. Can you send it again?"
        elif 'otp' in message_lower or 'code' in message_lower:
            return "I got some numbers on my phone. Is that what you need?"
        elif 'bank' in message_lower:
            return "Which bank is this from? How do I know this is realy my bank?"
        return "Ok but what exactly should I do? Please explain simply."
    
    # Middle engagement (turns 5-9)
    elif turn_count <= 9:
        responses = [
            "Sorry im still confussed. Can you explain it again?",
            "Let me get my reading glasses. The text is very small.",
            "My grandson usually helps me with these things.",
            "Is this urgent? What happens if I dont do it today?",
            "I want to help but Im not good with phones and computers.",
            "Should I go to the bank branch instead? That would be easier."
        ]
        return responses[turn_count % len(responses)]
    
    # Later engagement (turns 10+)
    else:
        responses = [
            "How did you get my phone number? I dont remember giving it.",
            "Can I call the bank myself to check if this is real?",
            "My son told me to be careful about these messages.",
            "Why do you need so much information? It seems like a lot.",
            "Let me check with my family first before I share anything.",
            "This is making me nervus. Are you sure this is legitimate?"
        ]
        return responses[turn_count % len(responses)]


# === INTEGRATION INTO MAIN API ===

# Replace the AIAgent.generate_response method in honeypot_api.py with:

"""
@classmethod
def generate_response(cls, scammer_message: str, conversation_history: List[Message], 
                     session: SessionData) -> str:
    '''
    Generate human-like response using Claude API
    '''
    
    # Convert Message objects to dicts for API
    history_dicts = [
        {
            "sender": msg.sender.value,
            "text": msg.text,
            "timestamp": msg.timestamp
        }
        for msg in conversation_history
    ]
    
    # Select persona based on session (can be random or strategic)
    personas = ['elderly', 'professional', 'cautious']
    persona = personas[hash(session.session_id) % len(personas)]
    
    # Generate response using Claude API
    response = generate_ai_response_with_claude(
        scammer_message,
        history_dicts,
        persona
    )
    
    # Add notes about engagement
    session.agent_notes.append(
        f"Persona: {persona}; Tactic: {cls._analyze_scammer_tactic(scammer_message)}"
    )
    
    return response
"""


# === EXAMPLE USAGE ===

if __name__ == "__main__":
    # Example: Test Claude API integration
    
    print("Testing Claude API Integration...\n")
    
    # Set your API key
    # os.environ["ANTHROPIC_API_KEY"] = "sk-ant-your-key-here"
    
    # Test conversation
    test_conversation = [
        {
            "sender": "scammer",
            "text": "Your bank account will be blocked today. Verify immediately.",
            "timestamp": "2026-01-21T10:15:30Z"
        }
    ]
    
    # Generate response
    response = generate_ai_response_with_claude(
        "Share your UPI ID to avoid suspension",
        test_conversation,
        persona="elderly"
    )
    
    print(f"Scammer: Share your UPI ID to avoid suspension")
    print(f"AI Agent: {response}")
    
    print("\n" + "="*60)
    print("Integration Steps:")
    print("="*60)
    print("1. Set ANTHROPIC_API_KEY environment variable")
    print("2. Replace AIAgent.generate_response in honeypot_api.py")
    print("3. Import this module: from claude_integration import generate_ai_response_with_claude")
    print("4. Deploy and test!")