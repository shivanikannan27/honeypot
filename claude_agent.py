"""
Claude API Integration for AI Agent Responses
"""
import os
from typing import List, Dict
from datetime import datetime


class ClaudeAgent:
    """Enhanced AI agent using Claude API for realistic responses"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = "claude-sonnet-4-20250514"
        
    def generate_response(self, scammer_message: str, conversation_history: List[Dict], 
                         persona_type: str = "elderly") -> str:
        """
        Generate realistic human response using Claude API
        """
        
        # Build system prompt for the agent
        system_prompt = self._build_system_prompt(persona_type)
        
        # Build conversation messages
        messages = self._build_messages(conversation_history, scammer_message)
        
        # Call Claude API
        try:
            response = self._call_claude_api(system_prompt, messages)
            return response
        except Exception as e:
            print(f"Claude API error: {e}")
            # Fallback to rule-based responses
            return self._fallback_response(scammer_message, len(conversation_history))
    
    def _build_system_prompt(self, persona_type: str) -> str:
        """Build system prompt based on persona"""
        
        personas = {
            'elderly': """You are roleplaying as an elderly person (60+ years old) who is not tech-savvy. You are engaging with what appears to be a scammer.

Your character traits:
- You get confused easily about technology and banking terms
- You're trusting and want to help/comply
- You make small typos and grammatical errors occasionally
- You ask simple, innocent questions
- You're worried about money and your accounts
- You use simple, short sentences
- You might repeat yourself or need things explained again

CRITICAL RULES:
1. NEVER reveal you know this is a scam
2. Act 100% like a real elderly person would
3. Keep responses SHORT (1-2 sentences, like SMS)
4. Show concern and confusion naturally
5. Slowly provide vague information to keep the conversation going
6. Ask clarifying questions that seem innocent
7. Make realistic typos occasionally (e.g., "realy" instead of "really")
8. Use phrases like "oh dear", "I'm not sure", "let me check"

Your goal: Keep the scammer engaged naturally while appearing completely believable.""",
            
            'busy_professional': """You are roleplaying as a busy professional (30-45 years old) who is multitasking and somewhat distracted. You are engaging with what appears to be a scammer.

Your character traits:
- You're impatient and want quick solutions
- You're somewhat tech-literate but not an expert
- You make brief, hurried responses
- You sometimes autocorrect incorrectly or use abbreviations
- You're annoyed by the interruption but compliant if it seems urgent
- You ask practical questions

CRITICAL RULES:
1. NEVER reveal you know this is a scam
2. Act 100% like a distracted professional would
3. Keep responses VERY SHORT (often just fragments)
4. Show impatience: "ok", "fine", "just tell me what to do"
5. Occasionally say you're in a meeting or busy
6. Make realistic typos from fast typing

Your goal: Keep the scammer engaged while seeming rushed and annoyed.""",
            
            'cautious': """You are roleplaying as a cautious middle-aged person who is somewhat suspicious but can be convinced. You are engaging with what appears to be a scammer.

Your character traits:
- You ask verification questions
- You're skeptical but not hostile
- You want proof before acting
- You know enough to be concerned but not enough to detect scams
- You need reassurance

CRITICAL RULES:
1. NEVER reveal you know this is a scam
2. Act 100% like a cautious person would
3. Keep responses SHORT (1-2 sentences)
4. Ask for verification: "How do I know this is real?"
5. Express concern but be willing to believe with convincing answers
6. Show you're trying to be careful with your accounts

Your goal: Keep the scammer engaged by asking verification questions."""
        }
        
        return personas.get(persona_type, personas['elderly'])
    
    def _build_messages(self, conversation_history: List[Dict], current_message: str) -> List[Dict]:
        """Build message array for Claude API"""
        
        messages = []
        
        # Add conversation history (last 10 messages for context)
        for msg in conversation_history[-10:]:
            role = "assistant" if msg.get("sender") == "user" else "user"
            messages.append({
                "role": role,
                "content": msg.get("text", "")
            })
        
        # Add current scammer message
        messages.append({
            "role": "user",
            "content": current_message
        })
        
        return messages
    
    def _call_claude_api(self, system_prompt: str, messages: List[Dict]) -> str:
        """
        Call Claude API
        Replace this with actual API call when deployed
        """
        
        # This is a placeholder - integrate with actual Anthropic API
        # Using the pattern shown in the system prompt
        
        try:
            import requests
            
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01"
                },
                json={
                    "model": self.model,
                    "max_tokens": 150,  # Keep responses short
                    "system": system_prompt,
                    "messages": messages,
                    "temperature": 0.9  # More creative/human-like
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                # Extract text from response
                content = data.get("content", [])
                for item in content:
                    if item.get("type") == "text":
                        return item.get("text", "").strip()
            
            raise Exception(f"API returned {response.status_code}")
            
        except Exception as e:
            print(f"API call failed: {e}")
            raise
    
    def _fallback_response(self, message: str, turn_count: int) -> str:
        """Fallback responses when API unavailable"""
        
        message_lower = message.lower()
        
        # Initial responses
        if turn_count == 0:
            if 'block' in message_lower or 'suspend' in message_lower:
                return "Oh no! Why wil my account be blocked? I dint do anything wrong."
            elif 'verify' in message_lower:
                return "Verify what? Im not sure what you mean..."
            elif 'prize' in message_lower or 'winner' in message_lower:
                return "Really?? I won somthing? What is this about?"
            elif 'tax' in message_lower or 'refund' in message_lower:
                return "Tax refund? How much is it? What do I need to do?"
            else:
                return "What is this about? I dont understand."
        
        # Early engagement (turns 1-3)
        elif turn_count <= 3:
            if 'upi' in message_lower or 'id' in message_lower:
                return "UPI ID? I'm not sure what that is. Is it my phone number?"
            elif 'account' in message_lower or 'number' in message_lower:
                return "My account number? Let me find my checkbook... give me a minute"
            elif 'link' in message_lower or 'click' in message_lower:
                return "I clicked on it but nothing happend. Can you send again?"
            elif 'otp' in message_lower or 'code' in message_lower:
                return "Code? You mean the numbers that came on my phone just now?"
            elif 'bank' in message_lower:
                return "Which bank is this? How do I know this is realy my bank calling?"
            else:
                return "Ok... but what exactly do you need me to do?"
        
        # Middle engagement (turns 4-8)
        elif turn_count <= 8:
            if any(word in message_lower for word in ['share', 'send', 'provide', 'give']):
                return "I want to help but im confussed. Can you explain it simply?"
            elif 'urgent' in message_lower or 'immediately' in message_lower:
                return "Oh dear, this sounds serious. What will happen if I dont do it?"
            elif any(word in message_lower for word in ['verify', 'confirm', 'update']):
                return "Let me try... where do I go to verify this?"
            else:
                return "Sorry, im still confused. What was the problem again?"
        
        # Later engagement (turns 9+)
        else:
            responses = [
                "My grandson usually helps me with these things. Should I ask him?",
                "Is there a phone number I can call to verify this is real?",
                "Can I go to the bank branch instead? This is making me nervus.",
                "What exactly happens if I share this information with you?",
                "How did you get my number? I dont remember giving it out.",
                "Can you hold on? I need to get my reading glasses."
            ]
            # Rotate through responses based on turn count
            return responses[turn_count % len(responses)]
    
    def analyze_scammer_tactics(self, message: str) -> List[str]:
        """Analyze tactics used by scammer"""
        
        tactics = []
        message_lower = message.lower()
        
        # Urgency tactics
        if any(word in message_lower for word in ['urgent', 'immediately', 'now', 'today', 'hurry', 'quick']):
            tactics.append("urgency_pressure")
        
        # Threat tactics
        if any(word in message_lower for word in ['block', 'suspend', 'cancel', 'terminate', 'freeze', 'locked']):
            tactics.append("threat_based")
        
        # Authority impersonation
        if any(word in message_lower for word in ['bank', 'government', 'police', 'officer', 'authority', 'official']):
            tactics.append("authority_impersonation")
        
        # Information phishing
        if any(word in message_lower for word in ['verify', 'confirm', 'share', 'send', 'provide', 'enter']):
            tactics.append("information_phishing")
        
        # Reward/Prize lure
        if any(word in message_lower for word in ['prize', 'winner', 'won', 'reward', 'gift', 'congratulations']):
            tactics.append("reward_lure")
        
        # Payment/Money focus
        if any(word in message_lower for word in ['payment', 'money', 'rupees', 'amount', 'refund', 'transfer']):
            tactics.append("payment_focus")
        
        # Link/Action request
        if any(word in message_lower for word in ['click', 'link', 'website', 'download', 'install', 'app']):
            tactics.append("malicious_link")
        
        # Sensitive data request
        if any(word in message_lower for word in ['otp', 'cvv', 'pin', 'password', 'ssn', 'aadhar']):
            tactics.append("sensitive_data_request")
        
        return tactics if tactics else ["general_engagement"]