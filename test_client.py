"""
Test Client for AI Honeypot System
Simulates the GUVI platform sending scam messages
"""
import requests
import json
import time
from datetime import datetime
from typing import List, Dict


class HoneypotTestClient:
    """Test client for the honeypot API"""
    
    def __init__(self, base_url: str = "http://localhost:8000", api_key: str = "thinkheist_honeypot_2026_secure_key"):
        self.base_url = base_url
        self.api_key = api_key
        self.headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key
        }
    
    def send_message(self, session_id: str, message_text: str, 
                     conversation_history: List[Dict] = None) -> Dict:
        """Send a message to the honeypot"""
        
        payload = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": message_text,
                "timestamp": datetime.now().isoformat() + "Z"
            },
            "conversationHistory": conversation_history or [],
            "metadata": {
                "channel": "SMS",
                "language": "English",
                "locale": "IN"
            }
        }
        
        response = requests.post(
            f"{self.base_url}/api/honeypot",
            json=payload,
            headers=self.headers,
            timeout=30
        )
        
        return response.json()
    
    def run_scam_scenario(self, scenario_name: str):
        """Run a complete scam scenario"""
        
        scenarios = {
            "bank_account_block": [
                "Your bank account will be blocked today. Verify immediately.",
                "Share your UPI ID to avoid account suspension.",
                "We need to verify your identity. What is your account number?",
                "Please confirm your last 4 digits of account number.",
                "Enter the OTP sent to your mobile to verify.",
                "Click this link to update your KYC: http://fake-bank-verify.com",
                "Your account will be permanently closed in 2 hours if not verified.",
                "What is your registered mobile number with the bank?",
                "We need your full name as per bank records.",
                "Thank you. Your account is now safe."
            ],
            
            "prize_winner": [
                "Congratulations! You've won Rs 50,000 in our lucky draw!",
                "To claim your prize, share your UPI ID for instant transfer.",
                "What is your full name for the prize certificate?",
                "Please share your mobile number for verification.",
                "We need a small processing fee of Rs 500. Share UPI to pay.",
                "After payment, prize will be credited within 24 hours.",
                "Click here to see your prize details: http://prize-claim.com",
                "What is your email ID for sending the prize letter?"
            ],
            
            "tax_refund": [
                "You have a pending tax refund of Rs 15,000 from the government.",
                "To receive your refund, provide your bank account number.",
                "What is your PAN card number for verification?",
                "Share your IFSC code for direct bank transfer.",
                "Government needs your Aadhar number to process the refund.",
                "There is a processing fee of Rs 200. Pay via UPI.",
                "Send payment to this UPI ID: taxrefund@paytm",
                "Your refund will be processed after fee payment."
            ]
        }
        
        scenario_messages = scenarios.get(scenario_name, scenarios["bank_account_block"])
        session_id = f"test-{scenario_name}-{int(time.time())}"
        
        print(f"\n{'='*60}")
        print(f"Running Scenario: {scenario_name.upper()}")
        print(f"Session ID: {session_id}")
        print(f"{'='*60}\n")
        
        conversation_history = []
        
        for i, scam_message in enumerate(scenario_messages, 1):
            print(f"\n--- Turn {i} ---")
            print(f"Scammer: {scam_message}")
            
            # Send to honeypot
            response = self.send_message(session_id, scam_message, conversation_history)
            
            # Display response
            if response.get("scamDetected"):
                print(f"✓ Scam Detected!")
                
                if response.get("response"):
                    print(f"Agent: {response['response']}")
                    
                    # Add to history
                    conversation_history.append({
                        "sender": "scammer",
                        "text": scam_message,
                        "timestamp": datetime.now().isoformat() + "Z"
                    })
                    conversation_history.append({
                        "sender": "user",
                        "text": response['response'],
                        "timestamp": datetime.now().isoformat() + "Z"
                    })
                else:
                    print("✓ Engagement Complete - No further response")
                    
                # Display metrics if available
                if response.get("engagementMetrics"):
                    metrics = response["engagementMetrics"]
                    print(f"\nMetrics:")
                    print(f"  Duration: {metrics['engagementDurationSeconds']}s")
                    print(f"  Messages: {metrics['totalMessagesExchanged']}")
                
                # Display extracted intelligence
                if response.get("extractedIntelligence"):
                    intel = response["extractedIntelligence"]
                    print(f"\nExtracted Intelligence:")
                    if intel.get("bankAccounts"):
                        print(f"  Bank Accounts: {intel['bankAccounts']}")
                    if intel.get("upiIds"):
                        print(f"  UPI IDs: {intel['upiIds']}")
                    if intel.get("phishingLinks"):
                        print(f"  Phishing Links: {intel['phishingLinks']}")
                    if intel.get("phoneNumbers"):
                        print(f"  Phone Numbers: {intel['phoneNumbers']}")
                    if intel.get("suspiciousKeywords"):
                        print(f"  Keywords: {', '.join(intel['suspiciousKeywords'][:5])}")
                
                # Display agent notes
                if response.get("agentNotes"):
                    print(f"\nAgent Notes: {response['agentNotes']}")
                
                # Check if engagement ended
                if not response.get("response"):
                    print("\n✓ Session completed and reported to GUVI")
                    break
            else:
                print("✗ Not detected as scam")
                break
            
            # Delay between messages
            time.sleep(1)
        
        print(f"\n{'='*60}")
        print(f"Scenario Complete: {scenario_name}")
        print(f"{'='*60}\n")
    
    def test_api_health(self):
        """Test API health"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code == 200:
                print("✓ API is healthy")
                return True
            else:
                print("✗ API health check failed")
                return False
        except Exception as e:
            print(f"✗ Cannot connect to API: {e}")
            return False


def main():
    """Run test scenarios"""
    
    print("\n" + "="*60)
    print("AI HONEYPOT SYSTEM - TEST CLIENT")
    print("="*60)
    
    client = HoneypotTestClient()
    
    # Test API health
    print("\n1. Testing API Health...")
    if not client.test_api_health():
        print("\nPlease start the API server first:")
        print("  python honeypot_api.py")
        return
    
    # Run scenarios
    print("\n2. Running Test Scenarios...")
    
    scenarios = [
        "bank_account_block",
        "prize_winner", 
        "tax_refund"
    ]
    
    for scenario in scenarios:
        try:
            client.run_scam_scenario(scenario)
            time.sleep(2)  # Delay between scenarios
        except Exception as e:
            print(f"Error in scenario {scenario}: {e}")
    
    print("\n" + "="*60)
    print("All test scenarios completed!")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()