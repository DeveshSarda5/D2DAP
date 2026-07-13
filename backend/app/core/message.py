# backend/app/core/message.py
import time
from typing import Any, Dict

class Message:
    def __init__(self, sender_id: str, receiver_id: str, payload: Any, message_type: str = "DATA"):
        self.sender_id: str = sender_id
        self.receiver_id: str = receiver_id
        self.payload: Any = payload
        self.message_type: str = message_type
        self.timestamp: float = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "sender": self.sender_id,
            "receiver": self.receiver_id,
            "message_type": self.message_type,
            "payload": str(self.payload)
        }

    def __repr__(self) -> str:
        return f"Message({self.message_type} | {self.sender_id} -> {self.receiver_id})"