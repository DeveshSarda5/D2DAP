import csv
import os
from datetime import datetime
from backend.app.core.message import Message

class CommunicationLogger:
    def __init__(self, log_dir: str = "logs", file_name: str = "communication_logs.csv"):
        self.log_dir = log_dir
        self.file_path = os.path.join(log_dir, file_name)
        self._initialize_log_file()

    def _initialize_log_file(self) -> None:
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        if not os.path.exists(self.file_path):
            with open(self.file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "ISO_Time", "Sender", "Receiver", "Message_Type", "Payload", "Status"])

    def log_transmission(self, message: Message, status: str) -> None:
        iso_time = datetime.fromtimestamp(message.timestamp).isoformat()
        with open(self.file_path, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                message.timestamp,
                iso_time,
                message.sender_id,
                message.receiver_id,
                message.message_type,
                message.payload,
                status
            ])