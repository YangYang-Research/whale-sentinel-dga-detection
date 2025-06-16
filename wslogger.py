import logging
from logging.handlers import RotatingFileHandler
import json
from datetime import datetime, timezone
from dotenv import load_dotenv
import os

load_dotenv()

LOG_MAX_SIZE = os.getenv("LOG_MAX_SIZE", 10000000)  # in bytes
LOG_MAX_BACKUPS = os.getenv("LOG_MAX_BACKUPS", 3)  # number of backup files

class CustomFormatter(logging.Formatter):
    def formatLevel(self, record):
        # Convert levelname to lowercase
        record.levelname = record.levelname.lower()
        return super().format(record)
    
    def format(self, record):
        log = {
            'level': record.levelname.lower(),
            'time': self.formatTime(record),
        }

        # Nếu message là dict thì merge vào log
        if isinstance(record.msg, dict):
            log.update(record.msg)
        else:
            log['message'] = record.getMessage()

        return json.dumps(log, ensure_ascii=False)

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    
def create_log_directory():
    import os
    log_dir = '/var/log/whale-sentinel/ws-services/ws-dga-detection'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        os.chmod(log_dir, 0o755)

def setup_logging():
    logger = logging.getLogger('wslogger')
    logger.setLevel(logging.INFO)
    formatter = CustomFormatter(json.dumps({'level': '%(levelname)s', 'msg': '%(message)s', 'time': '%(asctime)s'}))
    handler = RotatingFileHandler('/var/log/whale-sentinel/ws-services/ws-dga-detection/app.log', maxBytes=int(LOG_MAX_SIZE), backupCount=int(LOG_MAX_BACKUPS))
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# setup logging for script
create_log_directory()
setup_logging()
logger = logging.getLogger('wslogger')
