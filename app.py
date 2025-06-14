# python 3.9
import os
from huggingface_hub import hf_hub_download
import tensorflow as tf
from keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import load_model
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import base64
import uvicorn
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from concurrent.futures import ThreadPoolExecutor
import asyncio
from datetime import datetime, timezone
import json
import logging
from wslogger import logger

log = logging.getLogger(__name__)

class Payload(BaseModel):
    payload: str
    event_info: str
    agent_id: str
    agent_name: str
    request_created_at: str

load_dotenv()

AWS_REGION = os.getenv("AWS_REGION")
AWS_SECRET_NAME = os.getenv("AWS_SECRET_NAME")
WHALE_SENTINEL_SERVICE_SECRET_KEY_NAME = os.getenv("WHALE_SENTINEL_SERVICE_SECRET_KEY_NAME")

app = FastAPI()

def get_secret():

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=AWS_REGION
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=AWS_SECRET_NAME
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = get_secret_value_response['SecretString']
    secret_data = json.loads(secret)
    secret_value = secret_data.get(WHALE_SENTINEL_SERVICE_SECRET_KEY_NAME)

    return secret_value

def load_model_detector():
    local_model_path = hf_hub_download(
        repo_id="noobpk/dga-detection",
        filename="model.h5"
    )
    return load_model(local_model_path)
    
model_detector = load_model_detector()

valid_characters = "$abcdefghijklmnopqrstuvwxyz0123456789-_."
tokens = {char: idx for idx, char in enumerate(valid_characters)}

def get_decoded_auth(authorization: str) -> str:
    try:
        if not authorization.startswith("Basic "):
            raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})
        encoded_auth = authorization[len("Basic "):]
        decoded_auth = base64.b64decode(encoded_auth).decode()
        return decoded_auth
    except Exception:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})

def to_unix_time(timestamp):
    if not isinstance(timestamp, str):
        return 0
    try:
        parsed_time = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
        parsed_time = parsed_time.replace(tzinfo=timezone.utc)
        return int(parsed_time.timestamp())
    except ValueError:
        return 0
    
def extract_eventInfo(event_info: str):
    try:
        agent_id, service_name, event_id = event_info.split("|")
        return {
            "agent_id": agent_id,
            "service_name": service_name,
            "event_id": event_id,
        }
    except ValueError:
        log.error(f"Invalid event_info format: {event_info}. Expected format: agent_id|service_name|event_id")

async def process_loggcollection(payload: Payload, eventInfo: str, action_result: str, action_status: str,  score: float):
    info = extract_eventInfo(payload.event_info)
    # Construct log entry
    logEntry = {
        "name": "ws-dga-detection",
        "agent_id": payload.agent_id,
        "agent_name": payload.agent_name,
        "source": str(info["service_name"]).lower(),
        "destination": "ws-dga-detection",
        "event_info": eventInfo,
        "level": "INFO",
        "event_id": info["event_id"],
        "type": "SERVICE_EVENT",
        "action": "ANALYSIS_REQUEST",
        "action_result": action_result,
        "action_status": action_status,
        "raw_request": payload.payload,
        "prediction": score,
        "message": "Received request from service",
        "request_created_at": to_unix_time(payload.request_created_at),
        "request_processed_at": to_unix_time(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')),
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    }
    logEntryJSON = json.dumps(logEntry, ensure_ascii=False).replace('"', '\\"')    
    logger.info(logEntryJSON)

@app.get("/api/v1/ws/services/dga-detection/ping")
def ping_info(authorization: str = Header(None)):
    decoded_auth = get_decoded_auth(authorization)
    apiKey = get_secret()
    expectedAuthValue = f"ws:{apiKey}"
    if decoded_auth != expectedAuthValue:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})
    return {
        "model": "noobpk/dga-detection",
        "max_input_length": "unlimit",
        "vector_size": "45",
        "param": "5612705",
        "model_build_at": "25-03-2025",
        "encoder": "pad_sequences",
        "author": "noobpk - lethanhphuc",
    }

@app.post("/api/v1/ws/services/dga-detection")
async def detection(payload: Payload, authorization: str = Header(None)):
    try:
        # Enforce a 30-second timeout for the entire function
        result = await asyncio.wait_for(process_detection(payload, authorization), timeout=30.0)
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail={"status": "error", "message": "Request timed out", "error_code": 504})
    
async def process_detection(payload: Payload, authorization: str):
    decoded_auth = get_decoded_auth(authorization)
    apiKey = get_secret()
    expectedAuthValue = f"ws:{apiKey}"
    if decoded_auth != expectedAuthValue:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})
    
    payload_data = payload.payload

    # Convert domain to lowercase and encode it
    payload_encoded = [tokens[char] for char in payload_data.lower() if char in tokens]

    # Pad and truncate the sequence
    domain_encoded = pad_sequences([payload_encoded], maxlen=45, padding='post', truncating='post')

    def predict():
        return model_detector.predict(domain_encoded)

    def calculate_accuracy(prediction):
        return float(prediction[0][0] * 100)

    with ThreadPoolExecutor() as executor:
        prediction = executor.submit(predict).result()
        accuracy = executor.submit(calculate_accuracy, prediction).result()

    # Replace "WS_GATEWAY_SERVICE" with "WS_WEB_ATTACK_DETECTION" in event_id
    event_info = payload.event_info.replace("WS_GATEWAY_SERVICE", "WS_DGA_DETECTION")

    # Trigger log collection (do not await to keep async non-blocking)
    asyncio.create_task(process_loggcollection(payload, eventInfo=event_info, action_result="NO_MAKE_DECISION", action_status="SUCCESSED", score=accuracy))

    return JSONResponse(content={
        "status": "success",
        "message": "Request processed successfully",
        "data": {
            "threat_metrix": {
                "domain": payload_data,
                "class": 1 if prediction[0][0] > 0.9 else 0,
                "score": accuracy,
            }
        },
        "event_info": event_info,
        "request_created_at": payload.request_created_at,
        "request_processed_at":  datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    })

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5002)