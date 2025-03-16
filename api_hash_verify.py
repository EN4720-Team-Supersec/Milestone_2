from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from base64 import b64encode, b64decode
import os
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

app = FastAPI()

class HashVerifyRequest(BaseModel):
    data: str
    hash_value: str 
    algorithm: str  

@app.post("/verify-hash")
def verify_hash(request: HashVerifyRequest):
    try:
        data_bytes = request.data.encode()
        provided_hash_bytes = b64decode(request.hash_value)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64-encoded hash_value")

    algorithm = request.algorithm.upper()

    # Select hash algorithm
    if algorithm == "SHA-256":
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    elif algorithm == "SHA-384":
        digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
    elif algorithm == "SHA-512":
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    else:
        raise HTTPException(status_code=400, detail="Unsupported hashing algorithm")

    digest.update(data_bytes)
    computed_hash = digest.finalize()

    if computed_hash == provided_hash_bytes:
        return {"is_valid": True, "message": "Hash matches the data."}
    else:
        return {"is_valid": False, "message": "Hash does not match the data."}