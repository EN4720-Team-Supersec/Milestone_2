from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes
import base64

app = FastAPI()

class HashRequest(BaseModel):
    data: str
    algorithm: str

@app.post("/generate-hash")
async def generate_hash(request: HashRequest):
    hash_algorithms = {
        "SHA-256": hashes.SHA256(),
        "SHA-384": hashes.SHA384(),
        "SHA-512": hashes.SHA512()
    }
    
    algorithm = request.algorithm.upper()
    if algorithm not in hash_algorithms:
        raise HTTPException(status_code=400, detail="Unsupported hashing algorithm")
    
    digest = hashes.Hash(hash_algorithms[algorithm])
    digest.update(request.data.encode())
    hash_value = digest.finalize()
    
    return {
        "hash_value": base64.b64encode(hash_value).decode('utf-8'),
        "algorithm": algorithm
    }
