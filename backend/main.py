from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import oqs, os, base64
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Hybrid PQC + ECDHE API")

# Allow all origins for development purposes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== PQC Primitives ==================== #

DEFAULT_PQC_ENC_ALGORITHM = 'ML-KEM-768'

def pqc_key_gen(kem_alg: str = DEFAULT_PQC_ENC_ALGORITHM):
    pqc_kem = oqs.KeyEncapsulation(kem_alg)
    pqc_pk = pqc_kem.generate_keypair()
    pqc_sk = pqc_kem.export_secret_key()
    return pqc_kem, pqc_pk, pqc_sk

def pqc_encap(pqc_kem=None, pqc_pk=None):
    ciphertext, secret = pqc_kem.encap_secret(pqc_pk)
    return ciphertext, secret

def pqc_decap(pqc_kem=None, ciphertext=None):
    return pqc_kem.decap_secret(ciphertext)


# ==================== ECDHE Primitives ==================== #

def ecdhe_key_gen():
    ecdhe_sk = x25519.X25519PrivateKey.generate()
    ecdhe_pk = ecdhe_sk.public_key()
    return ecdhe_pk, ecdhe_sk

def ecdhe_share(internal_ecdhe_sk=None, external_ecdhe_pk=None):
    return internal_ecdhe_sk.exchange(external_ecdhe_pk)


# ==================== HKDF ==================== #

DEFAULT_HKDF_ALGORITHM = hashes.SHA256()
DEFAULT_HKDF_KEY_LEN = 32
DEFAULT_HKDF_SALT = os.urandom(16)
DEFAULT_HKDF_INFO = b'TLS-HYBRID-DEMO'

def session_root_key_gen(ecdhe_shared_secret, pqc_shared_secret):
    hkdf = HKDF(
        algorithm=DEFAULT_HKDF_ALGORITHM,
        length=DEFAULT_HKDF_KEY_LEN,
        salt=DEFAULT_HKDF_SALT,
        info=DEFAULT_HKDF_INFO
    )
    combined = ecdhe_shared_secret + pqc_shared_secret
    return hkdf.derive(combined)


# ==================== API MODELS ==================== #

class KeyResponse(BaseModel):
    ecdhe_pk: str
    pqc_pk: str

class SharedSecretsRequest(BaseModel):
    client_ecdhe_sk: str
    server_ecdhe_pk: str
    ciphertext: str
    server_pqc_sk: str

class SessionKeyRequest(BaseModel):
    ecdhe_secret: str
    pqc_secret: str

class MessageRequest(BaseModel):
    message: str
    session_key: str
    nonce: str = None
    ciphertext: str = None

class DecryptRequest(BaseModel):
    session_key: str
    nonce: str
    ciphertext: str

# ==================== API ENDPOINTS ==================== #

STATE = {}

@app.get("/keys", response_model=Dict[str, KeyResponse])
def generate_keys():
    # Generate client ECDHE
    client_ecdhe_pk, client_ecdhe_sk = ecdhe_key_gen()
    client_ecdhe_pk_bytes = client_ecdhe_pk.public_bytes_raw()

    # Generate client PQC (kem instance + public/secret bytes)
    client_pqc_kem, client_pqc_pk, client_pqc_sk = pqc_key_gen()

    # Generate server ECDHE
    server_ecdhe_pk, server_ecdhe_sk = ecdhe_key_gen()
    server_ecdhe_pk_bytes = server_ecdhe_pk.public_bytes_raw()

    # Generate server PQC
    server_pqc_kem, server_pqc_pk, server_pqc_sk = pqc_key_gen()

    # Save objects & bytes in STATE for demo (do NOT do this in production)
    STATE["client"] = {
        "ecdhe_sk": client_ecdhe_sk,
        "ecdhe_pk_bytes": client_ecdhe_pk_bytes,
        "pqc_kem": client_pqc_kem,
        "pqc_pk_bytes": client_pqc_pk,
        "pqc_sk_bytes": client_pqc_sk
    }
    STATE["server"] = {
        "ecdhe_sk": server_ecdhe_sk,
        "ecdhe_pk_bytes": server_ecdhe_pk_bytes,
        "pqc_kem": server_pqc_kem,
        "pqc_pk_bytes": server_pqc_pk,
        "pqc_sk_bytes": server_pqc_sk
    }

    return {
        "client": {
            "ecdhe_pk": base64.b64encode(client_ecdhe_pk_bytes).decode(),
            "pqc_pk": base64.b64encode(client_pqc_pk).decode()
        },
        "server": {
            "ecdhe_pk": base64.b64encode(server_ecdhe_pk_bytes).decode(),
            "pqc_pk": base64.b64encode(server_pqc_pk).decode()
        }
    }


@app.get("/shared-secrets")
def compute_shared():
    try:
        # --- ECDHE shared secret (X25519) ---
        # server's public key object from stored bytes
        server_pub = x25519.X25519PublicKey.from_public_bytes(STATE["server"]["ecdhe_pk_bytes"])
        client_shared = STATE["client"]["ecdhe_sk"].exchange(server_pub)

        # --- PQC shared secret (KEM) ---
        # IMPORTANT: call encap_secret on client's KEM and pass server's stored public bytes
        ct, client_pqc_secret = STATE["client"]["pqc_kem"].encap_secret(STATE["server"]["pqc_pk_bytes"])

        # server decapsulates using his KEM instance and the ciphertext
        server_pqc_secret = STATE["server"]["pqc_kem"].decap_secret(ct)

        # --- Combined secret (used for session key derivation) ---
        combined_secret = client_shared + client_pqc_secret

        # sanity check: client_pqc_secret == server_pqc_secret
        if client_pqc_secret != server_pqc_secret:
            # not expected, but guard anyway
            raise RuntimeError("PQC secrets do not match")

        return {
            "ecdhe_shared": base64.b64encode(client_shared).decode(),
            "pqc_shared": base64.b64encode(client_pqc_secret).decode(),
            "pqc_ciphertext": base64.b64encode(ct).decode(),
            "combined_secret": base64.b64encode(combined_secret).decode()
        }

    except KeyError:
        raise HTTPException(status_code=400, detail="STATE not initialized - call /keys first")
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=f"PQC error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.post("/session-key")
def derive_session_key(req: SessionKeyRequest):
    ecdhe_secret = base64.b64decode(req.ecdhe_secret)
    pqc_secret = base64.b64decode(req.pqc_secret)
    key = session_root_key_gen(ecdhe_secret, pqc_secret)
    return {"session_key": base64.b64encode(key).decode()}

@app.post("/encrypt")
def encrypt_message(req: MessageRequest):
    key = base64.b64decode(req.session_key)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, req.message.encode(), None)
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }

@app.post("/decrypt")
def decrypt_message(req: DecryptRequest):
    key = base64.b64decode(req.session_key)
    nonce = base64.b64decode(req.nonce)
    try:
        pt = AESGCM(key).decrypt(nonce, base64.b64decode(req.ciphertext), None)
        return {"message": pt.decode()}
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed")
