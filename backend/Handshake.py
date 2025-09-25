from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import oqs, os


# ==================== PQC Primitives ==================== #

DEFAULT_PQC_ENC_ALGORITHM = 'ML-KEM-768'
#DEFAULT_PQC_SIG_ALGORITHM = 'Dilithium3'

def pqc_key_gen(kem_alg: str = DEFAULT_PQC_ENC_ALGORITHM):
    """
    Generate PQC key pair according to the given algorithm
    """
    # Initialization of the PQC scheme
    pqc_kem = oqs.KeyEncapsulation(kem_alg)
    # Key pair generation
    pqc_pk = pqc_kem.generate_keypair()
    pqc_sk = pqc_kem.export_secret_key()
    return pqc_kem, pqc_pk, pqc_sk


def pqc_encap(pqc_kem = None, pqc_pk = None):
    """
    Encapsulate a secret using the given PQC KEM and public key
    """
    if not pqc_kem or not pqc_pk:
        raise Exception
    # Generate the secret and the related ciphertext
    ciphertext, secret = pqc_kem.encap_secret(pqc_pk)
    return ciphertext, secret


def pqc_decap(pqc_kem = None, ciphertext: str = None):
    """
    Decapsulate an encapsulated secret using the given PQC KEM
    """
    if not pqc_kem or not ciphertext:
        raise Exception
    # Generate the secret and the related ciphertext
    return pqc_kem.decap_secret(ciphertext)


# ==================== ECDHE Primitives ==================== #

def ecdhe_key_gen():
    """
    Generate ECDHE key pair using the X25519 algorithm
    """
    # Key pair generation
    ecdhe_sk = x25519.X25519PrivateKey.generate()
    ecdhe_pk = ecdhe_sk.public_key()
    return ecdhe_pk, ecdhe_sk


def ecdhe_share(internal_ecdhe_sk = None, external_ecdhe_pk = None):
    """
    Create a shared secret using the given own secret key and external public key
    """
    if not internal_ecdhe_sk or not external_ecdhe_pk:
        raise Exception
    # Generate the shared secret
    return internal_ecdhe_sk.exchange(external_ecdhe_pk)


# ==================== HKDF Primitives ==================== #

DEFAULT_HKDF_ALGORITHM = hashes.SHA256()
DEFAULT_HKDF_KEY_LEN = 32
DEFAULT_HKDF_SALT = os.urandom(16)
DEFAULT_HKDF_INFO = b'TLS-HYBRID-DEMO'

def session_root_key_gen(ecdhe_shared_secret: str = None, pqc_shared_secret: str = None):
    """
    Generate a session root key using the given ECDHE and PQC shared secrets
    """
    if not ecdhe_shared_secret or not pqc_shared_secret:
        raise Exception
    # Initialize the derivation function
    hkdf = HKDF(
        algorithm = DEFAULT_HKDF_ALGORITHM,
        length = DEFAULT_HKDF_KEY_LEN,
        salt = DEFAULT_HKDF_SALT,
        info = DEFAULT_HKDF_INFO
    )
    # Combine the two shared secrets
    combined_shared_secret = ecdhe_shared_secret + pqc_shared_secret
    # Derive a root key from the combined shared secret
    return hkdf.derive(combined_shared_secret)



if __name__ == "__main__":
    print("=== Hybrid PQC + ECDHE Key Exchange Demo ===\n")

    # ----- Simulate Alice -----
    print("Generating Alice's keys...")
    alice_ecdhe_pk, alice_ecdhe_sk = ecdhe_key_gen()
    alice_pqc_kem, alice_pqc_pk, alice_pqc_sk = pqc_key_gen()
    
    # ----- Simulate Bob -----
    print("Generating Bob's keys...")
    bob_ecdhe_pk, bob_ecdhe_sk = ecdhe_key_gen()
    bob_pqc_kem, bob_pqc_pk, bob_pqc_sk = pqc_key_gen()

    # ----- Classical ECDHE exchange -----
    alice_shared_classical = ecdhe_share(alice_ecdhe_sk, bob_ecdhe_pk)
    bob_shared_classical = ecdhe_share(bob_ecdhe_sk, alice_ecdhe_pk)

    print(f"ECDHE shared secret match: {alice_shared_classical == bob_shared_classical}")

    # ----- PQC KEM exchange -----
    ciphertext, alice_shared_pqc = pqc_encap(alice_pqc_kem, bob_pqc_pk)
    bob_shared_pqc = pqc_decap(bob_pqc_kem, ciphertext)

    print(f"PQC shared secret match: {alice_shared_pqc == bob_shared_pqc}")

    # ----- Derive session root key -----
    alice_session_key = session_root_key_gen(alice_shared_classical, alice_shared_pqc)
    bob_session_key = session_root_key_gen(bob_shared_classical, bob_shared_pqc)

    print(f"Session key match: {alice_session_key == bob_session_key}")
    print(f"Derived 256-bit session key: {alice_session_key.hex()}")
