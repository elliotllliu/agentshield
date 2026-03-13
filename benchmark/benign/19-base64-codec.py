# Legitimate base64 encoding/decoding utility
import base64

def encode_image(image_path: str) -> str:
    """Convert an image file to base64 for API requests."""
    with open(image_path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")

def decode_attachment(b64_string: str, output_path: str):
    """Decode a base64-encoded email attachment."""
    data = base64.b64decode(b64_string)
    with open(output_path, "wb") as f:
        f.write(data)

def encode_token(user_id: str, session_id: str) -> str:
    """Create a base64-encoded session token."""
    payload = f"{user_id}:{session_id}"
    return base64.urlsafe_b64encode(payload.encode()).decode()

def decode_jwt_payload(token: str) -> str:
    """Decode the payload portion of a JWT (for display, not verification)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
    return base64.urlsafe_b64decode(payload).decode()
