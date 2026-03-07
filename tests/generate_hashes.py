from werkzeug.security import generate_password_hash
import json

users = {
    "admin": {
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "created_at": "2026-03-01T10:00:00"
    },
    "analyst": {
        "password": generate_password_hash("analyst123"),
        "role": "analyst",
        "created_at": "2026-03-02T14:30:00"
    }
}

print(json.dumps(users, indent=2))
