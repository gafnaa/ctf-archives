import os
from uuid import uuid4

FLAG_STAGE_1 = os.environ.get("FLAG_STAGE_1")
FLAG_STAGE_5 = os.environ.get("FLAG_STAGE_5")

with open(".env", "w") as f:
    f.write(f"FLASK_APP_SECRET_KEY={os.urandom(50).hex()}\n")
    f.write(f"FLAG_STAGE_1={FLAG_STAGE_1}\n")

with open(f"flag_{uuid4().hex + uuid4().hex + uuid4().hex}.txt", "w") as f:
    f.write(FLAG_STAGE_5)