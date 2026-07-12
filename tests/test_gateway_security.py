import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.public_gateway_secure import validate_target_url


async def main() -> None:
    blocked = [
        "http://example.com/file",
        "https://127.0.0.1/admin",
        "https://localhost/metadata",
        "https://user:password@example.com/private",
    ]
    for target in blocked:
        try:
            await validate_target_url(target)
        except ValueError:
            continue
        raise AssertionError(f"unsafe target was accepted: {target}")


if __name__ == "__main__":
    asyncio.run(main())
    print("gateway security checks passed")
