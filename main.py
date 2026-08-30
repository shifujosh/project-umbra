"""
Project Umbra server entry point.
Run with: python main.py
Or: uvicorn project_umbra.api.app:app --host 0.0.0.0 --port 8000 --reload
"""
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    reload = os.getenv("ENVIRONMENT", "development") == "development"
    uvicorn.run(
        "project_umbra.api.app:app",
        host=host,
        port=port,
        reload=reload,
        loop="asyncio",
    )
