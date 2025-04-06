# main.py
import os
from dotenv import load_dotenv
load_dotenv()
from typing import Optional, List, Dict, Any
import re
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import asyncpg
from openai import OpenAI
import uvicorn
import logging


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="QR Safe API", description="API for QR code security verification")

# CORS middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connection config
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://postgres:postgres@localhost:5432/qr_safe"
)

# OpenAI client setup
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai_client = OpenAI(api_key=OPENAI_API_KEY)

# Pydantic models for request/response validation
class URLCheckRequest(BaseModel):
    url: str

class DBCheckResponse(BaseModel):
    verified: bool
    source: str
    details: str
    is_malicious: Optional[bool] = None
    threat_details: Optional[str] = None
    company_name: Optional[str] = None
    verification_date: Optional[str] = None
    unknown: Optional[bool] = None

class WebCheckResponse(BaseModel):
    safe: Optional[bool]
    source: str
    details: str
    raw_results: Optional[str] = None
    error: Optional[str] = None

class CombinedCheckResponse(BaseModel):
    db_check: DBCheckResponse
    web_check: WebCheckResponse

# Database connection pool
async def get_db_pool():
    return await asyncpg.create_pool(DATABASE_URL)

# Setup database pool during startup
@app.on_event("startup")
async def startup_db_client():
    app.state.pool = await get_db_pool()
    logger.info("Connected to database")

# Close database pool during shutdown
@app.on_event("shutdown")
async def shutdown_db_client():
    await app.state.pool.close()
    logger.info("Disconnected from database")

# Helper Functions
def normalize_url(url: str) -> str:
    """Normalize URL for consistent checking"""
    # Remove protocol (http/https) for matching
    normalized_url = url.lower()
    normalized_url = re.sub(r'^https?://', '', normalized_url)
    
    # Remove trailing slash
    normalized_url = re.sub(r'/$', '', normalized_url)
    
    return normalized_url

async def check_url_in_database(pool, normalized_url: str) -> Dict[str, Any]:
    """Check URL in PostgreSQL database"""
    try:
        # First check against known malicious URLs
        malicious_query = """
            SELECT * FROM malicious_urls 
            WHERE normalized_url = $1 
            OR normalized_url LIKE '%' || $1 || '%' 
            OR $1 LIKE '%' || normalized_url || '%'
        """
        
        async with pool.acquire() as conn:
            malicious_result = await conn.fetch(malicious_query, normalized_url)
        
        if malicious_result:
            return {
                "verified": False,
                "source": "QR Safe Threat Database",
                "details": "This URL has been reported as malicious.",
                "is_malicious": True,
                "threat_details": malicious_result[0]["threat_details"] or "Known scam or phishing URL"
            }
        
        # If not malicious, check against verified partners
        verified_query = """
            SELECT * FROM verified_partners 
            WHERE normalized_url = $1 
            OR $1 LIKE normalized_url || '%'
        """
        
        async with pool.acquire() as conn:
            verified_result = await conn.fetch(verified_query, normalized_url)
        
        if verified_result:
            partner = verified_result[0]
            return {
                "verified": True,
                "source": "QR Safe Verified Database",
                "details": f"Official {partner['company_name']} QR code. Verified partner.",
                "company_name": partner["company_name"],
                "verification_date": partner["verification_date"].isoformat()
            }
        
        # If neither verified nor malicious
        return {
            "verified": False,
            "source": "QR Safe Verified Database",
            "details": "This URL is not from a verified partner.",
            "unknown": True
        }
    except Exception as e:
        logger.error(f"Database query error: {e}")
        raise e

async def check_url_with_openai(url: str) -> Dict[str, Any]:
    """Check a URL using OpenAI's Responses API with web search enabled, then analyze the results.
    
    1. Perform a web search about the URL.
    2. Use a second OpenAI call to interpret and classify the website's safety.
    
    Returns:
        Dict with:
        - "safe" (bool or None): True = safe, False = unsafe, None = uncertain
        - "source": A string reference
        - "details": A short reason for classification
        - "raw_results": The raw text from the web search
        - Optional "error": In case something went wrong
    """
    try:
        # Step 1: Web search to gather information
        search_query = (
            f'Is "{url}" a legitimate website or is it associated with scams, '
            'phishing, or malware? Provide any relevant security concerns.'
        )
        
        response = openai_client.responses.create(
            model="gpt-4o",
            tools=[{"type": "web_search_preview"}],
            input=search_query
        )
        # Extract the raw text from the first piece of content
        search_results = response.output_text
        
        logger.info(f"Search results for {url}:\n{search_results}\n")
        
        # Step 2: Use a second call to analyze the results
        analysis_prompt = f"""
        Based on the following information about {url}, determine if the website is safe, suspicious, or dangerous.
        
        Web search information:
        {search_results}
        
        Respond in this exact format:
        SAFETY: [safe/suspicious/dangerous]
        REASON: [one clear sentence explaining your assessment]
        """
        
        analysis_response = openai_client.responses.create(
            model="gpt-4o-mini",
            input=analysis_prompt
        )
        analysis_text = analysis_response.output_text
        
        logger.info(f"Analysis for {url}:\n{analysis_text}\n")
        
        # Parse the results
        safety_match = re.search(r"SAFETY:\s*(safe|suspicious|dangerous)", analysis_text, re.IGNORECASE)
        reason_match = re.search(r"REASON:\s*(.*?)($|\n)", analysis_text, re.IGNORECASE)
        
        safety_rating = safety_match.group(1).lower() if safety_match else "uncertain"
        reason = reason_match.group(1).strip() if reason_match else "Unable to determine a clear reason."
        
        # Map the safety rating
        if safety_rating == "safe":
            safe_value = True
        elif safety_rating == "dangerous":
            safe_value = False
        else:  # includes "suspicious" or "uncertain"
            safe_value = None
        
        return {
            "safe": safe_value,
            "source": "Web Search Analysis",
            "details": reason,
            "raw_results": search_results
        }
    
    except Exception as e:
        logger.error(f"OpenAI API error: {e}", exc_info=True)
        return {
            "safe": None,
            "source": "Web Search Analysis",
            "details": "Unable to verify this URL through web search. Please proceed with caution.",
            "error": str(e)
        }

# API Routes
@app.post("/api/check-url-in-db", response_model=DBCheckResponse)
async def api_check_url_in_db(request: URLCheckRequest):
    """Check URL in PostgreSQL database endpoint"""
    try:
        if not request.url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        # Normalize the URL for consistent checking
        normalized_url = normalize_url(request.url)
        
        # Check against the database
        result = await check_url_in_database(app.state.pool, normalized_url)
        
        return result
    except Exception as e:
        logger.error(f"Database check error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/check-url-with-openai", response_model=WebCheckResponse)
async def api_check_url_with_openai(request: URLCheckRequest):
    """Check URL with OpenAI web search endpoint"""
    try:
        if not request.url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        # Perform web search using OpenAI
        result = await check_url_with_openai(request.url)
        
        return result
    except Exception as e:
        logger.error(f"OpenAI check error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/check-url", response_model=CombinedCheckResponse)
async def api_check_url(request: URLCheckRequest):
    """Combined check (both DB and OpenAI) endpoint"""
    try:
        if not request.url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        # Normalize the URL for consistent checking
        normalized_url = normalize_url(request.url)
        
        # Run both checks concurrently
        import asyncio
        db_result, web_result = await asyncio.gather(
            check_url_in_database(app.state.pool, normalized_url),
            check_url_with_openai(request.url)
        )
        
        return {
            "db_check": db_result,
            "web_check": web_result
        }
    except Exception as e:
        logger.error(f"URL check error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Serve static files from the "public" directory
app.mount("/", StaticFiles(directory="public", html=True), name="static")

# Error handler
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)},
    )

# Run the application if executed directly
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=3000, reload=True)

