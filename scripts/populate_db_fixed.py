# populate_db_fixed.py
import os
from dotenv import load_dotenv
import asyncio
import asyncpg
from datetime import date
import re

# Load environment variables (for local dev)
load_dotenv()

# Retrieve DATABASE_URL from env, with a default for local dev.
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://postgres:postgres@localhost:5432/qr_safe"
)

# Normalize URL for consistent checking
def normalize_url(url):
    # Remove protocol (http/https) for matching
    normalized_url = url.lower()
    normalized_url = re.sub(r'^https?://', '', normalized_url)
    
    # Remove trailing slash
    normalized_url = re.sub(r'/$', '', normalized_url)
    
    return normalized_url

# Main function to populate the database
async def populate_database():

    # List of benign URLs from your QR codes
    benign_urls = [
        "https://www.wikipedia.org/",
        "https://www.openai.com/", 
        "https://www.khanacademy.org/", 
        "https://www.python.org/", 
        "https://www.github.com/", 
        "https://www.stackoverflow.com/", 
        "https://www.apple.com/", 
        "https://www.google.com/", 
        "https://www.microsoft.com/", 
        "https://www.nytimes.com/"
    ]
    
    # List of malicious URLs from your QR codes
    malicious_urls = [
        "http://login-microsoft.com.verify-credentials.ru/",
        "http://192.168.0.101/phish",
        "http://free-gift-now.click/claim",
        "http://update-bank.info/login",
        "http://evil.site/download/installer.exe",
        "http://verify-now.security-check.ga/"
    ]
    
    try:
        # Connect to the database
        print("Connecting to database...")
        pool = await asyncpg.create_pool(DATABASE_URL)
        
        # First, ensure the unique constraints exist
        try:
            print("Checking and adding unique constraints if needed...")
            await pool.execute('''
                DO $$
                BEGIN
                    -- Check if unique constraint exists on verified_partners
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'verified_partners_normalized_url_key'
                        AND conrelid = 'verified_partners'::regclass
                    ) THEN
                        ALTER TABLE verified_partners ADD CONSTRAINT verified_partners_normalized_url_key UNIQUE (normalized_url);
                    END IF;
                    
                    -- Check if unique constraint exists on malicious_urls
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'malicious_urls_normalized_url_key'
                        AND conrelid = 'malicious_urls'::regclass
                    ) THEN
                        ALTER TABLE malicious_urls ADD CONSTRAINT malicious_urls_normalized_url_key UNIQUE (normalized_url);
                    END IF;
                END
                $$;
            ''')
        except Exception as e:
            print(f"Warning: Could not verify/add unique constraints: {e}")
            print("Will use alternative approach for duplicate handling")
        
        # Today's date for verification_date and reported_date
        today = date.today()
        
        # Insert benign URLs into verified_partners table
        print(f"Adding {len(benign_urls)} benign URLs to database...")
        for i, url in enumerate(benign_urls, 1):
            normalized = normalize_url(url)
            
            # Extract domain for company name
            domain_match = re.search(r'https?://(?:www\.)?([^/]+)', url)
            company_name = domain_match.group(1) if domain_match else f"Verified Partner {i}"
            
            # Check if URL already exists before inserting
            try:
                exists = await pool.fetchval('''
                    SELECT EXISTS(SELECT 1 FROM verified_partners WHERE normalized_url = $1)
                ''', normalized)
                
                if exists:
                    print(f"URL already exists, skipping: {url}")
                else:
                    # Insert into the database
                    await pool.execute('''
                        INSERT INTO verified_partners 
                        (company_name, original_url, normalized_url, verification_date, category, notes) 
                        VALUES ($1, $2, $3, $4, $5, $6)
                    ''', company_name, url, normalized, today, 
                        "Trusted Website", f"From benign_qr_{i}.png")
                    
                    print(f"Added verified URL: {url}")
            except Exception as e:
                print(f"Error processing verified URL {url}: {e}")
        
        # Insert malicious URLs into malicious_urls table
        print(f"Adding {len(malicious_urls)} malicious URLs to database...")
        for i, url in enumerate(malicious_urls, 1):
            normalized = normalize_url(url)
            
            # Determine threat type based on URL patterns
            threat_type = "phishing"  # Default
            
            if "download" in url or ".exe" in url:
                threat_type = "malware"
            elif "free" in url or "gift" in url or "claim" in url:
                threat_type = "scam"
            
            # Check if URL already exists before inserting
            try:
                exists = await pool.fetchval('''
                    SELECT EXISTS(SELECT 1 FROM malicious_urls WHERE normalized_url = $1)
                ''', normalized)
                
                if exists:
                    print(f"Malicious URL already exists, skipping: {url}")
                else:
                    # Insert into the database
                    await pool.execute('''
                        INSERT INTO malicious_urls 
                        (original_url, normalized_url, threat_type, threat_details, reported_date, source) 
                        VALUES ($1, $2, $3, $4, $5, $6)
                    ''', url, normalized, threat_type, 
                        f"Detected from fake_malicious_{i}.png", 
                        today, "Internal QR analysis")
                    
                    print(f"Added malicious URL: {url}")
            except Exception as e:
                print(f"Error processing malicious URL {url}: {e}")
        
        # Verify the entries were added successfully
        verified_count = await pool.fetchval('SELECT COUNT(*) FROM verified_partners')
        malicious_count = await pool.fetchval('SELECT COUNT(*) FROM malicious_urls')
        
        print(f"\nDatabase now contains:")
        print(f"- {verified_count} verified partner URLs")
        print(f"- {malicious_count} malicious URLs")
        
        print("\nDatabase population complete!")
    
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the connection pool
        if 'pool' in locals():
            await pool.close()

# Run the async main function
if __name__ == "__main__":
    asyncio.run(populate_database())