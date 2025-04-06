
-- Create tables for the QR Safe database
CREATE TABLE verified_partners (
  id SERIAL PRIMARY KEY,
  company_name VARCHAR(255) NOT NULL,
  original_url TEXT NOT NULL,
  normalized_url TEXT NOT NULL UNIQUE,
  verification_date DATE NOT NULL,
  logo_url TEXT,
  category VARCHAR(50),
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE malicious_urls (
  id SERIAL PRIMARY KEY,
  original_url TEXT NOT NULL,
  normalized_url TEXT NOT NULL UNIQUE,
  threat_type VARCHAR(50) NOT NULL,
  threat_details TEXT,
  reported_date DATE NOT NULL,
  confirmed BOOLEAN DEFAULT TRUE,
  source VARCHAR(100),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scan_history (
  id SERIAL PRIMARY KEY,
  scan_url TEXT NOT NULL,
  normalized_url TEXT NOT NULL,
  scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  ip_address VARCHAR(45),
  device_info TEXT,
  verified_result BOOLEAN,
  web_search_result VARCHAR(50),
  user_action VARCHAR(50)
);

CREATE INDEX idx_verified_normalized_url ON verified_partners(normalized_url);
CREATE INDEX idx_malicious_normalized_url ON malicious_urls(normalized_url);
