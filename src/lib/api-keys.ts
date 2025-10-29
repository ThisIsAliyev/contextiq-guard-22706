// API Key management for localStorage
export interface ApiKeys {
  whoisxml: string;
  virustotal: string;
  abuseipdb: string;
  shodan: string;
  hibp: string;
  supabase_url: string;
  supabase_anon_key: string;
}

const STORAGE_KEY = 'contextiq_api_keys';

export const saveApiKeys = (keys: ApiKeys): void => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
  } catch (error) {
    console.error('Failed to save API keys:', error);
    throw new Error('Failed to save API keys to browser storage');
  }
};

export const loadApiKeys = (): ApiKeys | null => {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return null;
    return JSON.parse(stored) as ApiKeys;
  } catch (error) {
    console.error('Failed to load API keys:', error);
    return null;
  }
};

export const clearApiKeys = (): void => {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (error) {
    console.error('Failed to clear API keys:', error);
  }
};

export const hasApiKeys = (): boolean => {
  const keys = loadApiKeys();
  if (!keys) return false;
  
  return Boolean(
    keys.whoisxml &&
    keys.virustotal &&
    keys.abuseipdb &&
    keys.shodan &&
    keys.hibp &&
    keys.supabase_url &&
    keys.supabase_anon_key
  );
};
