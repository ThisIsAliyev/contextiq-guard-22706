import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface TestKeyRequest {
  service: 'whoisxml' | 'virustotal' | 'abuseipdb' | 'shodan' | 'hibp' | 'gemini';
  api_key: string;
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { service, api_key }: TestKeyRequest = await req.json();
    
    console.log(`Testing ${service} API key`);
    
    let success = false;
    let error = '';
    
    try {
      switch (service) {
        case 'whoisxml':
          success = await testWhoisXML(api_key);
          break;
        case 'virustotal':
          success = await testVirusTotal(api_key);
          break;
        case 'abuseipdb':
          success = await testAbuseIPDB(api_key);
          break;
        case 'shodan':
          success = await testShodan(api_key);
          break;
        case 'hibp':
          success = await testHIBP(api_key);
          break;
        case 'gemini':
          success = await testGemini(api_key);
          break;
        default:
          error = 'Unknown service';
      }
    } catch (e) {
      error = e instanceof Error ? e.message : 'Unknown error';
    }
    
    return new Response(JSON.stringify({ success, error }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
    
  } catch (error) {
    console.error('Error in test-key function:', error);
    return new Response(JSON.stringify({ success: false, error: error instanceof Error ? error.message : 'Unknown error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

async function testWhoisXML(apiKey: string): Promise<boolean> {
  const response = await fetch(
    `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=google.com&outputFormat=JSON`
  );
  return response.ok;
}

async function testVirusTotal(apiKey: string): Promise<boolean> {
  const response = await fetch('https://www.virustotal.com/api/v3/domains/google.com', {
    headers: { 'x-apikey': apiKey },
  });
  return response.ok;
}

async function testAbuseIPDB(apiKey: string): Promise<boolean> {
  const response = await fetch('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8', {
    headers: { 'Key': apiKey, 'Accept': 'application/json' },
  });
  return response.ok;
}

async function testShodan(apiKey: string): Promise<boolean> {
  const response = await fetch(`https://api.shodan.io/api-info?key=${apiKey}`);
  return response.ok;
}

async function testHIBP(apiKey: string): Promise<boolean> {
  const response = await fetch('https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com', {
    headers: { 'hibp-api-key': apiKey, 'user-agent': 'ContextIQ' },
  });
  // 404 is OK for HIBP (means no breaches)
  return response.ok || response.status === 404;
}

async function testGemini(apiKey: string): Promise<boolean> {
  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${apiKey}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: 'test' }] }],
      }),
    }
  );
  return response.ok;
}
