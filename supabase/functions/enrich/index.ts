import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface ApiKeys {
  whois_key: string;
  vt_key: string;
  abuse_key: string;
  shodan_key: string;
  hibp_key: string;
  gemini_key: string;
}

interface EnrichRequest {
  indicator_type: 'ip' | 'domain' | 'hash' | 'email';
  indicator_value: string;
  api_keys: ApiKeys;
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { indicator_type, indicator_value, api_keys }: EnrichRequest = await req.json();
    
    console.log(`Enriching ${indicator_type}: ${indicator_value}`);
    
    const rawData: any = {};
    
    // Conditional API calls based on indicator type
    if (indicator_type === 'ip') {
      // IP: Call WHOIS, AbuseIPDB, VirusTotal, Shodan
      const [whoisData, abuseData, vtData, shodanData] = await Promise.allSettled([
        fetchWhois(indicator_value, api_keys.whois_key),
        fetchAbuseIPDB(indicator_value, api_keys.abuse_key),
        fetchVirusTotal(indicator_value, 'ip', api_keys.vt_key),
        fetchShodan(indicator_value, api_keys.shodan_key),
      ]);
      
      if (whoisData.status === 'fulfilled') rawData.whoisxml = whoisData.value;
      if (abuseData.status === 'fulfilled') rawData.abuseipdb = abuseData.value;
      if (vtData.status === 'fulfilled') rawData.virustotal = vtData.value;
      if (shodanData.status === 'fulfilled') rawData.shodan = shodanData.value;
      
    } else if (indicator_type === 'domain') {
      // Domain: Call WHOIS, VirusTotal
      const [whoisData, vtData] = await Promise.allSettled([
        fetchWhois(indicator_value, api_keys.whois_key),
        fetchVirusTotal(indicator_value, 'domain', api_keys.vt_key),
      ]);
      
      if (whoisData.status === 'fulfilled') rawData.whoisxml = whoisData.value;
      if (vtData.status === 'fulfilled') rawData.virustotal = vtData.value;
      
    } else if (indicator_type === 'hash') {
      // Hash: Call VirusTotal only
      const vtData = await fetchVirusTotal(indicator_value, 'hash', api_keys.vt_key);
      rawData.virustotal = vtData;
      
    } else if (indicator_type === 'email') {
      // Email: Call HIBP, optionally VirusTotal
      const [hibpData] = await Promise.allSettled([
        fetchHIBP(indicator_value, api_keys.hibp_key),
      ]);
      
      if (hibpData.status === 'fulfilled') rawData.hibp = hibpData.value;
    }
    
    // Calculate dynamic score
    const contextScore = calculateScore(indicator_type, rawData);
    
    // Generate AI summary
    const { summary, recommendation } = await generateAISummary(
      indicator_type,
      indicator_value,
      rawData,
      contextScore,
      api_keys.gemini_key
    );
    
    const response = {
      indicator: indicator_value,
      indicatorType: indicator_type,
      contextScore,
      summary,
      recommendation,
      rawData,
    };
    
    console.log(`Enrichment complete. Score: ${contextScore}`);
    
    return new Response(JSON.stringify(response), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
    
  } catch (error) {
    console.error('Error in enrich function:', error);
    return new Response(JSON.stringify({ error: error instanceof Error ? error.message : 'Unknown error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

async function fetchWhois(indicator: string, apiKey: string) {
  const url = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${indicator}&outputFormat=JSON`;
  const response = await fetch(url);
  const data = await response.json();
  
  return {
    createdDate: data.WhoisRecord?.createdDate || 'Unknown',
    registrarName: data.WhoisRecord?.registrarName || 'Unknown',
    asn: data.WhoisRecord?.registryData?.nameServers?.[0] || 'Unknown',
  };
}

async function fetchAbuseIPDB(ip: string, apiKey: string) {
  const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
    headers: { 'Key': apiKey, 'Accept': 'application/json' },
  });
  const data = await response.json();
  
  return {
    abuseConfidenceScore: data.data?.abuseConfidenceScore || 0,
    totalReports: data.data?.totalReports || 0,
    countryCode: data.data?.countryCode || 'Unknown',
    isp: data.data?.isp || 'Unknown',
  };
}

async function fetchVirusTotal(indicator: string, type: 'ip' | 'domain' | 'hash', apiKey: string) {
  let url = '';
  if (type === 'ip') {
    url = `https://www.virustotal.com/api/v3/ip_addresses/${indicator}`;
  } else if (type === 'domain') {
    url = `https://www.virustotal.com/api/v3/domains/${indicator}`;
  } else if (type === 'hash') {
    url = `https://www.virustotal.com/api/v3/files/${indicator}`;
  }
  
  const response = await fetch(url, {
    headers: { 'x-apikey': apiKey },
  });
  const data = await response.json();
  
  return {
    malicious: data.data?.attributes?.last_analysis_stats?.malicious || 0,
    suspicious: data.data?.attributes?.last_analysis_stats?.suspicious || 0,
    reputation: data.data?.attributes?.reputation || 0,
  };
}

async function fetchShodan(ip: string, apiKey: string) {
  const response = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
  const data = await response.json();
  
  return {
    ports: data.ports || [],
    vulns: data.vulns ? Object.keys(data.vulns).length > 0 : false,
    org: data.org || 'Unknown',
  };
}

async function fetchHIBP(email: string, apiKey: string) {
  const response = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${email}`, {
    headers: { 'hibp-api-key': apiKey, 'user-agent': 'ContextIQ' },
  });
  
  if (response.status === 404) {
    return { breaches: 0, breachNames: [] };
  }
  
  const data = await response.json();
  return {
    breaches: data.length || 0,
    breachNames: data.map((b: any) => b.Name) || [],
  };
}

function calculateScore(type: string, rawData: any): number {
  if (type === 'ip') {
    const vtMalicious = rawData.virustotal?.malicious || 0;
    const vtSuspicious = rawData.virustotal?.suspicious || 0;
    const abuseScore = rawData.abuseipdb?.abuseConfidenceScore || 0;
    const hasVulns = rawData.shodan?.vulns || false;
    const openPorts = rawData.shodan?.ports?.length || 0;
    
    const scoreVT = (vtMalicious > 0 ? 0.8 : 0) + (vtSuspicious > 0 ? 0.2 : 0);
    const scoreAbuse = abuseScore / 100.0;
    const scoreShodan = (hasVulns ? 0.8 : 0) + (Math.min(openPorts, 10) / 10 * 0.2);
    
    return Math.round((scoreVT * 40) + (scoreAbuse * 35) + (scoreShodan * 25));
    
  } else if (type === 'domain') {
    const vtMalicious = rawData.virustotal?.malicious || 0;
    const vtSuspicious = rawData.virustotal?.suspicious || 0;
    
    const scoreVT = (vtMalicious > 0 ? 0.8 : 0) + (vtSuspicious > 0 ? 0.2 : 0);
    return Math.round(scoreVT * 100);
    
  } else if (type === 'hash') {
    const vtMalicious = rawData.virustotal?.malicious || 0;
    const vtSuspicious = rawData.virustotal?.suspicious || 0;
    
    const scoreVT = (vtMalicious > 0 ? 0.9 : 0) + (vtSuspicious > 0 ? 0.1 : 0);
    return Math.round(scoreVT * 100);
    
  } else if (type === 'email') {
    const breaches = rawData.hibp?.breaches || 0;
    const score = Math.min(breaches * 15, 100);
    return Math.round(score);
  }
  
  return 0;
}

async function generateAISummary(
  type: string,
  indicator: string,
  rawData: any,
  score: number,
  geminiKey: string
): Promise<{ summary: string; recommendation: string }> {
  const prompt = `You are a cybersecurity analyst. Analyze this ${type} indicator: ${indicator}

Context Score: ${score}/100
Raw Data: ${JSON.stringify(rawData, null, 2)}

Provide:
1. A concise 2-3 sentence summary of the threat level and key findings
2. A clear, actionable recommendation (one sentence)

Format your response as:
SUMMARY: [your summary]
RECOMMENDATION: [your recommendation]`;

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${geminiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
        }),
      }
    );
    
    const data = await response.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    
    const summaryMatch = text.match(/SUMMARY:\s*(.+?)(?=RECOMMENDATION:|$)/s);
    const recommendationMatch = text.match(/RECOMMENDATION:\s*(.+?)$/s);
    
    return {
      summary: summaryMatch?.[1]?.trim() || 'AI summary unavailable',
      recommendation: recommendationMatch?.[1]?.trim() || 'Review manually',
    };
  } catch (error) {
    console.error('Gemini API error:', error);
    return {
      summary: `Score: ${score}/100. Manual review required.`,
      recommendation: 'Unable to generate AI recommendation. Review data manually.',
    };
  }
}
