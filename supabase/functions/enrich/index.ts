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
  supabase_url: string;
  supabase_anon_key: string;
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
    
    // Calculate dynamic score with new algorithm
    const { score: contextScore, details: scoreDetails } = calculateScore(indicator_type, rawData);
    
    // Generate AI summary via Supabase
    let summary = 'AI summary unavailable';
    let recommendation = 'Review manually';
    
    try {
      const aiResponse = await fetch(`${api_keys.supabase_url}/functions/v1/contextiq-summarizer`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${api_keys.supabase_anon_key}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          indicator_value,
          indicator_type,
          context_score: contextScore,
          raw_data: rawData,
          score_details: scoreDetails,
        }),
      });
      
      if (aiResponse.ok) {
        const aiData = await aiResponse.json();
        summary = aiData.summary || summary;
        recommendation = aiData.recommendation || recommendation;
      } else {
        console.error('Supabase AI call failed:', await aiResponse.text());
      }
    } catch (aiError) {
      console.error('AI summary error:', aiError);
    }
    
    const response = {
      indicator: indicator_value,
      indicatorType: indicator_type,
      contextScore,
      scoreDetails,
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
  
  // Calculate domain age
  let ageDays = null;
  if (data.WhoisRecord?.createdDate) {
    const created = new Date(data.WhoisRecord.createdDate);
    const now = new Date();
    ageDays = Math.floor((now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24));
  }
  
  return {
    createdDate: data.WhoisRecord?.createdDate || 'Unknown',
    registrarName: data.WhoisRecord?.registrarName || 'Unknown',
    asn: data.WhoisRecord?.registryData?.nameServers?.[0] || 'Unknown',
    ageDays,
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
  
  const vulns = data.vulns ? Object.keys(data.vulns) : [];
  
  return {
    ports: data.ports || [],
    vulns: vulns,
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

function calculateScore(type: string, rawData: any): { score: number; details: string[] } {
  let score = 0;
  const details: string[] = [];
  
  if (type === 'ip') {
    // 1. VirusTotal
    const vtMalicious = rawData.virustotal?.malicious || 0;
    const vtSuspicious = rawData.virustotal?.suspicious || 0;
    
    if (vtMalicious >= 6) {
      score += 60;
      details.push(`VirusTotal: High detection rate (${vtMalicious} vendors flagged as malicious)`);
    } else if (vtMalicious >= 2) {
      score += 30;
      details.push(`VirusTotal: Medium detection rate (${vtMalicious} vendors flagged as malicious)`);
    } else if (vtMalicious === 1) {
      score += 15;
      details.push(`VirusTotal: Low detection rate (1 vendor flagged as malicious)`);
    }
    
    if (vtSuspicious > 0 && vtMalicious === 0) {
      score += 5;
      details.push(`VirusTotal: ${vtSuspicious} vendors flagged as suspicious`);
    }
    
    // 2. AbuseIPDB
    const abuseScore = rawData.abuseipdb?.abuseConfidenceScore || 0;
    
    if (abuseScore >= 76) {
      score += 25;
      details.push(`AbuseIPDB: High confidence of abuse (${abuseScore}%)`);
    } else if (abuseScore >= 50) {
      score += 10;
      details.push(`AbuseIPDB: Medium confidence of abuse (${abuseScore}%)`);
    } else if (abuseScore > 0) {
      details.push(`AbuseIPDB: Low abuse score (${abuseScore}%)`);
    }
    
    // 3. Shodan
    const vulnCount = rawData.shodan?.vulns?.length || 0;
    const portCount = rawData.shodan?.ports?.length || 0;
    
    if (vulnCount >= 3) {
      score += 25;
      details.push(`Shodan: ${vulnCount} known vulnerabilities detected`);
    } else if (vulnCount >= 1) {
      score += 10;
      details.push(`Shodan: ${vulnCount} known vulnerabilit${vulnCount === 1 ? 'y' : 'ies'} detected`);
    }
    
    if (portCount > 10) {
      score += 5;
      details.push(`Shodan: High number of open ports (${portCount})`);
    } else if (portCount > 0) {
      details.push(`Shodan: ${portCount} open ports detected`);
    }
    
  } else if (type === 'domain') {
    // Domain scoring
    const vtMalicious = rawData.virustotal?.malicious || 0;
    const vtSuspicious = rawData.virustotal?.suspicious || 0;
    
    if (vtMalicious >= 6) {
      score += 80;
      details.push(`VirusTotal: High detection rate (${vtMalicious} vendors)`);
    } else if (vtMalicious >= 2) {
      score += 40;
      details.push(`VirusTotal: Medium detection rate (${vtMalicious} vendors)`);
    } else if (vtMalicious === 1) {
      score += 20;
      details.push(`VirusTotal: Low detection rate (1 vendor)`);
    }
    
    if (vtSuspicious > 0 && vtMalicious === 0) {
      score += 10;
      details.push(`VirusTotal: ${vtSuspicious} vendors flagged as suspicious`);
    }
    
    // WHOIS age check
    const ageDays = rawData.whoisxml?.ageDays;
    if (ageDays !== null && ageDays < 90) {
      score += 20;
      details.push(`WHOIS: Newly registered domain (${ageDays} days old)`);
    } else if (ageDays !== null) {
      details.push(`WHOIS: Domain age: ${ageDays} days`);
    }
    
  } else if (type === 'hash') {
    // Hash scoring
    const vtMalicious = rawData.virustotal?.malicious || 0;
    const vtSuspicious = rawData.virustotal?.suspicious || 0;
    
    if (vtMalicious >= 10) {
      score += 90;
      details.push(`VirusTotal: Very high detection rate (${vtMalicious} vendors)`);
    } else if (vtMalicious >= 5) {
      score += 70;
      details.push(`VirusTotal: High detection rate (${vtMalicious} vendors)`);
    } else if (vtMalicious >= 1) {
      score += 40;
      details.push(`VirusTotal: Low detection rate (${vtMalicious} vendors)`);
    }
    
    if (vtSuspicious > 0) {
      score += 10;
      details.push(`VirusTotal: ${vtSuspicious} vendors flagged as suspicious`);
    }
    
  } else if (type === 'email') {
    // Email scoring
    const breaches = rawData.hibp?.breaches || 0;
    
    if (breaches >= 5) {
      score += 70;
      details.push(`HaveIBeenPwned: Email found in ${breaches} data breaches`);
    } else if (breaches >= 2) {
      score += 40;
      details.push(`HaveIBeenPwned: Email found in ${breaches} data breaches`);
    } else if (breaches === 1) {
      score += 20;
      details.push(`HaveIBeenPwned: Email found in 1 data breach`);
    }
  }
  
  // Add a baseline message if no threats found
  if (details.length === 0) {
    details.push('No significant threats detected across all sources');
  }
  
  return {
    score: Math.min(score, 100),
    details,
  };
}
