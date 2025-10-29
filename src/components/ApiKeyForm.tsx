import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Eye, EyeOff, Save, Shield, Check, X, Loader2, AlertTriangle } from 'lucide-react';
import { saveApiKeys, loadApiKeys, type ApiKeys } from '@/lib/api-keys';
import { toast } from 'sonner';

export const ApiKeyForm = () => {
  const [keys, setKeys] = useState<ApiKeys>(() => {
    return loadApiKeys() || {
      whoisxml: '',
      virustotal: '',
      abuseipdb: '',
      shodan: '',
      hibp: '',
      gemini: '',
    };
  });

  const [showKeys, setShowKeys] = useState<Record<keyof ApiKeys, boolean>>({
    whoisxml: false,
    virustotal: false,
    abuseipdb: false,
    shodan: false,
    hibp: false,
    gemini: false,
  });

  const [testStatus, setTestStatus] = useState<Record<keyof ApiKeys, 'idle' | 'testing' | 'valid' | 'invalid'>>({
    whoisxml: 'idle',
    virustotal: 'idle',
    abuseipdb: 'idle',
    shodan: 'idle',
    hibp: 'idle',
    gemini: 'idle',
  });

  useEffect(() => {
    const loaded = loadApiKeys();
    if (loaded) {
      setKeys(loaded);
    }
  }, []);

  const handleSave = () => {
    try {
      saveApiKeys(keys);
      toast.success('API keys saved successfully');
    } catch (error) {
      toast.error('Failed to save API keys');
    }
  };

  const handleTestKey = async (service: keyof ApiKeys) => {
    const keyMap: Record<keyof ApiKeys, string> = {
      whoisxml: 'whoisxml',
      virustotal: 'virustotal',
      abuseipdb: 'abuseipdb',
      shodan: 'shodan',
      hibp: 'hibp',
      gemini: 'gemini',
    };

    const apiKey = keys[service];
    if (!apiKey) {
      toast.error('Please enter an API key first');
      return;
    }

    setTestStatus(prev => ({ ...prev, [service]: 'testing' }));

    try {
      const response = await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/test-key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          service: keyMap[service],
          api_key: apiKey,
        }),
      });

      const data = await response.json();

      if (data.success) {
        setTestStatus(prev => ({ ...prev, [service]: 'valid' }));
        toast.success(`${service} API key is valid`);
      } else {
        setTestStatus(prev => ({ ...prev, [service]: 'invalid' }));
        toast.error(`${service} API key is invalid`);
      }
    } catch (error) {
      setTestStatus(prev => ({ ...prev, [service]: 'invalid' }));
      toast.error(`Failed to test ${service} key`);
    }
  };

  const apiKeyFields: Array<{
    key: keyof ApiKeys;
    label: string;
    description: string;
    link: string;
  }> = [
    {
      key: 'whoisxml',
      label: 'WHOISXML API Key',
      description: 'For domain age & registrar analysis',
      link: 'https://whoisxmlapi.com/',
    },
    {
      key: 'virustotal',
      label: 'VirusTotal API Key',
      description: 'For malware/threat analysis',
      link: 'https://www.virustotal.com/gui/my-apikey',
    },
    {
      key: 'abuseipdb',
      label: 'AbuseIPDB API Key',
      description: 'For IP reputation checks',
      link: 'https://www.abuseipdb.com/account/api',
    },
    {
      key: 'shodan',
      label: 'Shodan API Key',
      description: 'For external exposure scanning',
      link: 'https://account.shodan.io/',
    },
    {
      key: 'hibp',
      label: 'Have I Been Pwned API Key',
      description: 'For email breach discovery',
      link: 'https://haveibeenpwned.com/API/Key',
    },
    {
      key: 'gemini',
      label: 'Google Gemini API Key',
      description: 'For AI-powered summaries',
      link: 'https://makersuite.google.com/app/apikey',
    },
  ];

  return (
    <div className="space-y-6">
      <Alert variant="default" className="border-primary/50 bg-primary/5">
        <Shield className="h-4 w-4" />
        <AlertDescription className="ml-2">
          <strong>Privacy Notice:</strong> Your API keys are stored only in your browser's
          localStorage and are never sent to our servers for storage. They are transmitted
          securely with each enrichment request and immediately discarded after use.
        </AlertDescription>
      </Alert>

      <Alert variant="destructive" className="border-destructive/50">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription className="ml-2">
          <strong>Security Warning:</strong> Do not use this application on public or shared
          computers. Anyone with access to your browser can read your stored API keys.
        </AlertDescription>
      </Alert>

      {apiKeyFields.map(({ key, label, description, link }) => (
        <Card key={key}>
          <CardHeader>
            <CardTitle className="text-lg">{label}</CardTitle>
            <CardDescription>
              {description} •{' '}
              <a
                href={link}
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline"
              >
                Get API Key
              </a>
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="relative">
              <Label htmlFor={key} className="sr-only">
                {label}
              </Label>
              <Input
                id={key}
                type={showKeys[key] ? 'text' : 'password'}
                value={keys[key]}
                onChange={(e) => setKeys(prev => ({ ...prev, [key]: e.target.value }))}
                placeholder={`Enter your ${label.toLowerCase()}`}
                className="font-mono pr-20"
              />
              <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-2">
                {testStatus[key] === 'valid' && <Check className="h-4 w-4 text-risk-safe" />}
                {testStatus[key] === 'invalid' && <X className="h-4 w-4 text-risk-critical" />}
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowKeys(prev => ({ ...prev, [key]: !prev[key] }))}
                >
                  {showKeys[key] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
            </div>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => handleTestKey(key)}
              disabled={testStatus[key] === 'testing'}
            >
              {testStatus[key] === 'testing' ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Testing...
                </>
              ) : (
                'Test Key'
              )}
            </Button>
          </CardContent>
        </Card>
      ))}

      <Button onClick={handleSave} className="w-full" size="lg">
        <Save className="mr-2 h-4 w-4" />
        Save API Keys to Browser
      </Button>
    </div>
  );
};
