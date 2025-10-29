import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Settings, History, Search, Shield, Zap, Brain } from 'lucide-react';
import { hasApiKeys, loadApiKeys } from '@/lib/api-keys';
import { saveToHistory } from '@/lib/history';
import { EnrichmentViewer } from '@/components/EnrichmentViewer';
import { toast } from 'sonner';

const Index = () => {
  const [indicator, setIndicator] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const detectIndicatorType = (value: string): 'ip' | 'domain' | 'hash' | 'email' | null => {
    // IP address (simple IPv4)
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
    
    // Email
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'email';
    
    // Hash (MD5, SHA1, SHA256)
    if (/^[a-fA-F0-9]{32}$/.test(value)) return 'hash'; // MD5
    if (/^[a-fA-F0-9]{40}$/.test(value)) return 'hash'; // SHA1
    if (/^[a-fA-F0-9]{64}$/.test(value)) return 'hash'; // SHA256
    
    // Domain (basic check)
    if (/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/.test(value)) return 'domain';
    
    return null;
  };

  const handleEnrich = async () => {
    if (!indicator.trim()) {
      toast.error('Please enter an indicator');
      return;
    }

    const indicatorType = detectIndicatorType(indicator.trim());
    if (!indicatorType) {
      toast.error('Invalid indicator format', {
        description: 'Please enter a valid IP, domain, email, or file hash',
      });
      return;
    }

    if (!hasApiKeys()) {
      toast.error('API keys not configured', {
        description: 'Please configure your API keys in Settings first.',
        action: {
          label: 'Go to Settings',
          onClick: () => window.location.href = '/settings',
        },
      });
      return;
    }

    setIsLoading(true);
    
    try {
      const keys = loadApiKeys();
      const response = await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/enrich`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          indicator_type: indicatorType,
          indicator_value: indicator.trim(),
          api_keys: {
            whois_key: keys?.whoisxml || '',
            vt_key: keys?.virustotal || '',
            abuse_key: keys?.abuseipdb || '',
            shodan_key: keys?.shodan || '',
            hibp_key: keys?.hibp || '',
            gemini_key: keys?.gemini || '',
          },
        }),
      });

      if (!response.ok) {
        throw new Error('Enrichment failed');
      }

      const data = await response.json();
      setResult(data);
      
      // Save to history
      saveToHistory({
        indicator: data.indicator,
        indicatorType: data.indicatorType,
        contextScore: data.contextScore,
        summary: data.summary,
      });
      
      toast.success('Enrichment complete');
    } catch (error) {
      console.error('Enrichment error:', error);
      toast.error('Enrichment failed', {
        description: 'Please check your API keys and try again',
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border/50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-primary" />
              <div>
                <h1 className="text-2xl font-bold">ContextIQ</h1>
                <p className="text-sm text-muted-foreground">Threat Intelligence Aggregator</p>
              </div>
            </div>
            <div className="flex gap-2">
              <Link to="/history">
                <Button variant="outline" size="sm">
                  <History className="mr-2 h-4 w-4" />
                  History
                </Button>
              </Link>
              <Link to="/settings">
                <Button variant="outline" size="sm">
                  <Settings className="mr-2 h-4 w-4" />
                  Settings
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </header>

      <div className="container max-w-7xl mx-auto px-4 py-12">
        {!result ? (
          <div className="max-w-3xl mx-auto space-y-8">
            {/* Hero Section */}
            <div className="text-center space-y-4">
              <h2 className="text-5xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                Enrich Threat Indicators
              </h2>
              <p className="text-xl text-muted-foreground">
                Query 6 threat intelligence sources instantly. Get AI-powered summaries and
                actionable recommendations.
              </p>
            </div>

            {/* Search Card */}
            <Card className="border-primary/20 shadow-lg">
              <CardHeader>
                <CardTitle>Enter Indicator</CardTitle>
                <CardDescription>
                  IP address, domain, file hash, or email address
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  <Input
                    placeholder="e.g., 198.51.100.23 or example.com"
                    value={indicator}
                    onChange={(e) => setIndicator(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleEnrich()}
                    className="font-mono text-lg"
                    disabled={isLoading}
                  />
                  <Button
                    onClick={handleEnrich}
                    disabled={isLoading}
                    size="lg"
                    className="px-8"
                  >
                    {isLoading ? (
                      <>
                        <div className="animate-spin mr-2 h-4 w-4 border-2 border-current border-t-transparent rounded-full" />
                        Enriching...
                      </>
                    ) : (
                      <>
                        <Search className="mr-2 h-4 w-4" />
                        Enrich
                      </>
                    )}
                  </Button>
                </div>

                {!hasApiKeys() && (
                  <Alert variant="default" className="border-primary/50">
                    <Settings className="h-4 w-4" />
                    <AlertDescription className="ml-2">
                      You need to configure your API keys first.{' '}
                      <Link to="/settings" className="font-semibold text-primary hover:underline">
                        Go to Settings →
                      </Link>
                    </AlertDescription>
                  </Alert>
                )}
              </CardContent>
            </Card>

            {/* Features Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-8">
              <Card>
                <CardHeader>
                  <Zap className="h-8 w-8 text-primary mb-2" />
                  <CardTitle className="text-lg">Lightning Fast</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">
                    Query 6 threat intel sources in parallel. Get results in seconds, not minutes.
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <Brain className="h-8 w-8 text-primary mb-2" />
                  <CardTitle className="text-lg">AI-Powered</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">
                    Gemini AI analyzes all data and provides clear, actionable summaries.
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <Shield className="h-8 w-8 text-primary mb-2" />
                  <CardTitle className="text-lg">Privacy First</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">
                    Your API keys never leave your browser. Stateless backend ensures privacy.
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            <Button variant="outline" onClick={() => setResult(null)}>
              ← New Search
            </Button>
            <EnrichmentViewer result={result} />
          </div>
        )}
      </div>
    </div>
  );
};

export default Index;
