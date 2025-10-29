import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ScoreGauge } from './ScoreGauge';
import { Badge } from '@/components/ui/badge';
import { Sparkles, FileCode, BookOpen } from 'lucide-react';

interface EnrichmentResult {
  indicator: string;
  indicatorType: string;
  contextScore: number;
  summary: string;
  recommendation: string;
  rawData: {
    abuseipdb?: any;
    virustotal?: any;
    shodan?: any;
    whoisxml?: any;
    hibp?: any;
  };
}

interface EnrichmentViewerProps {
  result: EnrichmentResult;
}

export const EnrichmentViewer = ({ result }: EnrichmentViewerProps) => {
  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row gap-6 items-start">
        <div className="flex-shrink-0">
          <ScoreGauge score={result.contextScore} size="lg" />
        </div>

        <Card className="flex-1">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-primary" />
              <CardTitle>AI Summary</CardTitle>
            </div>
            <CardDescription>
              Analyzed indicator:{' '}
              <code className="font-mono text-primary">{result.indicator}</code>
              <Badge variant="outline" className="ml-2">
                {result.indicatorType}
              </Badge>
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h4 className="font-semibold mb-2 text-foreground">Summary</h4>
              <p className="text-muted-foreground leading-relaxed">{result.summary}</p>
            </div>
            <div>
              <h4 className="font-semibold mb-2 text-foreground">Recommendation</h4>
              <p className="text-primary font-medium">{result.recommendation}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="overview">
            <BookOpen className="h-4 w-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="raw">
            <FileCode className="h-4 w-4 mr-2" />
            Raw Data
          </TabsTrigger>
          <TabsTrigger value="playbooks">Playbooks</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {result.rawData.abuseipdb && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">AbuseIPDB</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Confidence Score:</span>
                    <span className="font-mono font-semibold">
                      {result.rawData.abuseipdb.abuseConfidenceScore || 'N/A'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Total Reports:</span>
                    <span className="font-mono">{result.rawData.abuseipdb.totalReports || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Country:</span>
                    <span className="font-mono">{result.rawData.abuseipdb.countryCode || 'N/A'}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {result.rawData.virustotal && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">VirusTotal</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Malicious:</span>
                    <span className="font-mono text-risk-critical font-semibold">
                      {result.rawData.virustotal.malicious || 0}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Suspicious:</span>
                    <span className="font-mono text-risk-medium">
                      {result.rawData.virustotal.suspicious || 0}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Reputation:</span>
                    <span className="font-mono">{result.rawData.virustotal.reputation || 'N/A'}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {result.rawData.shodan && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Shodan</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Open Ports:</span>
                    <span className="font-mono">{result.rawData.shodan.ports?.length || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Vulnerabilities:</span>
                    <span className="font-mono text-risk-high">
                      {result.rawData.shodan.vulns ? 'Yes' : 'No'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Organization:</span>
                    <span className="font-mono text-xs">{result.rawData.shodan.org || 'N/A'}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {result.rawData.whoisxml && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">WHOIS</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Created Date:</span>
                    <span className="font-mono text-xs">{result.rawData.whoisxml.createdDate || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Registrar:</span>
                    <span className="font-mono text-xs">{result.rawData.whoisxml.registrarName || 'N/A'}</span>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>

        <TabsContent value="raw">
          <Card>
            <CardHeader>
              <CardTitle>Raw JSON Response</CardTitle>
              <CardDescription>Complete enrichment data from all sources</CardDescription>
            </CardHeader>
            <CardContent>
              <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-xs font-mono">
                {JSON.stringify(result, null, 2)}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="playbooks">
          <Card>
            <CardHeader>
              <CardTitle>Response Playbooks</CardTitle>
              <CardDescription>Suggested actions based on threat level</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-muted-foreground">
                Response playbooks will be displayed here based on the context score and threat
                indicators.
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};
