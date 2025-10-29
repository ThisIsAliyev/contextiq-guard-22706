import { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ScoreGauge } from './ScoreGauge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Sparkles, FileCode, BookOpen, Maximize2, Download } from 'lucide-react';
import { toast } from 'sonner';

interface EnrichmentResult {
  indicator: string;
  indicatorType: string;
  contextScore: number;
  summary: string;
  recommendation: string;
  scoreDetails?: string[];
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
  const [expandedTool, setExpandedTool] = useState<string | null>(null);

  const downloadJSON = (data: any, filename: string) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success(`Downloaded ${filename}`);
  };

  const ExpandedToolView = ({ tool, data }: { tool: string; data: any }) => {
    if (!data) return <p className="text-muted-foreground">No data available</p>;

    return (
      <div className="space-y-4">
        <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-xs font-mono max-h-96">
          {JSON.stringify(data, null, 2)}
        </pre>
        <Button
          variant="outline"
          onClick={() => downloadJSON(data, `${tool}-${result.indicator}.json`)}
          className="w-full"
        >
          <Download className="mr-2 h-4 w-4" />
          Download {tool} JSON
        </Button>
      </div>
    );
  };

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
            {result.scoreDetails && result.scoreDetails.length > 0 && (
              <div>
                <h4 className="font-semibold mb-2 text-foreground">Score Rationale</h4>
                <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground">
                  {result.scoreDetails.map((detail, idx) => (
                    <li key={idx}>{detail}</li>
                  ))}
                </ul>
              </div>
            )}
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
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">AbuseIPDB</CardTitle>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setExpandedTool('abuseipdb')}
                    >
                      <Maximize2 className="h-4 w-4" />
                    </Button>
                  </div>
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
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">VirusTotal</CardTitle>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setExpandedTool('virustotal')}
                    >
                      <Maximize2 className="h-4 w-4" />
                    </Button>
                  </div>
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
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">Shodan</CardTitle>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setExpandedTool('shodan')}
                    >
                      <Maximize2 className="h-4 w-4" />
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Open Ports:</span>
                    <span className="font-mono">{result.rawData.shodan.ports?.length || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Vulnerabilities:</span>
                    <span className="font-mono text-risk-high">
                      {result.rawData.shodan.vulns?.length || 0}
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
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">WHOIS</CardTitle>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setExpandedTool('whoisxml')}
                    >
                      <Maximize2 className="h-4 w-4" />
                    </Button>
                  </div>
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
                  {result.rawData.whoisxml.ageDays !== null && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Domain Age:</span>
                      <span className="font-mono text-xs">{result.rawData.whoisxml.ageDays} days</span>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {result.rawData.hibp && (
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">Have I Been Pwned</CardTitle>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setExpandedTool('hibp')}
                    >
                      <Maximize2 className="h-4 w-4" />
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Data Breaches:</span>
                    <span className="font-mono text-risk-critical font-semibold">
                      {result.rawData.hibp.breaches || 0}
                    </span>
                  </div>
                  {result.rawData.hibp.breachNames && result.rawData.hibp.breachNames.length > 0 && (
                    <div className="pt-2">
                      <span className="text-muted-foreground text-xs">Breach Sites:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {result.rawData.hibp.breachNames.slice(0, 3).map((name: string, idx: number) => (
                          <Badge key={idx} variant="destructive" className="text-xs">
                            {name}
                          </Badge>
                        ))}
                        {result.rawData.hibp.breachNames.length > 3 && (
                          <Badge variant="outline" className="text-xs">
                            +{result.rawData.hibp.breachNames.length - 3} more
                          </Badge>
                        )}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>

        <TabsContent value="raw">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Raw JSON Response</CardTitle>
                  <CardDescription>Complete enrichment data from all sources</CardDescription>
                </div>
                <Button
                  variant="outline"
                  onClick={() => downloadJSON(result, `enrichment-${result.indicator}.json`)}
                >
                  <Download className="mr-2 h-4 w-4" />
                  Download Full Report
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-xs font-mono max-h-96">
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

      {/* Expanded Tool Dialog */}
      <Dialog open={expandedTool !== null} onOpenChange={() => setExpandedTool(null)}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {expandedTool && expandedTool.charAt(0).toUpperCase() + expandedTool.slice(1)} - Detailed View
            </DialogTitle>
            <DialogDescription>
              Complete raw data from {expandedTool}
            </DialogDescription>
          </DialogHeader>
          {expandedTool && (
            <ExpandedToolView
              tool={expandedTool}
              data={result.rawData[expandedTool as keyof typeof result.rawData]}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};
