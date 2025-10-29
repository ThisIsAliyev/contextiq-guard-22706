import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ArrowLeft, Clock, Trash2 } from 'lucide-react';
import { getHistory, clearHistory, EnrichmentHistory } from '@/lib/history';
import { toast } from 'sonner';

const History = () => {
  const [history, setHistory] = useState<EnrichmentHistory[]>([]);

  useEffect(() => {
    setHistory(getHistory());
  }, []);

  const handleClearHistory = () => {
    if (confirm('Are you sure you want to clear all history? This cannot be undone.')) {
      clearHistory();
      setHistory([]);
      toast.success('History cleared');
    }
  };

  const getScoreColor = (score: number): string => {
    if (score < 20) return 'text-risk-safe';
    if (score < 40) return 'text-risk-low';
    if (score < 60) return 'text-risk-medium';
    if (score < 80) return 'text-risk-high';
    return 'text-risk-critical';
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container max-w-6xl mx-auto px-4 py-8">
        <div className="mb-8 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link to="/">
              <Button variant="ghost" size="sm">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to Dashboard
              </Button>
            </Link>
          </div>
          {history.length > 0 && (
            <Button variant="destructive" size="sm" onClick={handleClearHistory}>
              <Trash2 className="mr-2 h-4 w-4" />
              Clear History
            </Button>
          )}
        </div>

        <div className="space-y-6">
          <div>
            <h1 className="text-4xl font-bold mb-2">Enrichment History</h1>
            <p className="text-muted-foreground">
              Your last {history.length} enrichment queries (max 100 stored locally)
            </p>
          </div>

          {history.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Clock className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <h3 className="text-lg font-semibold mb-2">No History Yet</h3>
                <p className="text-muted-foreground mb-4">
                  Start enriching indicators to build your history
                </p>
                <Link to="/">
                  <Button>Go to Dashboard</Button>
                </Link>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {history.map((entry) => (
                <Link key={entry.id} to={`/enrichment/${entry.id}`}>
                  <Card className="hover:border-primary/50 transition-smooth cursor-pointer">
                    <CardContent className="py-4">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-3 mb-2">
                            <code className="font-mono text-primary font-semibold">
                              {entry.indicator}
                            </code>
                            <Badge variant="outline">{entry.indicatorType}</Badge>
                            <span className={`font-mono font-bold ${getScoreColor(entry.contextScore)}`}>
                              {entry.contextScore}
                            </span>
                          </div>
                          <p className="text-sm text-muted-foreground line-clamp-2">
                            {entry.summary}
                          </p>
                        </div>
                        <div className="text-sm text-muted-foreground whitespace-nowrap">
                          {new Date(entry.timestamp).toLocaleString()}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default History;
