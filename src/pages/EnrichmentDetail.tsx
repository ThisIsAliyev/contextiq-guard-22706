import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { ArrowLeft } from 'lucide-react';
import { getHistoryEntry, EnrichmentHistory } from '@/lib/history';
import { EnrichmentViewer } from '@/components/EnrichmentViewer';

const EnrichmentDetail = () => {
  const { id } = useParams<{ id: string }>();
  const [entry, setEntry] = useState<EnrichmentHistory | null>(null);

  useEffect(() => {
    if (id) {
      const found = getHistoryEntry(id);
      setEntry(found);
    }
  }, [id]);

  if (!entry) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold mb-4">Enrichment Not Found</h2>
          <Link to="/history">
            <Button>Back to History</Button>
          </Link>
        </div>
      </div>
    );
  }

  // Transform history entry to match EnrichmentViewer props
  const result = {
    indicator: entry.indicator,
    indicatorType: entry.indicatorType,
    contextScore: entry.contextScore,
    summary: entry.summary,
    recommendation: 'See full enrichment details below',
    rawData: {},
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container max-w-7xl mx-auto px-4 py-8">
        <div className="mb-8">
          <Link to="/history">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to History
            </Button>
          </Link>
        </div>

        <div className="space-y-6">
          <div>
            <h1 className="text-3xl font-bold mb-2">Enrichment Details</h1>
            <p className="text-muted-foreground">
              Analyzed on {new Date(entry.timestamp).toLocaleString()}
            </p>
          </div>

          <EnrichmentViewer result={result} />
        </div>
      </div>
    </div>
  );
};

export default EnrichmentDetail;
