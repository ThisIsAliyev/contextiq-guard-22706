import { ApiKeyForm } from '@/components/ApiKeyForm';
import { Button } from '@/components/ui/button';
import { ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';

const Settings = () => {
  return (
    <div className="min-h-screen bg-background">
      <div className="container max-w-4xl mx-auto px-4 py-8">
        <div className="mb-8">
          <Link to="/">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Dashboard
            </Button>
          </Link>
        </div>

        <div className="space-y-6">
          <div>
            <h1 className="text-4xl font-bold mb-2">API Keys Settings</h1>
            <p className="text-muted-foreground">
              Configure your API keys for threat intelligence enrichment. These keys are stored
              securely in your browser and never on our servers.
            </p>
          </div>

          <ApiKeyForm />
        </div>
      </div>
    </div>
  );
};

export default Settings;
