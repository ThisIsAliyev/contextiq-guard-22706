// History management for localStorage
export interface EnrichmentHistory {
  id: string;
  indicator: string;
  indicatorType: 'ip' | 'domain' | 'hash' | 'email';
  contextScore: number;
  timestamp: string;
  summary: string;
  recommendation: string;
  scoreDetails: string[];
  rawData: any;
}

const HISTORY_KEY = 'contextiq_history';
const MAX_HISTORY = 100;

export const saveToHistory = (entry: Omit<EnrichmentHistory, 'id' | 'timestamp'>): void => {
  try {
    const history = getHistory();
    const newEntry: EnrichmentHistory = {
      ...entry,
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
    };
    
    history.unshift(newEntry);
    
    // Keep only last 100 entries
    if (history.length > MAX_HISTORY) {
      history.splice(MAX_HISTORY);
    }
    
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch (error) {
    console.error('Failed to save to history:', error);
  }
};

export const getHistory = (): EnrichmentHistory[] => {
  try {
    const stored = localStorage.getItem(HISTORY_KEY);
    if (!stored) return [];
    return JSON.parse(stored) as EnrichmentHistory[];
  } catch (error) {
    console.error('Failed to load history:', error);
    return [];
  }
};

export const clearHistory = (): void => {
  try {
    localStorage.removeItem(HISTORY_KEY);
  } catch (error) {
    console.error('Failed to clear history:', error);
  }
};

export const getHistoryEntry = (id: string): EnrichmentHistory | null => {
  const history = getHistory();
  return history.find(entry => entry.id === id) || null;
};

