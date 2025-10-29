import { useEffect, useState } from 'react';

interface ScoreGaugeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
}

export const ScoreGauge = ({ score, size = 'md' }: ScoreGaugeProps) => {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    const duration = 1500;
    const steps = 60;
    const increment = score / steps;
    let current = 0;
    
    const timer = setInterval(() => {
      current += increment;
      if (current >= score) {
        setAnimatedScore(score);
        clearInterval(timer);
      } else {
        setAnimatedScore(Math.round(current));
      }
    }, duration / steps);

    return () => clearInterval(timer);
  }, [score]);

  const getColor = (value: number): string => {
    if (value < 20) return 'hsl(var(--risk-safe))';
    if (value < 40) return 'hsl(var(--risk-low))';
    if (value < 60) return 'hsl(var(--risk-medium))';
    if (value < 80) return 'hsl(var(--risk-high))';
    return 'hsl(var(--risk-critical))';
  };

  const getLabel = (value: number): string => {
    if (value < 20) return 'Safe';
    if (value < 40) return 'Low Risk';
    if (value < 60) return 'Medium Risk';
    if (value < 80) return 'High Risk';
    return 'Critical';
  };

  const sizes = {
    sm: { width: 120, stroke: 8, fontSize: 'text-xl' },
    md: { width: 200, stroke: 12, fontSize: 'text-4xl' },
    lg: { width: 280, stroke: 16, fontSize: 'text-6xl' },
  };

  const config = sizes[size];
  const radius = (config.width - config.stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (animatedScore / 100) * circumference;
  const color = getColor(animatedScore);

  return (
    <div className="flex flex-col items-center gap-4">
      <div className="relative" style={{ width: config.width, height: config.width }}>
        <svg
          width={config.width}
          height={config.width}
          className="transform -rotate-90"
        >
          {/* Background circle */}
          <circle
            cx={config.width / 2}
            cy={config.width / 2}
            r={radius}
            stroke="hsl(var(--muted))"
            strokeWidth={config.stroke}
            fill="none"
          />
          {/* Progress circle */}
          <circle
            cx={config.width / 2}
            cy={config.width / 2}
            r={radius}
            stroke={color}
            strokeWidth={config.stroke}
            fill="none"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
            style={{
              filter: `drop-shadow(0 0 8px ${color})`,
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className={`font-bold font-mono ${config.fontSize}`} style={{ color }}>
            {animatedScore}
          </div>
          <div className="text-sm text-muted-foreground">/ 100</div>
        </div>
      </div>
      <div className="text-center">
        <div className="text-lg font-semibold" style={{ color }}>
          {getLabel(animatedScore)}
        </div>
        <div className="text-sm text-muted-foreground">Context Score</div>
      </div>
    </div>
  );
};
