import React from "react";

interface SummaryData {
  total_records: number;
  malware_detected: number;
  malware_percentage: number;
  threat_breakdown: {
    high_confidence_ransomware: number;
    known_ransomware_pattern: number;
    novel_unknown_anomaly: number;
    benign: number;
  };
}

const SummaryCards = ({ summary }: { summary: SummaryData }) => {
  const cards = [
    {
      label: "High-Confidence",
      value: summary.threat_breakdown.high_confidence_ransomware,
      bgColor: "bg-red-950/50 border-red-900/50",
      textColor: "text-red-400",
      dotColor: "bg-red-500",
    },
    {
      label: "Known Pattern",
      value: summary.threat_breakdown.known_ransomware_pattern,
      bgColor: "bg-amber-950/50 border-amber-900/50",
      textColor: "text-amber-400",
      dotColor: "bg-amber-500",
    },
    {
      label: "Novel Anomaly",
      value: summary.threat_breakdown.novel_unknown_anomaly,
      bgColor: "bg-orange-950/50 border-orange-900/50",
      textColor: "text-orange-400",
      dotColor: "bg-orange-500",
    },
    {
      label: "Benign",
      value: summary.threat_breakdown.benign,
      bgColor: "bg-emerald-950/50 border-emerald-900/50",
      textColor: "text-emerald-400",
      dotColor: "bg-emerald-500",
    },
  ];

  return (
    <div className="w-full space-y-6">
      {/* Main Malware Percentage */}
      <div className="relative overflow-hidden rounded-lg border border-slate-800 bg-gradient-to-br from-slate-900 to-slate-950 p-8">
        <div className="absolute inset-0 bg-gradient-to-r from-red-600/10 via-transparent to-transparent"></div>
        <div className="relative">
          <p className="text-sm font-medium text-slate-400 uppercase tracking-wide">Detection Rate</p>
          <p className="text-6xl font-light mt-3 text-red-400">{summary.malware_percentage}%</p>
          <p className="text-xs text-slate-500 mt-3">
            {summary.malware_detected} threats detected in {summary.total_records} events
          </p>
        </div>
      </div>

      {/* Threat Categories Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card, idx) => (
          <div
            key={idx}
            className={`rounded-lg border ${card.bgColor} p-5 transition-all hover:border-opacity-100 hover:bg-opacity-70`}
          >
            <div className="flex items-center gap-3 mb-3">
              <div className={`h-2 w-2 rounded-full ${card.dotColor}`}></div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wide">{card.label}</p>
            </div>
            <p className={`text-4xl font-light ${card.textColor}`}>{card.value}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SummaryCards;
