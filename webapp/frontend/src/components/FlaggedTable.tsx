

const FlaggedTable = ({ flagged }: { flagged: any[] }) => {
  if (!flagged || flagged.length === 0) {
    return null;
  }

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-800">
        <h2 className="text-lg font-light">Flagged Events</h2>
        <p className="text-xs text-slate-500 mt-1">{flagged.length} suspicious events detected</p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/50">
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wide">Source</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wide">Type</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wide">Confidence</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wide">Score</th>
            </tr>
          </thead>
          <tbody>
            {flagged.map((row, idx) => (
              <tr key={idx} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                <td className="px-6 py-3 text-slate-300 text-xs font-mono">{row.Source}</td>
                <td className="px-6 py-3">
                  <span className="text-xs px-2 py-1 rounded bg-slate-800 text-slate-300">
                    {row.threat_classification?.split(" ")[0] || "Unknown"}
                  </span>
                </td>
                <td className="px-6 py-3">
                  <span className={`text-xs font-medium ${
                    row.rf_malware_prob > 0.7 ? "text-red-400" : "text-amber-400"
                  }`}>
                    {(row.rf_malware_prob * 100).toFixed(1)}%
                  </span>
                </td>
                <td className="px-6 py-3 text-xs text-slate-500">
                  {Math.abs(row.if_anomaly_score).toFixed(4)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default FlaggedTable;
