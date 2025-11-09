import React, { useState } from "react";
import UploadSection from "./components/UploadSection";
import SummaryCards from "./components/SummaryCards";
import FlaggedTable from "./components/FlaggedTable";
import "./App.css";

const App: React.FC = () => {
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleUpload = (data: any) => {
    setResults(data);
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      {/* Header */}
      <div className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-6">
          <h1 className="text-3xl font-light tracking-tight">Ransomware Detector</h1>
          <p className="text-sm text-slate-400 mt-1">Hybrid ML-based threat analysis</p>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        <UploadSection onUpload={handleUpload} setLoading={setLoading} />

        {loading && (
          <div className="mt-8 flex items-center justify-center">
            <div className="animate-spin h-8 w-8 border-2 border-slate-600 border-t-slate-100 rounded-full"></div>
            <span className="ml-3 text-sm text-slate-400">Analyzing logs...</span>
          </div>
        )}

        {results && (
          <div className="mt-12 space-y-8">
            <SummaryCards summary={results.summary} />
            <FlaggedTable flagged={results.flagged} />
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
