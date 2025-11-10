import { useState } from "react";
import axios from "axios";

interface Props {
  onUpload: (data: any) => void;
  setLoading: (loading: boolean) => void;
}

const UploadSection: React.FC<Props> = ({ onUpload, setLoading }) => {
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleUpload = async () => {
    if (!file) {
      setError("Please select a CSV file");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);
    setLoading(true);
    setError(null);

    try {
      const res = await axios.post("https://ransomware-backend-1si8.onrender.com/api/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      onUpload(res.data);
    } catch {
      setError("Failed to connect to backend. Ensure Flask is running on port 5000.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-8">
      <h2 className="text-xl font-light mb-6">Upload System Logs</h2>

      <div className="space-y-4">
        {/* File Input */}
        <div className="relative">
          <input
            type="file"
            accept=".csv"
            onChange={(e) => {
              setFile(e.target.files?.[0] || null);
              setError(null);
            }}
            className="hidden"
            id="file-input"
          />
          <label
            htmlFor="file-input"
            className="block w-full px-4 py-3 rounded-lg border border-dashed border-slate-700 bg-slate-950/50 text-center cursor-pointer hover:border-slate-600 transition-colors"
          >
            <p className="text-sm text-slate-400">
              {file ? file.name : "Click to select CSV file"}
            </p>
          </label>
        </div>

        {/* Upload Button */}
        <button
          onClick={handleUpload}
          disabled={!file}
          className="w-full px-4 py-3 rounded-lg bg-slate-700 hover:bg-slate-600 disabled:bg-slate-800 disabled:cursor-not-allowed text-sm font-medium transition-colors"
        >
          Analyze
        </button>

        {/* Error Message */}
        {error && (
          <p className="text-xs text-red-400 bg-red-950/20 border border-red-900/50 rounded px-3 py-2">
            {error}
          </p>
        )}
      </div>
    </div>
  );
};

export default UploadSection;
