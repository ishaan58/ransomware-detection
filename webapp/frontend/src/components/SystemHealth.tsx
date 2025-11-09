import React from "react";

const SystemHealth = ({ summary }: { summary: any }) => {
  const total = summary.total_records || 1;
  const infected = summary.ransomware_detected || 0;
  const infectionRatio = (infected / total) * 100;
  const healthRatio = 100 - infectionRatio;

  // Determine system state
  let status = "healthy";
  if (infectionRatio > 0.1 && infectionRatio <= 1) status = "alert";
  if (infectionRatio > 1) status = "compromised";

  return (
    <div className="card">
      <h2 className="text-lg font-semibold text-green-400 glow mb-4">
        System Health Monitor
      </h2>

      {/* Progress Bar */}
      <div className="relative w-full h-6 bg-gray-950 border border-gray-800 rounded-full overflow-hidden shadow-[0_0_25px_rgba(0,255,100,0.25)]">
        {/* Healthy section */}
        <div
          className="absolute left-0 top-0 h-full bg-green-500 transition-all duration-1000 ease-out shadow-[0_0_20px_rgba(0,255,100,0.7)]"
          style={{ width: `${healthRatio}%` }}
        ></div>

        {/* Infected section */}
        <div
          className={`absolute top-0 h-full ${
            infectionRatio > 1
              ? "bg-red-600 animate-pulse"
              : infectionRatio > 0.1
              ? "bg-yellow-400"
              : "bg-green-500"
          } transition-all duration-1000 ease-out shadow-[0_0_20px_rgba(255,50,50,0.8)]`}
          style={{ left: `${healthRatio}%`, width: `${infectionRatio}%` }}
        ></div>

        {/* Scanning shimmer */}
        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent animate-[shine_5s_linear_infinite]" />
      </div>

      {/* Status row */}
      <div className="mt-3 flex items-center gap-6 text-sm text-gray-300 whitespace-nowrap">
        {/* Status label */}
        <div className="flex items-center gap-2">
          <span>Status:</span>
          {status === "healthy" ? (
            <span className="flex items-center gap-1 text-green-400 font-semibold">
              <span className="w-3 h-3 rounded-full bg-green-400 inline-block shadow-[0_0_8px_rgba(0,255,100,0.9)]"></span>
              Healthy
            </span>
          ) : status === "alert" ? (
            <span className="flex items-center gap-1 text-yellow-400 font-semibold">
              <span className="w-3 h-3 rounded-full bg-yellow-400 inline-block shadow-[0_0_8px_rgba(255,200,0,0.9)]"></span>
              Alert
            </span>
          ) : (
            <span className="flex items-center gap-1 text-red-400 font-semibold">
              <span className="w-3 h-3 rounded-full bg-red-400 inline-block shadow-[0_0_8px_rgba(255,0,0,0.9)] animate-pulse"></span>
              Compromised
            </span>
          )}
        </div>

        {/* Infection */}
        <div className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-red-500 inline-block shadow-[0_0_6px_rgba(255,0,0,0.8)]"></span>
          <span className="text-red-400 font-semibold">
            Infection Rate: {infectionRatio.toFixed(3)}%
          </span>
        </div>

        {/* Healthy */}
        <div className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-green-400 inline-block shadow-[0_0_6px_rgba(0,255,100,0.8)]"></span>
          <span className="text-green-400 font-semibold">
            Healthy: {healthRatio.toFixed(3)}%
          </span>
        </div>
      </div>
    </div>
  );
};

export default SystemHealth;
