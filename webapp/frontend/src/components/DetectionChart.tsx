import React from "react";
import { Pie } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";

ChartJS.register(ArcElement, Tooltip, Legend);

const DetectionChart = ({ summary }: { summary: any }) => {
  const data = {
    labels: ["Benign", "Ransomware"],
    datasets: [
      {
        data: [summary.benign_events, summary.ransomware_detected],
        backgroundColor: ["#10b981", "#ef4444"],
        borderColor: "#0f0f0f",
        borderWidth: 1,
      },
    ],
  };

  const options = {
    plugins: {
      legend: {
        labels: { color: "#a3a3a3", font: { size: 13 } },
      },
    },
    maintainAspectRatio: false,
  };

  return (
    <div className="card hover:shadow-green-400/30">
      <h2 className="text-lg font-semibold glow mb-4">Detection Breakdown</h2>
      <div className="flex justify-center">
        <div className="h-48 w-48 hover:scale-105 transition-all duration-500">
          <Pie data={data} options={options} />
        </div>
      </div>
    </div>
  );
};

export default DetectionChart;
