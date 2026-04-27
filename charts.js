function renderPerformanceCharts(rows) {
  if (!rows || rows.length === 0) {
    return;
  }

  const labels = rows.map((r) => `Epoch ${r.epoch}`);
  const accuracy = rows.map((r) => r.accuracy);
  const loss = rows.map((r) => r.loss);
  const precision = rows.map((r) => r.precision);
  const recall = rows.map((r) => r.recall);
  const f1 = rows.map((r) => r.f1);

  const barCanvas = document.getElementById("barChart");
  const lineCanvas = document.getElementById("lineChart");

  if (barCanvas) {
    new Chart(barCanvas, {
      type: "bar",
      data: {
        labels,
        datasets: [
          {
            label: "Accuracy",
            data: accuracy,
            backgroundColor: "rgba(37, 99, 235, 0.72)",
            borderRadius: 8,
          },
          {
            label: "Precision",
            data: precision,
            backgroundColor: "rgba(5, 150, 105, 0.72)",
            borderRadius: 8,
          },
          {
            label: "Recall",
            data: recall,
            backgroundColor: "rgba(245, 158, 11, 0.72)",
            borderRadius: 8,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { labels: { color: "#f8fafc" } },
        },
        scales: {
          x: { ticks: { color: "#e2e8f0" }, grid: { color: "rgba(226,232,240,0.15)" } },
          y: { ticks: { color: "#e2e8f0" }, grid: { color: "rgba(226,232,240,0.12)" }, beginAtZero: true },
        },
      },
    });
  }

  if (lineCanvas) {
    new Chart(lineCanvas, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Loss",
            data: loss,
            borderColor: "#ef4444",
            pointBackgroundColor: "#ef4444",
            tension: 0.3,
            fill: false,
          },
          {
            label: "F1 Score",
            data: f1,
            borderColor: "#22c55e",
            pointBackgroundColor: "#22c55e",
            tension: 0.3,
            fill: false,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { labels: { color: "#f8fafc" } },
        },
        scales: {
          x: { ticks: { color: "#e2e8f0" }, grid: { color: "rgba(226,232,240,0.15)" } },
          y: { ticks: { color: "#e2e8f0" }, grid: { color: "rgba(226,232,240,0.12)" }, beginAtZero: true },
        },
      },
    });
  }
}
