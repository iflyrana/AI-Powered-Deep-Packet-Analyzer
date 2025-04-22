async function fetchPacketData() {
    try {
        const response = await fetch('http://192.168.88.5:5000/fetch-data'); // Use correct IP
        const data = await response.json();
        console.log("Fetched Data:", data); // Debugging log
        updateDashboard(data);  // Update values on dashboard
        updateCharts(data);  // Update charts
    } catch (error) {
        console.error("Error fetching data:", error);
    }
}

function updateDashboard(data) {
    let normalCount = 0;
    let anomalyCount = 0;

    data.forEach(entry => {
        if (entry.field === "normal_count") {
            normalCount = entry.value;
        } else if (entry.field === "anomaly_count") {
            anomalyCount = entry.value;
        }
    });

    console.log("Updating Dashboard: Normal:", normalCount, "Anomaly:", anomalyCount);

    // Update values on the dashboard (Make sure these IDs exist in your HTML)
    document.getElementById("normalCount").textContent = parseInt(normalCount);
    document.getElementById("anomalyCount").textContent = parseInt(anomalyCount);
}

function updateCharts(data) {
    let normalCount = 0;
    let anomalyCount = 0;

    data.forEach(entry => {
        if (entry.field === "normal_count") {
            normalCount = entry.value;
        } else if (entry.field === "anomaly_count") {
            anomalyCount = entry.value;
        }
    });

    console.log("Updating Chart: Normal:", normalCount, "Anomaly:", anomalyCount);

    if (typeof normalAnomalyChart !== "undefined" && normalAnomalyChart) {
        normalAnomalyChart.data.datasets[0].data = [normalCount, anomalyCount];
        normalAnomalyChart.update();
    } else {
        console.warn("Chart not initialized! Creating new chart...");
        createChart(normalCount, anomalyCount);
    }
}

function createChart(normal, anomaly) {
    const ctx = document.getElementById("normalAnomalyChart").getContext("2d");
    normalAnomalyChart = new Chart(ctx, {
        type: "pie",
        data: {
            labels: ["Normal", "Anomaly"],
            datasets: [{
                data: [normal, anomaly],
                backgroundColor: ["green", "red"]
            }]
        }
    });
}

// Fetch data every 5 seconds
setInterval(fetchPacketData, 5000);
