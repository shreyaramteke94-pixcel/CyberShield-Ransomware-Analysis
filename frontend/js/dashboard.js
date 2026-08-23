function getHistory() {

    return JSON.parse(
        localStorage.getItem("scanHistory")
    ) || [];

}


function updateDashboard() {

    const history = getHistory();


    const total =
        history.length;

    const clean =
        history.filter(
            item => item.status === "Clean"
        ).length;

    const threats =
        history.filter(
            item => item.status === "Threat Detected"
        ).length;


    document.getElementById(
        "totalScans"
    ).textContent = total;


    document.getElementById(
        "cleanFiles"
    ).textContent = clean;


    document.getElementById(
        "threatFiles"
    ).textContent = threats;


    const recent =
        document.getElementById("recentScans");


    if (history.length === 0) {

        recent.innerHTML = `
            <div class="empty-state">
                No scans yet.
                <br><br>
                Start your first scan.
            </div>
        `;

        return;
    }


    recent.innerHTML = "";


    history
        .slice(-4)
        .reverse()
        .forEach(item => {

            const row =
                document.createElement("div");

            row.className =
                "history-item";

            row.style.gridTemplateColumns =
                "1.5fr 1fr 0.8fr";

            row.innerHTML = `

                <div class="file-name">

                    <div class="file-icon">
                        📄
                    </div>

                    <strong>
                        ${item.filename}
                    </strong>

                </div>

                <div class="date">
                    ${item.date}
                </div>

                <div>

                    <span class="status ${
                        item.status === "Clean"
                            ? "clean"
                            : "threat"
                    }">

                        ${
                            item.status === "Clean"
                                ? "✓ Clean"
                                : "⚠ Threat"
                        }

                    </span>

                </div>

            `;

            recent.appendChild(row);

        });

}


updateDashboard();