const historyList =
    document.getElementById(
        "historyList"
    );

const clearHistory =
    document.getElementById(
        "clearHistory"
    );


function loadHistory() {

    const history =
        JSON.parse(
            localStorage.getItem(
                "scanHistory"
            )
        ) || [];


    if (history.length === 0) {

        historyList.innerHTML = `

            <div class="empty-state">

                🛡️

                <br><br>

                No scan history yet.

                <br>

                Go to Scanner to scan
                your first file.

            </div>

        `;

        return;
    }


    historyList.innerHTML = "";


    history
        .slice()
        .reverse()
        .forEach(item => {

            const row =
                document.createElement(
                    "div"
                );

            row.className =
                "history-item";


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
                                : "⚠ Threat Detected"
                        }

                    </span>

                </div>

            `;


            historyList.appendChild(
                row
            );

        });

}


/* CLEAR */

clearHistory.addEventListener(
    "click",
    function () {

        const history =
            JSON.parse(
                localStorage.getItem(
                    "scanHistory"
                )
            ) || [];


        if (history.length === 0) {

            return;

        }


        const confirmed =
            confirm(
                "Are you sure you want to clear all scan history?"
            );


        if (confirmed) {

            localStorage.removeItem(
                "scanHistory"
            );

            loadHistory();

        }

    }
);


loadHistory();