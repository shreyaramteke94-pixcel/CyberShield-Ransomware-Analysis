const fileInput =
    document.getElementById("fileInput");

const dropArea =
    document.getElementById("dropArea");

const selectedFile =
    document.getElementById("selectedFile");

const scanButton =
    document.getElementById("scanButton");

const scanProgress =
    document.getElementById("scanProgress");

const progressBar =
    document.getElementById("progressBar");

const progressText =
    document.getElementById("progressText");

const scanResult =
    document.getElementById("scanResult");

const threatPopup =
    document.getElementById("threatPopup");


let currentFile = null;


/* FILE SELECTION */

fileInput.addEventListener(
    "change",
    function () {

        if (this.files.length > 0) {

            currentFile =
                this.files[0];

            showSelectedFile(
                currentFile
            );
        }

    }
);


/* DRAG AND DROP */

dropArea.addEventListener(
    "dragover",
    function (event) {

        event.preventDefault();

        dropArea.classList.add(
            "dragover"
        );

    }
);


dropArea.addEventListener(
    "dragleave",
    function () {

        dropArea.classList.remove(
            "dragover"
        );

    }
);


dropArea.addEventListener(
    "drop",
    function (event) {

        event.preventDefault();

        dropArea.classList.remove(
            "dragover"
        );


        if (event.dataTransfer.files.length) {

            currentFile =
                event.dataTransfer.files[0];

            showSelectedFile(
                currentFile
            );

        }

    }
);


/* SHOW FILE */

function showSelectedFile(file) {

    selectedFile.innerHTML = `
        📄 <strong>${file.name}</strong>
        <br>
        ${(file.size / 1024).toFixed(1)} KB
    `;

    scanButton.disabled = false;

    scanResult.style.display =
        "none";
}


/* SCAN */

scanButton.addEventListener(
    "click",
    function () {

        if (!currentFile) {

            return;
        }


        scanButton.disabled = true;

        dropArea.style.display =
            "none";

        scanProgress.style.display =
            "block";

        scanResult.style.display =
            "none";


        let progress = 0;


        const interval =
            setInterval(
                function () {

                    progress +=
                        Math.floor(
                            Math.random() * 10
                        ) + 5;


                    if (progress > 100) {

                        progress = 100;

                    }


                    progressBar.style.width =
                        progress + "%";


                    progressText.textContent =
                        progress + "%";


                    if (progress >= 100) {

                        clearInterval(
                            interval
                        );

                        finishScan();

                    }

                },
                250
            );

    }
);


/*
    DEMO RESULT

    For demonstration, the app decides the
    result based on the filename.

    In a real product, this section should
    call your backend/security scanner.
*/

function getDemoResult(file) {

    const name =
        file.name.toLowerCase();


    const suspiciousWords = [
        "ransom",
        "virus",
        "malware",
        "trojan",
        "danger",
        "hack",
        "encrypted"
    ];


    const suspicious =
        suspiciousWords.some(
            word =>
                name.includes(word)
        );


    if (suspicious) {

        return "Threat Detected";

    }


    return "Clean";

}


/* FINISH */

function finishScan() {

    const result =
        getDemoResult(currentFile);


    scanProgress.style.display =
        "none";


    saveHistory(
        currentFile.name,
        result
    );


    if (result === "Clean") {

        showCleanResult();

    } else {

        showThreatResult();

    }

}


/* CLEAN */

function showCleanResult() {

    scanResult.style.display =
        "block";

    scanResult.className =
        "scan-result clean";


    scanResult.innerHTML = `

        <div class="result-icon">
            🟢
        </div>

        <h2>
            No Threat Detected
        </h2>

        <p>
            Cyber Shield did not detect a
            threat in <strong>
            ${currentFile.name}
            </strong>.
        </p>

        <br>

        <button
            class="primary-btn"
            onclick="resetScanner()"
        >
            Scan Another File
        </button>

    `;

}


/* THREAT */

function showThreatResult() {

    scanResult.style.display =
        "block";

    scanResult.className =
        "scan-result threat";


    scanResult.innerHTML = `

        <div class="result-icon">
            🚨
        </div>

        <h2>
            Potential Threat Detected
        </h2>

        <p>
            Cyber Shield detected a
            potentially dangerous file:
            <strong>
            ${currentFile.name}
            </strong>.
        </p>

        <br>

        <button
            class="danger-btn"
            onclick="resetScanner()"
        >
            Scan Another File
        </button>

    `;


    threatPopup.style.display =
        "flex";

}


/* SAVE HISTORY */

function saveHistory(
    filename,
    status
) {

    let history =
        JSON.parse(
            localStorage.getItem(
                "scanHistory"
            )
        ) || [];


    history.push({

        filename: filename,

        status: status,

        date:
            new Date()
                .toLocaleString()

    });


    localStorage.setItem(
        "scanHistory",
        JSON.stringify(history)
    );

}


/* RESET */

function resetScanner() {

    currentFile = null;

    fileInput.value = "";

    selectedFile.textContent =
        "No file selected";

    scanButton.disabled = true;

    dropArea.style.display =
        "flex";

    scanProgress.style.display =
        "none";

    scanResult.style.display =
        "none";

    progressBar.style.width =
        "0%";

    progressText.textContent =
        "0%";

}


/* POPUP */

function closePopup() {

    threatPopup.style.display =
        "none";

}