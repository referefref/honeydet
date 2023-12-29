var storedScans = {};

document.addEventListener('DOMContentLoaded', function () {
    if (document.getElementById("searchInput")) {
        document.getElementById("searchInput").addEventListener("keyup", function() {
            var search = this.value.toLowerCase();
            $("#resultsTable tbody tr").filter(function() {
                $(this).toggle($(this).text().toLowerCase().indexOf(search) > -1)
            });
        });
    }
    
    var clearBtn = document.getElementById("clearBtn");
    if (clearBtn) {
        clearBtn.addEventListener("click", function() {
            clearResults();
        });
    }

    var advancedOptionsToggle = document.getElementById("advancedOptionsToggle");
    if (advancedOptionsToggle) {
        advancedOptionsToggle.addEventListener("change", function() {
            toggleAdvancedOptions();
        });
    } else {
	    console.error("Advanced options toggle not found");
    }
    
});

function toggleAdvancedOptions() {
    var advancedOptions = document.getElementById("advancedOptions");
    if (advancedOptions.style.display === "none") {
        advancedOptions.style.display = "block";
    } else {
        advancedOptions.style.display = "none";
    }
}

function startScan() {
    const host = document.getElementById('hostInput').value;
    const port = document.getElementById('portInput').value;
    const threads = document.getElementById('threadsInput').value;
    const proto = document.getElementById('protocolSelect').value;

    let params = `host=${host}&port=${port}&threads=${threads}&proto=${proto}`;

    const timeout = document.getElementById('timeoutInput').value;
    const delay = document.getElementById('delayInput').value;
    const pingCheck = document.getElementById('pingCheckInput').checked ? 'true' : 'false';
    const portOverride = document.getElementById('portOverrideInput').checked ? 'true' : 'false';
    const username = document.getElementById('usernameInput').value;
    const password = document.getElementById('passwordInput').value;

    if (timeout) params += `&timeout=${timeout}`;
    if (delay > 0) params += `&delay=${delay}`;
    params += `&checkPing=${pingCheck}&bypassPortCheck=${portOverride}`;
    if (username) params += `&username=${username}`;
    if (password) params += `&password=${password}`;

    var scanId = host + ":" + port + ":" + new Date().getTime();
    var scanTime = new Date().toLocaleString();

    addScanToExecutionList(scanId, host, port, scanTime);

    axios.get(`/scan?${params}`)
    .then(response => {
        const data = response.data;
        // Store the scan results
        storedScans[scanId] = data;
        markScanAsCompleted(scanId, host, port);
    })
    .catch(error => {
        console.error('Error:', error);
        markScanAsError(scanId, host, port);
    });
}

function addScanToExecutionList(scanId, host, port, scanTime) {
    var tbody = document.getElementById("scanExecutionsTable").getElementsByTagName("tbody")[0];
    
    if (tbody) {
        var row = tbody.insertRow();
        var startTimeCell = row.insertCell(0);
	var finishTimeCell = row.insertCell(1);
        var targetsCell = row.insertCell(2);
        var portsCell = row.insertCell(3);
        var statusCell = row.insertCell(4);
        var actionCell = row.insertCell(5);

        startTimeCell.innerHTML = scanTime;
        targetsCell.innerHTML = host;
        portsCell.innerHTML = port;
        finishTimeCell.innerHTML = ''; // Initially empty, filled on scan completion
        statusCell.innerHTML = 'New';
        actionCell.innerHTML = ''; // Initially empty, will be filled later

        row.dataset.scanId = scanId; // Ensure this is correctly being set
        row.dataset.scanTime = scanTime; // Store scan time    

    } else {
        console.error("Execution list table not found");
    }
}

function markScanAsCompleted(scanId, host, port) {
    var row = document.querySelector(`#scanExecutionsTable tbody tr[data-scan-id="${scanId}"]`);
    if (row) {
        var finishTimeCell = row.cells[1];
        var statusCell = row.cells[4];
        var actionCell = row.cells[5];

        finishTimeCell.innerHTML = new Date().toLocaleString();
        statusCell.innerHTML = 'Completed';
        actionCell.innerHTML = '<button class="btn btn-primary btn-sm" onclick="viewResults(\'' + scanId + '\')">View Results</button>' +
                                 '<button class="btn btn-success btn-sm ml-2" onclick="downloadResults(\'' + scanId + '\', \'json\')">JSON</button>' +
                                 '<button class="btn btn-success btn-sm ml-2" onclick="downloadResults(\'' + scanId + '\', \'csv\')">CSV</button>';
    }
}

function viewResults(scanId) {
    if (storedScans[scanId]) {
        populateResults(storedScans[scanId], scanId);
    } else {
        console.error('No data found for scanId:', scanId);
    }
}


function populateResults(data, scanId) {
    var tbody = document.getElementById("resultsTable").getElementsByTagName("tbody")[0];
    tbody.innerHTML = ''; // Clear current results

    var scanRow = document.querySelector(`#scanExecutionsTable tbody tr[data-scan-id="${scanId}"]`);
    var scanTime = scanRow ? scanRow.dataset.scanTime : 'Unknown Time';

    data.forEach(function(result) {
        var row = tbody.insertRow();
        var scanTimeCell = row.insertCell(0);
        var hostCell = row.insertCell(1);
        var portCell = row.insertCell(2);
        var isHoneypotCell = row.insertCell(3);
        var honeypotTypeCell = row.insertCell(4);

        scanTimeCell.innerHTML = scanTime;
	hostCell.innerHTML = result.Host;
        portCell.innerHTML = result.Port;
        isHoneypotCell.innerHTML = result.IsHoneypot ? 'Yes' : 'No';
        honeypotTypeCell.innerHTML = result.HoneypotType;

        row.className = result.IsHoneypot ? 'alert-honeypot' : 'alert-nonhoneypot';
    });
}

function clearResults() {
    var table = document.getElementById("resultsTable");
    if (table) {
        table.getElementsByTagName("tbody")[0].innerHTML = '';
    } else {
        console.error("Results table not found");
    }
}

function downloadResults(scanId, format) {
    if (storedScans[scanId]) {
        const data = storedScans[scanId];
        let dataStr;

        if (format === 'json') {
            dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data));
        } else if (format === 'csv') {
            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "Scan Time,Host,Port,Is Honeypot,Honeypot Type\n"; // CSV Header

            const scanTime = new Date(parseInt(scanId.split(':')[2])).toISOString().replace(/T/, ' ').replace(/\..+/, ''); // Extract and format time from scanId

            data.forEach(row => {
                const rowArray = [
                    scanTime,
                    row.Host,
                    row.Port,
                    row.IsHoneypot ? 'Yes' : 'No',
                    row.HoneypotType
                ];
                csvContent += rowArray.join(",") + "\r\n";
            });

            dataStr = encodeURI(csvContent);
        } else {
            console.error("Invalid format for download");
            return;
        }

        // Create a download element and trigger download
        const downloadElement = document.createElement('a');
        downloadElement.setAttribute('href', dataStr);
        downloadElement.setAttribute('download', `scan_results_${scanId}.${format}`);
        document.body.appendChild(downloadElement); // Append to body
        downloadElement.click(); // Simulate click to trigger download
        document.body.removeChild(downloadElement); // Remove the element after download
    } else {
        console.error("No data found for scanId:", scanId);
    }
}
