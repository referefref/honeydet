var storedScans = {};
var hasNewScans = false;
let confirmCallback = null;

document.addEventListener('DOMContentLoaded', function () {
    fetchScans();
    setInterval(function() {
        if (hasNewScans) {
            fetchScans();
        }
    }, 1000);

    var clearDbBtn = document.getElementById('clearDbBtn');
    if (clearDbBtn) {
        clearDbBtn.addEventListener('click', clearDatabase);
    }

    var scanBtn = document.getElementById('scanBtn');
    if (scanBtn) {
        scanBtn.addEventListener('click', startScan);
    } else {
        console.error("Scan button not found");
    }

    var searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('keyup', function() {
            var search = this.value.toLowerCase();
            filterTableRows('resultsTable', search);
        });
    } else {
        console.error("Search input not found");
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

    var confirmBtn = document.getElementById('confirmBtn');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', function() {
            $('#confirmationModal').modal('hide');
            if (typeof confirmCallback === 'function') {
                confirmCallback();
                confirmCallback = null; // Reset callback after invocation
            }
        });
    } else {
        console.error("Confirm button not found");
    }

    var searchExecutionsInput = document.getElementById('searchExecutionsInput');
    if (searchExecutionsInput) {
        searchExecutionsInput.addEventListener('keyup', function() {
            var search = this.value.toLowerCase();
            filterTableRows('scanExecutionsTable', search);
        });
    }

    $('[data-toggle="tooltip"]').tooltip();

});

function filterTableRows(tableId, search) {
    var table = document.getElementById(tableId);
    var tr = table.getElementsByTagName('tr');

    for (var i = 1; i < tr.length; i++) {
        var td = tr[i].getElementsByTagName('td');
        var found = false;
        for (var j = 0; j < td.length; j++) {
            if (td[j].textContent.toLowerCase().indexOf(search) > -1) {
                found = true;
                break;
            }
        }
        tr[i].style.display = found ? '' : 'none';
    }
}

function showConfirmationModal(title, message, callback) {
    $('#confirmationModal .modal-title').text(title);
    $('#confirmationModal .modal-body').text(message);
    confirmCallback = callback;
    $('#confirmationModal').modal('show');
}

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

    addScanToExecutionList({
        scan_id: scanId,
        start_time: new Date().toLocaleString(),
        hosts: host.split(','),
        ports: port.split(','),
        status: 'New'
    });

	axios.get(`/scan?${params}`)
        .then(response => {
            const scanId = response.data.scan_id;
            console.log("Scan started. ScanId:", scanId);

            addScanToExecutionList({
                scan_id: scanId,
                start_time: new Date().toLocaleString(),
                host: host.split(','),
                port: port.split(','),
                status: 'New'
            });
            storedScans[scanId] = {
                hosts: host.split(','),
                ports: port.split(','),
                status: 'New',
                results: []
            };

            hasNewScans = true;
            pollForScanCompletion(scanId);
        })
        .catch(error => {
            console.error('Error:', error);
        });
}

function pollForScanCompletion(scanId) {
    const checkCompletion = setInterval(() => {
        axios.get(`/getScans`)
            .then(response => {
                const scan = response.data.find(s => s.scan_id === scanId);
                if (scan && scan.end_time) {
                    clearInterval(checkCompletion);
                    storedScans[scanId] = scan;
                    updateScanExecutionList(scan);
                    console.log("Scan completed. ScanId:", scanId, "Final Scan Data:", scan);
                }
            })
            .catch(error => {
                console.error('Error fetching scan status:', error);
                clearInterval(checkCompletion);
            });
    }, 1000);
}

function updateScanExecutionList(scan) {
    var row = document.querySelector(`#scanExecutionsTable tbody tr[data-scan-id="${scan.scan_id}"]`);
    if (row) {
        row.cells[1].innerHTML = scan.end_time ? new Date(scan.end_time).toLocaleString() : 'Running';
        row.cells[2].innerHTML = scan.target_hosts ? scan.hosts.join(", ") : 'N/A'; 
        row.cells[3].innerHTML = scan.target_ports ? scan.ports.join(", ") : 'N/A'; 
	row.cells[4].innerHTML = 'Completed';
        row.cells[5].innerHTML = getActionButtonsHTML(scan.scan_id);
    } else {
        addScanToExecutionList(scan);
    }
}

function addScanToExecutionList(scan) {
    var tbody = document.getElementById("scanExecutionsTable").getElementsByTagName("tbody")[0];
    var row = tbody.insertRow();
    if (tbody) {
	    row.dataset.scanTime = scan.start_time;
    }
    var startTimeCell = row.insertCell(0);
    var finishTimeCell = row.insertCell(1);
    var targetsCell = row.insertCell(2);
    var portsCell = row.insertCell(3);
    var statusCell = row.insertCell(4);
    var actionCell = row.insertCell(5);

    startTimeCell.innerHTML = new Date(scan.start_time).toLocaleString();
    finishTimeCell.innerHTML = scan.end_time ? new Date(scan.end_time).toLocaleString() : '';
    targetsCell.innerHTML = scan.hosts ? scan.hosts.join(", ") : 'N/A';
    portsCell.innerHTML = scan.ports ? scan.ports.join(", ") : 'N/A';
    statusCell.innerHTML = scan.status;

    if (statusCell.innerHTML === 'Completed') {
        actionCell.innerHTML = getActionButtonsHTML(scan.scan_id);
    } else {
        actionCell.innerHTML = '';
    }

    row.dataset.scanId = scan.scan_id;
}

function fetchScans() {
    axios.get('/getScans')
        .then(response => {
            const scans = response.data;

            if (!scans || !Array.isArray(scans)) {
                console.error('Invalid scan data received:', scans);
                return; 
            }

            clearScanExecutionsTable();
            scans.forEach(scan => {
                storedScans[scan.scan_id] = {
                    hosts: scan.hosts,
                    ports: scan.ports,
                    results: scan.results,
                    status: scan.end_time ? 'Completed' : 'New'
                };
                addScanToExecutionList(scan);
            });
            autoRefreshForNewScans();
        })
        .catch(error => {
            console.error('Error fetching scans:', error);
        });
}

function aggregateScans(scanResults) {
    const aggregatedScans = {};
    scanResults.forEach(result => {
        if (!aggregatedScans[result.scan_id]) {
            aggregatedScans[result.scan_id] = {
                scan_id: result.scan_id,
                start_time: result.start_time,
                end_time: result.end_time,
                hosts: new Set(),  
                ports: new Set(),
                results: []
            };
        }
        aggregatedScans[result.scan_id].hosts.add(result.host);
        aggregatedScans[result.scan_id].ports.add(result.port.toString());
        aggregatedScans[result.scan_id].results.push(result);
    });

    Object.values(aggregatedScans).forEach(scan => {
        scan.hosts = Array.from(scan.hosts);
        scan.ports = Array.from(scan.ports);
    });

    return aggregatedScans;
}

function clearScanExecutionsTable() {
    var table = document.getElementById("scanExecutionsTable").getElementsByTagName("tbody")[0];
    table.innerHTML = ''; 
}

function addScanToExecutionList(scan) {
    var tbody = document.getElementById("scanExecutionsTable").getElementsByTagName("tbody")[0];
    var row = tbody.insertRow();

    var startTimeCell = row.insertCell(0);
    var finishTimeCell = row.insertCell(1);
    var targetsCell = row.insertCell(2);
    var portsCell = row.insertCell(3);
    var statusCell = row.insertCell(4);
    var actionCell = row.insertCell(5);

    startTimeCell.innerHTML = scan.start_time ? new Date(scan.start_time).toLocaleString() : 'Unknown Time';
    finishTimeCell.innerHTML = scan.end_time ? new Date(scan.end_time).toLocaleString() : '';
    targetsCell.innerHTML = scan.target_hosts ? scan.target_hosts : 'N/A';
    portsCell.innerHTML = scan.target_ports ? scan.target_ports : 'N/A';
    statusCell.innerHTML = scan.results && scan.results.length > 0 ? 'Completed' : 'New';

   if (statusCell.innerHTML === 'Completed') {
        actionCell.innerHTML = '<button class="btn btn-primary btn-sm" onclick="viewResults(\'' + scan.scan_id + '\')">View Results</button>' +
           '<button class="btn btn-success btn-sm ml-2" onclick="downloadResults(\'' + scan.scan_id + '\', \'json\')">JSON</button>' +
           '<button class="btn btn-success btn-sm ml-2" onclick="downloadResults(\'' + scan.scan_id + '\', \'csv\')">CSV</button>' +
           '<button class="btn btn-danger btn-sm ml-2" onclick="deleteScan(\'' + scan.scan_id + '\')"><i class="fas fa-times"></i></button>';
    } else {
        actionCell.innerHTML = '';
    }

    row.dataset.scanId = scan.scan_id;
}

function getActionButtonsHTML(scanId) {
	return '<button class="btn btn-primary btn-sm" onclick="viewResults(\'' + scan.scan_id + '\')">View Results</button>' +
           '<button class="btn btn-success btn-sm ml-2" onclick="downloadResults(\'' + scan.scan_id + '\', \'json\')">JSON</button>' +
           '<button class="btn btn-success btn-sm ml-2" onclick="downloadResults(\'' + scan.scan_id + '\', \'csv\')">CSV</button>' +
           '<button class="btn btn-danger btn-sm ml-2" onclick="deleteScan(\'' + scan.scan_id + '\')"><i class="fas fa-times"></i></button>';
}

function autoRefreshForNewScans() {
    const scans = document.querySelectorAll('#scanExecutionsTable tbody tr');
    const hasNewScans = Array.from(scans).some(row => row.cells[4].innerHTML === 'New');

    if (hasNewScans) {
        setTimeout(fetchScans, 1000);
    }
}

function viewResults(scanId) {
    var scan = storedScans[scanId];
    if (scan && scan.results) {
        populateResults(scan.results, scanId);
    } else {
        console.error('No data or invalid data found for scanId:', scanId);
    }
}

function populateResults(results, scanId) {
    var tbody = document.getElementById("resultsTable").getElementsByTagName("tbody")[0];
    tbody.innerHTML = ''; 

    results.forEach(result => {
        var row = tbody.insertRow();
        var detectionTimeCell = row.insertCell(0);
        var hostCell = row.insertCell(1);
        var portCell = row.insertCell(2);
        var isHoneypotCell = row.insertCell(3);
        var honeypotTypeCell = row.insertCell(4);

        detectionTimeCell.innerHTML = result.detection_time ? new Date(result.detection_time).toLocaleString() : 'N/A';
        hostCell.innerHTML = result.host || 'N/A';
        portCell.innerHTML = result.port || 'N/A';
        isHoneypotCell.innerHTML = result.is_honeypot ? 'Yes' : 'No';
        honeypotTypeCell.innerHTML = result.honeypot_type || 'N/A';

        row.className = result.is_honeypot ? 'alert-honeypot' : 'alert-nonhoneypot';
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

function clearDatabase() {
        showConfirmationModal("Confirm Delete", "Are you sure you want to delete all records from the database?", function() {
	axios.get('/clearDatabase')
            .then(response => {
                clearResults();
		fetchScans(); 
            })
            .catch(error => {
                console.error('Error clearing database:', error);
            });
    });
}

function deleteScan(scanId) {
        showConfirmationModal("Confirm Delete", "Are you sure you want to delete this scan and its results?", function() {
	axios.get(`/deleteScan?scanId=${scanId}`)
            .then(response => {
                showModal("Scan Deleted", "Scan and related results have been deleted.");
                clearResults();
		fetchScans(); 
            })
            .catch(error => {
                console.error('Error deleting scan:', error);
                showModal("Error", "Failed to delete the scan.");
            });
    });
}

function downloadResults(scanId, format) {
    if (storedScans[scanId]) {
        const data = storedScans[scanId];
        let dataStr;

        if (format === 'json') {
            dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data));
        } else if (format === 'csv') {
            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "Scan Time,Host,Port,Is Honeypot,Honeypot Type\n"; 

            const scanTime = new Date(parseInt(scanId.split(':')[2])).toISOString().replace(/T/, ' ').replace(/\..+/, ''); 

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

        const downloadElement = document.createElement('a');
        downloadElement.setAttribute('href', dataStr);
        downloadElement.setAttribute('download', `scan_results_${scanId}.${format}`);
        document.body.appendChild(downloadElement); 
        downloadElement.click(); 
        document.body.removeChild(downloadElement); 
    } else {
        console.error("No data found for scanId:", scanId);
    }
}

function showModal(title, message) {
    $('#infoModal .modal-title').text(title);
    $('#infoModal .modal-body').text(message);
    $('#infoModal').modal('show');
}
