document.addEventListener('DOMContentLoaded', function () {
    if (document.getElementById("searchInput")) {
        document.getElementById("searchInput").addEventListener("keyup", function() {
            var search = this.value.toLowerCase();
            $("#resultsTable tbody tr").filter(function() {
                $(this).toggle($(this).text().toLowerCase().indexOf(search) > -1)
            });
        });
    }
});

function startScan() {
    const host = document.getElementById('hostInput').value;
    const port = document.getElementById('portInput').value;
    const threads = document.getElementById('threadsInput').value;
    const proto = document.getElementById('protocolSelect').value;

    // Show the loading overlay
    document.getElementById('loadingOverlay').style.display = 'flex';

    // Call the honeydet API
    axios.get(`/scan?host=${host}&port=${port}&threads=${threads}&proto=${proto}`).then(response => {
        const data = response.data;
        populateTable(data);

        // Hide the loading overlay
        document.getElementById('loadingOverlay').style.display = 'none';
    }).catch(error => {
        console.error('Error:', error);
    });
}

function populateTable(data) {
    var tbody = document.getElementById("resultsTable").getElementsByTagName("tbody")[0];

    data.forEach(function(result) {
        var row = tbody.insertRow();
        var scanTimeCell = row.insertCell(0);
        var hostCell = row.insertCell(1);
        var portCell = row.insertCell(2);
        var isHoneypotCell = row.insertCell(3);
        var honeypotTypeCell = row.insertCell(4);

        scanTimeCell.innerHTML = new Date().toLocaleString();
        hostCell.innerHTML = result.Host;
        portCell.innerHTML = result.Port;
        isHoneypotCell.innerHTML = result.IsHoneypot ? 'Yes' : 'No';
        honeypotTypeCell.innerHTML = result.HoneypotType;

        row.className = result.IsHoneypot ? 'alert-honeypot' : 'alert-nonhoneypot';
    });
}

function sortTable(columnIndex) {
    var table, rows, switching, i, x, y, shouldSwitch;
    table = document.getElementById("resultsTable");
    switching = true;
        document.getElementById('loadingOverlay').style.display = 'flex';
	while (switching) {
        switching = false;
        rows = table.rows;
        for (i = 1; i < (rows.length - 1); i++) {
            shouldSwitch = false;
            x = rows[i].getElementsByTagName("TD")[columnIndex];
            y = rows[i + 1].getElementsByTagName("TD")[columnIndex];
            if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                shouldSwitch = true;
                break;
            }
        }
        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
        }
	}
	document.getElementById('loadingOverlay').style.display = 'none';
}

function downloadResults(format) {
    var data = [];

    $("#resultsTable tbody tr").each(function() {
        var row = $(this);
        var rowData = {
            ScanTime: row.find("td:eq(0)").text(),
            Host: row.find("td:eq(1)").text(),
            Port: row.find("td:eq(2)").text(),
            IsHoneypot: row.find("td:eq(3)").text(),
            HoneypotType: row.find("td:eq(4)").text()
        };
        data.push(rowData);
    });

    if (format === 'json') {
        var dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data));
        var dlAnchorElem = document.createElement('a');
        dlAnchorElem.setAttribute("href", dataStr);
        dlAnchorElem.setAttribute("download", "scan_results.json");
        dlAnchorElem.click();
    } else if (format === 'csv') {
        var csvContent = "data:text/csv;charset=utf-8," +
            data.map(e => Object.values(e).join(",")).join("\n");
        var encodedUri = encodeURI(csvContent);
        var link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", "scan_results.csv");
        document.body.appendChild(link);
        link.click();
    }
}

function displayResults(data) {
    var tbody = document.getElementById("resultsTable").getElementsByTagName("tbody")[0];

    data.forEach(function(result) {
        var row = tbody.insertRow();
        var scanTimeCell = row.insertCell(0);
        var hostCell = row.insertCell(1);
        scanTimeCell.innerHTML = new Date().toLocaleString();
        hostCell.innerHTML = result.Host;
        row.className = result.IsHoneypot ? 'alert-honeypot' : 'alert-nonhoneypot';
    });
}

document.addEventListener('DOMContentLoaded', function () {
    var clearBtn = document.getElementById("clearBtn");
    if (clearBtn) {
        clearBtn.addEventListener("click", function() {
            document.getElementById("resultsTable").getElementsByTagName("tbody")[0].innerHTML = '';
        });
    }
});
