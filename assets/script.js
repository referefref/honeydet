var storedScans = {};
var hasNewScans = false;
var currentSort = { column: 'startTime', direction: 'desc' };

let confirmCallback = null;
let scansOverTimeChart, hostsByPingResponseChart, hostsByHoneypotTypeChart, hostsByIsHoneypotChart, detectionsByPortChart;
let chartsInitialized = false;

document.addEventListener('DOMContentLoaded', function () {
	fetchScans();
	applyDefaultSort();
	setInterval(function() {
		if (hasNewScans) {
			fetchScans();
		}
	}, 1000);
	
	var headers = document.querySelectorAll('#scanExecutionsTable thead th');
			headers.forEach(function(header, index) {
			header.addEventListener('click', function() {
				sortTableByColumn('scanExecutionsTable', index);
			});
		});

	var darkModeToggle = document.getElementById('darkModeToggle');
	if (darkModeToggle) {
			darkModeToggle.addEventListener('click', function() {
			document.body.classList.toggle('dark-mode');
			toggleChartThemes();
			});
		}

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
				confirmCallback = null; 
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

		var scanExecutionsRowCount = document.getElementById('scanExecutionsRowCount');
	if (scanExecutionsRowCount) {
		scanExecutionsRowCount.addEventListener('change', function() {
				console.log("Rows per page changed to:", this.value);
			updatePaginationControls('scanExecutionsTable', this.value);
			paginateTable('scanExecutionsTable', 1, this.value);
		});
	} else {
		console.error("Element 'scanExecutionsRowCount' not found");
	}

	var resultsRowCount = document.getElementById('resultsRowCount');
	if (resultsRowCount) {
		resultsRowCount.addEventListener('change', function() {
			updatePaginationControls('resultsTable', this.value);
			paginateTable('resultsTable', 1, this.value);
		});
	} else {
		console.error("Element 'resultsRowCount' not found");
	}

	document.querySelectorAll('.comment-col').forEach(cell => {
		cell.addEventListener('mouseover', function() {
			const commentDiv = this.querySelector('.comment-content');
			if (commentDiv) {
				commentDiv.style.width = this.offsetWidth + 'px';
			}
		});
	});

});

function formatShodanData(shodanInfo) {
	if (!shodanInfo || shodanInfo === 'null' || shodanInfo.trim() === '') {
		return 'No Shodan data available';
	}
	try {
		// Parse the JSON string and then stringify it with indentation
		var parsedJson = JSON.parse(shodanInfo);
		var prettyJson = JSON.stringify(parsedJson, null, 2); // Indent with 2 spaces
		return `<pre class="shodan-info-container">${prettyJson}</pre>`; // Use <pre> tag for formatted display
	} catch (e) {
		return 'Invalid JSON data';
	}
}

function toggleChartThemes() {

	var darkModeEnabled = document.body.classList.contains('dark-mode');

	if (hostsByHoneypotTypeChart) {
		hostsByHoneypotTypeChart.setThemes([
			am5themes_Animated.new(root3), 
			darkModeEnabled ? am5themes_Dark.new(root3): am5themes_Animated.new(root3)
		//darkModeEnabled ? am5themes_Dark.new(root3) : am5themes_Default.new(root3)
		]);
		hostsByHoneypotTypeChart.invalidateData(); 
	}

	if (hostsByIsHoneypotChart) {
		hostsByIsHoneypotChart.setThemes([
			am5themes_Animated.new(root4), 
			darkModeEnabled ? am5themes_Dark.new(root4) : am5themes_Default.new(root4)
		]);
		hostsByIsHoneypotChart.invalidateData(); 
	}

	if (detectionsByPortChart) {
		detectionsByPortChart.setThemes([
			am5themes_Animated.new(root5), 
			darkModeEnabled ? am5themes_Dark.new(root5) : am5themes_Default.new(root5)
		]);
		detectionsByPortChart.invalidateData(); 
	}
}

function sortTableByColumn(tableId, columnIndex) {
	var table = document.getElementById(tableId);
	var tbody = table.querySelector('tbody');
	var rows = Array.from(tbody.querySelectorAll('tr'));

	var isAscending = currentSort.column === columnIndex && currentSort.direction === 'asc';
	currentSort = { column: columnIndex, direction: isAscending ? 'desc' : 'asc' };

	rows.sort(function (a, b) {
		var cellA = a.querySelectorAll('td')[columnIndex].textContent.toLowerCase();
		var cellB = b.querySelectorAll('td')[columnIndex].textContent.toLowerCase();

		if (columnIndex === 0) { 
			cellA = new Date(cellA).getTime();
			cellB = new Date(cellB).getTime();
		}

		if (cellA < cellB) return isAscending ? -1 : 1;
		if (cellA > cellB) return isAscending ? 1 : -1;
		return 0;
	});

	rows.forEach(function(row) {
		tbody.appendChild(row);
	});
}

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

function applyDefaultSort() {
	sortTableByColumn('scanExecutionsTable', 0); 
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
			const ServerScanId = response.data.scan_id;
			console.log("Scan started. ScanId:", ServerScanId);

			addScanToExecutionList({
				scan_id: scanId,
				start_time: new Date().toLocaleString(),
				hosts: host.split(','),
				ports: port.split(','),
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
			console.error('Error starting scan:', error);
		});
}

function pollForScanCompletion(scanId) {
	const checkCompletion = setInterval(() => {
		axios.get(`/getScans`)
			.then(response => {
				const scan = response.data.find(s => s.scan_id === scanId);
				if (scan) {
					if (scan.end_time || scan.status === 'Failed') {
						clearInterval(checkCompletion);
						storedScans[scanId] = scan;
						updateScanExecutionList(scan);
						console.log("Scan updated. ScanId:", scanId, "Final Scan Data:", scan);
					}
				}
			})
			.catch(error => {
				console.error('Error fetching scan status:', error);
				clearInterval(checkCompletion);
				handleFailedScan(scanId);
			});
	}, 1000);
}

function handleFailedScan(scanId) {
	if (storedScans[scanId]) {
		storedScans[scanId].status = 'Failed';
		updateScanExecutionList({
			scan_id: scanId,
			status: 'Failed',
			...storedScans[scanId]
		});
	}
}

function updateScanExecutionList(scan) {
	var row = document.querySelector(`#scanExecutionsTable tbody tr[data-scan-id="${scan.scan_id}"]`);
	if (row) {
		row.cells[1].innerHTML = scan.end_time ? new Date(scan.end_time).toLocaleString() : 'Running';
		row.cells[2].innerHTML = scan.target_hosts ? scan.target_hosts.join(", ") : 'N/A'; 
		row.cells[3].innerHTML = scan.target_ports ? scan.target_ports.join(", ") : 'N/A'; 
	row.cells[4].innerHTML = 'Completed';
		row.cells[5].innerHTML = getActionButtonsHTML(scan.scan_id);
		row.setAttribute('data-start-time', scan.start_time);
		sortScanExecutionTable();
	} else {
		addScanToExecutionList(scan);
	}
	sortScanExecutionTable();
}

function sortScanExecutionTable() {
	var tbody = document.getElementById("scanExecutionsTable").getElementsByTagName("tbody")[0];
	var rows = Array.from(tbody.rows);

	rows.sort(function(a, b) {
		var dateA = new Date(a.getAttribute('data-start-time'));
		var dateB = new Date(b.getAttribute('data-start-time'));
		return dateB - dateA; 
	});

	rows.forEach(function(row) {
		tbody.appendChild(row);
	});
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

	row.setAttribute('data-start-time', scan.start_time);
	row.dataset.scanId = scan.scan_id;

	sortScanExecutionTable();
}

function fetchScans() {
	console.log("Fetching scans...");
	axios.get('/getScans')
		.then(response => {
			console.log("Scans fetched, processing data...");
			const scans = response.data;

			if (!scans || !Array.isArray(scans)) {
				console.error('Invalid scan data received:', scans);
				return;
			}

			clearScanExecutionsTable();
			scans.forEach(scan => {
				storedScans[scan.scan_id] = {
					hosts: scan.target_hosts,
					ports: scan.target_ports,
					results: scan.results,
					status: scan.end_time ? 'Completed' : 'New'
				};
				addScanToExecutionList(scan);
			});
			autoRefreshForNewScans();

				updatePaginationControls('scanExecutionsTable', 5); 
				paginateTable('scanExecutionsTable', 1, 5);

			const processedData = processDataForCharts(scans);
			if (chartsInitialized) {
				updateCharts(processedData);
			} else {
				
				var checkChartsInitialized = setInterval(() => {
					if (chartsInitialized) {
						clearInterval(checkChartsInitialized);
						updateCharts(processedData);
					}
				}, 500); 
			}
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
	if (tbody) {
		row.dataset.scanTime = scan.start_time;
	}

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

	row.setAttribute('data-start-time', scan.start_time);
	sortScanExecutionTable();
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
	return `
		<div class="action-buttons">
			<button class="btn btn-primary btn-sm" onclick="viewResults('${scanId}')">View Results</button>
			<button class="btn btn-success btn-sm ml-2" onclick="downloadResults('${scanId}', 'json')">JSON</button>
			<button class="btn btn-success btn-sm ml-2" onclick="downloadResults('${scanId}', 'csv')">CSV</button>
			<button class="btn btn-danger btn-sm ml-2" onclick="deleteScan('${scanId}')"><i class="fas fa-times"></i></button>
		</div>`;
}

function formatCommaSeparatedValues(str) {
	return str.split(',').join(', ');
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

		const chartData = processDataForCharts([scan]); 

		initializeAndUpdateCharts(chartData);

		toggleChartVisibility('hostsByHoneypotTypeChartDiv', true);
		toggleChartVisibility('hostsByIsHoneypotChartDiv', true);
		toggleChartVisibility('detectionsByPortChartDiv', true);

		updatePaginationControls('resultsTable', 20);
		paginateTable('resultsTable', 1, 20);
	} else {
		console.error('No data or invalid data found for scanId:', scanId);
	}
}

function toggleChartVisibility(chartDivId, isVisible) {
	var chartDiv = document.getElementById(chartDivId);
	var heading = chartDiv.previousElementSibling; 
	if (chartDiv && heading) {
		chartDiv.style.display = isVisible ? 'block' : 'none';
		heading.style.display = isVisible ? 'block' : 'none';
	}
}


function showChartWithHeading(chartDivId) {
	var chartDiv = document.getElementById(chartDivId);
	var heading = chartDiv.previousElementSibling; 
	if (chartDiv && heading) {
		chartDiv.style.display = 'block';
		heading.classList.remove('hidden');
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
		var confidenceCell = row.insertCell(5);
		var commentCell = row.insertCell(6);

		detectionTimeCell.innerHTML = result.detection_time ? new Date(result.detection_time).toLocaleString() : 'N/A';
		hostCell.innerHTML = result.host || 'N/A';
		/* hostCell.className = 'wrap-cell'; */
		portCell.innerHTML = result.port || 'N/A';
		isHoneypotCell.innerHTML = result.is_honeypot ? 'Yes' : 'No';
		honeypotTypeCell.innerHTML = result.honeypot_type || 'N/A';
		confidenceCell.innerHTML = result.confidence || 'N/A';
		commentCell.innerHTML = result.comment || 'N/A';
		
		hostCell.className = 'host-col';
		detectionTimeCell.className = 'time-col';
		/* portCell.className = 'port-col'; */
		isHoneypotCell.className = 'honeypot-col';
		honeypotTypeCell.className = 'type-col';
		confidenceCell.className = 'confidence-col';
		commentCell.className = 'wrap-cell';

		row.className = result.is_honeypot ? 'alert-honeypot' : 'alert-nonhoneypot';

		row.addEventListener('click', function() {
			var shodanRow = this.nextElementSibling;
			if (shodanRow && shodanRow.classList.contains('shodan-info')) {
				shodanRow.style.display = shodanRow.style.display === 'none' ? '' : 'none';
			}
		});

		if (result.shodan_info && result.shodan_info !== 'null' && result.shodan_info.trim() !== '') {
			var shodanRow = tbody.insertRow();
			shodanRow.className = 'shodan-info';
			shodanRow.style.display = 'none';
			var shodanCell = shodanRow.insertCell(0);
			shodanCell.colSpan = 7;
			shodanCell.innerHTML = formatShodanData(result.shodan_info);
		}
		updatePaginationControls('resultsTable', 20);
			paginateTable('resultsTable', 1, 20);

	});
}

function clearResults() {
	var table = document.getElementById("resultsTable");
	if (table) {
		table.getElementsByTagName("tbody")[0].innerHTML = '';
		toggleChartVisibility('hostsByHoneypotTypeChartDiv', false);
		toggleChartVisibility('hostsByIsHoneypotChartDiv', false);
		toggleChartVisibility('detectionsByPortChartDiv', false);
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
		const data = storedScans[scanId].map(row => {
			if (row.Port && row.Port.includes(",")) {
				row.Port = formatCommaSeparatedValues(row.Port);
			}
			return row;
		});

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

function initializeAndUpdateCharts(data) {
	console.log(data);
	if (!chartsInitialized) {
		initializeCharts();
		chartsInitialized = true;
	}
	updateCharts(data);
}

function initializeCharts() {
	am5.ready(function() {
		console.log("Initializing charts...");

		var root3 = am5.Root.new("hostsByHoneypotTypeChartDiv");
		hostsByHoneypotTypeChart = root3.container.children.push(am5percent.PieChart.new(root3, { layout: root3.horizontalLayout }));
		var honeypotTypeSeries = hostsByHoneypotTypeChart.series.push(am5percent.PieSeries.new(root3, { valueField: "count", categoryField: "type" }));
		honeypotTypeSeries.labels.template.set("forcehidden", true);

		var root4 = am5.Root.new("hostsByIsHoneypotChartDiv");
		hostsByIsHoneypotChart = root4.container.children.push(am5percent.PieChart.new(root4, { layout: root4.horizontalLayout }));
		var isHoneypotSeries = hostsByIsHoneypotChart.series.push(am5percent.PieSeries.new(root4, { valueField: "count", categoryField: "category" }));

		var root5 = am5.Root.new("detectionsByPortChartDiv");
		detectionsByPortChart = root5.container.children.push(am5percent.PieChart.new(root5, { layout: root5.horizontalLayout }));
		var detectionsByPortSeries = detectionsByPortChart.series.push(am5percent.PieSeries.new(root5, { valueField: "count", categoryField: "port" }));

		chartsInitialized = true;
		console.log("Charts initialized.");

		updateChartLegendLabels(hostsByHoneypotTypeChart);
		updateChartLegendLabels(hostsByIsHoneypotChart);
		updateChartLegendLabels(detectionsByPortChart);
			toggleChartVisibility('hostsByHoneypotTypeChartDiv', false);
			toggleChartVisibility('hostsByIsHoneypotChartDiv', false);
			toggleChartVisibility('detectionsByPortChartDiv', false);
		addChartHeading('hostsByHoneypotTypeChartDiv', 'Hosts By Honeypot Type');
		addChartHeading('hostsByIsHoneypotChartDiv', 'Hosts By Is Honeypot');
		addChartHeading('detectionsByPortChartDiv', 'Detections By Port');
	});
}

function addChartHeading(chartDivId, headingText) {
	var chartDiv = document.getElementById(chartDivId);
	if (chartDiv) {
		var heading = document.createElement('h4'); 
		heading.textContent = headingText;
		heading.classList.add('chart-heading', 'hidden'); 
		chartDiv.parentNode.insertBefore(heading, chartDiv);
	}
}

function updateChartLegendLabels(chart) {
	if (chart && chart.legend && chart.legend.labels && chart.legend.labels.template) {
		chart.legend.labels.template.set("forceHidden", true);
		console.log("Updated legend labels to be hidden");
	} else {
		console.error("Chart or legend not initialized", chart);
	}
}

function updateCharts(data) {
	console.log("Updating charts with data:", data);
	if (chartsInitialized) {
		console.log("Charts are initialized, setting data...");
		try {
			hostsByHoneypotTypeChart.series.values[0].data.setAll(data.hostsByHoneypotTypeData);

			hostsByIsHoneypotChart.series.values[0].data.setAll(data.hostsByIsHoneypotData);

			detectionsByPortChart.series.values[0].data.setAll(data.detectionsByPortData);

			console.log("Charts updated.");
		} catch (error) {
			console.error("Error updating charts:", error);
		}
	} else {
		console.log("Charts not initialized yet.");
	}
}

function processDataForCharts(scansData) {
	let hostsByHoneypotTypeData = {};
	let hostsByIsHoneypotData = { 'Honeypot': 0, 'Not-Honeypot': 0 };
	let detectionsByPortData = {};

	scansData.forEach(scan => {
		let honeypotDetected = false;

		scan.results.forEach(result => {
			if (result.is_honeypot) {
				honeypotDetected = true;
				const type = result.honeypot_type || 'Unknown';
				hostsByHoneypotTypeData[type] = (hostsByHoneypotTypeData[type] || 0) + 1;
			}

			const category = result.is_honeypot ? 'Honeypot' : 'Not-Honeypot';
			hostsByIsHoneypotData[category]++;

			const port = result.port.toString();
			detectionsByPortData[port] = (detectionsByPortData[port] || 0) + 1;
		});

		if (!honeypotDetected) {
			hostsByHoneypotTypeData['None'] = 1;
		}
	});

	let formattedHostsByHoneypotTypeData = Object.keys(hostsByHoneypotTypeData).map(type => ({
		type: type,
		count: hostsByHoneypotTypeData[type]
	}));

	let formattedHostsByIsHoneypotData = Object.keys(hostsByIsHoneypotData).map(category => ({
		category: category,
		count: hostsByIsHoneypotData[category]
	}));

	let formattedDetectionsByPortData = Object.keys(detectionsByPortData).map(port => ({
		port: port,
		count: detectionsByPortData[port]
	}));

	return {
		hostsByHoneypotTypeData: formattedHostsByHoneypotTypeData,
		hostsByIsHoneypotData: formattedHostsByIsHoneypotData,
		detectionsByPortData: formattedDetectionsByPortData
	};
}

function paginateTable(tableId, page, rowsPerPage) {
	var table = document.getElementById(tableId);
	var tr = table.getElementsByTagName('tr');

	var start = (page - 1) * rowsPerPage + 1;
	var end = start + rowsPerPage;

	for (var i = 1; i < tr.length; i++) {
		if (i >= start && i < end) {
			tr[i].style.display = ''; 
		} else {
			tr[i].style.display = 'none'; 
		}
	}
}

function updatePaginationControls(tableId, rowsPerPage) {
	console.log("Updating pagination controls for:", tableId);
	var paginationUlId;
	if (tableId === 'scanExecutionsTable') {
		paginationUlId = 'paginationScanExecutions';
	} else {
		paginationUlId = 'paginationResults';
	}
	console.log("paginationUlId=", paginationUlId);
	var paginationUl = document.getElementById(paginationUlId);
	console.log("paginationUl", paginationUl);

	if (paginationUl) {
		paginationUl.innerHTML = '';
		var tr = document.getElementById(tableId).getElementsByTagName('tr');
		var pageCount = Math.ceil((tr.length - 1) / rowsPerPage);

		for (let i = 1; i <= pageCount; i++) {
			var li = document.createElement('li');
			li.className = 'page-item';
			li.innerHTML = `<a class="page-link" href="#" onclick="paginateTable('${tableId}', ${i}, ${rowsPerPage})">${i}</a>`;
			paginationUl.appendChild(li);
		}
	} else {
		console.error('Pagination UL not found for tableId:', tableId);
	}
}
