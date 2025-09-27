const singleDomainForm = document.getElementById('singleDomainForm');
const csvForm = document.getElementById('csvForm');
const domainInput = document.getElementById('domainInput');
const emailBodyInput = document.getElementById('emailBodyInput')
const csvFileInput = document.getElementById('csvFile');
const fileInfo = document.getElementById('fileInfo');
const csvFormat = document.getElementById('csvFormat');
const resultsSection = document.getElementById('resultsSection');
const resultsTitle = document.getElementById('resultsTitle');
const processingProgress = document.getElementById('processingProgress');
const detectionInfo = document.getElementById('detectionInfo');
const singleResult = document.getElementById('singleResult');
const csvResults = document.getElementById('csvResults');
const domainList = document.getElementById('domainList');
const validateSingleBtn = document.getElementById('validateSingleBtn');
const validateCsvBtn = document.getElementById('validateCsvBtn');

const MAX_FILE_SIZE = 50 * 1024 * 1024;

document.addEventListener('DOMContentLoaded', function () {
    loadDomains();
});

// Handles CSV file selection
csvFileInput.addEventListener('change', function () {
    if (!csvFileInput.files || csvFileInput.files.length === 0) {
        fileInfo.innerHTML = '';
        csvFormat.value = 'Detected Headers...';
        return;
    }

    const file = csvFileInput.files[0];
    const fileSize = FileSize(file.size);
    fileInfo.innerHTML = `Selected file: ${file.name} (${fileSize})`;

    if (file.size > MAX_FILE_SIZE) {
        fileInfo.innerHTML += `<br><span class="error">File too big. Maximum size is ${FileSize(MAX_FILE_SIZE)}</span>`;
        validateCsvBtn.disabled = true;
        return;
    } else {
        validateCsvBtn.disabled = false;
    }

    csvFormat.value = 'Detecting headers...';

    // Extracts headers from CSV file
    const formData = new FormData();
    formData.append('csv_file', file);

    fetch('/get_headers', {
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                csvFormat.value = `Error: ${data.error}`;
            } else {
                csvFormat.value = data.headers.join(', ');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            csvFormat.value = 'Error detecting headers';
        });
});

// Formatting various file sizes
function FileSize(bytes) {
    if (bytes < 1024) return bytes + ' bytes';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    else return (bytes / 1048576).toFixed(1) + ' MB';
}

function loadDomains() {
    fetch('/domains')
        .then(response => response.json())
        .then(data => {
            updateDomainList(data.domains);
        })
        .catch(error => {
            console.error('Error loading domains:', error);
            domainList.innerHTML = '<span class="domain-tag">Error loading domains</span>';
        });
}

function updateDomainList(domains) {
    domainList.innerHTML = '';

    if (!domains || domains.length === 0) {
        domainList.innerHTML = '<span class="domain-tag">No domains loaded</span>';
        return;
    }

    // Show domains
    domains.forEach(domain => {
        const domainTag = document.createElement('span');
        domainTag.classList.add('domain-tag');
        domainTag.textContent = domain;
        domainList.appendChild(domainTag);
    });
}

// THIS IS THE PART WHERE THE USER SUBMITS THE SINGLE ITEM OF DOMAIN AND EMAIL BODY -ZQ
/* SO BASICALLY WHEN THE USER PRESS THE BUTTON TO DETECT IT WILL GET DATA OF THE INPUT*/
singleDomainForm.addEventListener('submit', function (e) {
    e.preventDefault();

    const domain = domainInput.value.trim();
    const emailBody = emailBodyInput.value.trim() //SPLITTING BOTH THE EMAIL ADDRESS/DOMAIN AND THE EMAIL BODY INTO VARIABLES
    if (!domain) {
        alert('Please enter a domain or email address'); //CHECKING IF THERE IS VALID INPUTS
        return;
    }

    if (!emailBody) {
        alert('Please enter email body!');
        return;
    }

    validateSingleBtn.innerHTML = '<div class="loading"></div> Validating...';
    validateSingleBtn.disabled = true; //DISABLES THE BUTTON

    const formData = new FormData(); //INITIALISING THE FORMDATA TO BE SEND TO APP.PY
    formData.append('domain', domain); // formData = {'domain': var domain}
    formData.append('emailBody', emailBody)// same as above

    fetch('/validate', { //THIS WILL REACT WITH APP.PY TO DO THE DETECTION OF PHISHING
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                error_msg(data.error);
            } else {
                const result = data.results[0];
                const isInvalid = result.is_invalid || !result.domain || result.domain === 'Invalid';
                const trustedCount = isInvalid ? 0 : (result.is_trusted ? 1 : 0);
                const phishingCount = isInvalid ? 0 : (result.is_trusted ? 0 : 1);
                const invalidCount = isInvalid ? 1 : 0;

                SingleDomainResult(result, trustedCount, phishingCount, invalidCount);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            error_msg('An error occurred while validating the domain.');
        })
        .finally(() => {
            validateSingleBtn.innerHTML = 'Validate Domain';
            validateSingleBtn.disabled = false;
        });
});

// HERE EDITS THE RESULTS MESSAGES - ZQ

function SingleDomainResult(result, trustedCount = 0, phishingCount = 0, invalidCount = 0) {
    resultsSection.style.display = 'block';
    resultsTitle.textContent = 'Validation Result';
    processingProgress.innerHTML = '';
    csvResults.innerHTML = '';

    let statusClass, statusIcon, statusText, riskMsg;

    if (result.is_invalid || !result.domain || result.domain === 'Invalid') {
        statusClass = 'error';
        statusIcon = '❌';
        statusText = 'INVALID DOMAIN';
    } else {
        statusClass = result.is_trusted ? 'safe' : 'phishing';
        statusIcon = result.is_trusted ? '✅' : '⚠️';
        statusText = result.is_trusted ? 'SAFE' : 'PHISHING';
    }
    if (result.bodyRiskMsg == []) {
        riskMsg = ''
    } else {
        riskMsg = (result.bodyRiskMsg).join('\n');
    }

    detectionInfo.innerHTML = `
        <div class="detection-info">
            <p>📊 <strong>Detection Summary:</strong> ${trustedCount} safe domain(s), ${phishingCount} phishing domain(s), ${invalidCount} invalid domain(s)</p>
        </div>
    `;
    //THIS DISPLAYS THE RESULTS MESSAGES
    singleResult.innerHTML = `
        <div class="result-item ${statusClass}">
            <p><strong>Email/Domain:</strong> ${result.email || 'Invalid format'}</p>
            <p><strong>Domain:</strong> ${result.domain || 'N/A'}</p>
            <p><strong>Status:</strong> ${statusIcon} ${statusText}</p>
            <p><strong>Message:</strong> ${result.message}</p>
            <p><strong>Risk Informations:</strong>${riskMsg}</p>
            <p><strong>Edit Distance Check:</strong> ${(result.edit_distance && result.edit_distance.message) || ''}</p>
        </div>
    `;
}

// THIS IS FOR THE CSV UPLOADS (ZQ HAVENT ADD IN HIS PART)
csvForm.addEventListener('submit', function (e) {
    e.preventDefault();

    if (!csvFileInput.files || csvFileInput.files.length === 0) {
        alert('Please select a CSV file to upload');
        return;
    }

    const file = csvFileInput.files[0];
    if (file.size > MAX_FILE_SIZE) {
        alert(`File too big. Maximum size is ${FileSize(MAX_FILE_SIZE)}`);
        return;
    }

    validateCsvBtn.innerHTML = '<div class="loading"></div> Processing...';
    validateCsvBtn.disabled = true;
    processingProgress.innerHTML = '<p>Processing file...</p>';

    const formData = new FormData();
    formData.append('csv_file', file);

    fetch('/validate', {
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            processingProgress.innerHTML = '';
            if (data.error) {
                error_msg(data.error);
            } else {
                const results = data.results;
                const trustedCount = results.filter(r => !r.is_invalid && r.is_trusted).length;
                const phishingCount = results.filter(r => !r.is_invalid && !r.is_trusted).length;
                const invalidCount = results.filter(r => r.is_invalid).length;

                CSVResult(results, data.row_count, trustedCount, phishingCount, invalidCount);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            processingProgress.innerHTML = '';
            error_msg('An error occurred while processing the CSV file: ' + error.message);
        })
        .finally(() => {
            validateCsvBtn.innerHTML = 'Validate CSV';
            validateCsvBtn.disabled = false;
        });
});

// CSV file validation results (ignores invalid email domains)
function CSVResult(results, rowCount, trustedCount, phishingCount) {
    resultsSection.style.display = 'block';
    resultsTitle.textContent = `CSV Validation Results (${rowCount} records processed)`;
    processingProgress.innerHTML = '';
    singleResult.innerHTML = '';

    if (results.length === 0) {
        detectionInfo.innerHTML = '<div class="detection-info"><p>❌ <strong>No sender email addresses found in the CSV file.</strong></p></div>';
        csvResults.innerHTML = '<p>Please check if your CSV file contains sender email addresses.</p>';
        return;
    }

    detectionInfo.innerHTML = `
        <div class="detection-info">
            <p>📊 <strong>Detection Summary:</strong> ${trustedCount} safe domains, ${phishingCount} phishing domains</p>
            <p>✅ <strong>Sender emails successfully detected and validated</strong></p>
        </div>
    `;

    // Displays first 100 results with an option to download full results
    const displayResults = results.slice(0, 100);

    let tableHTML = `
        <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Email</th>
                    <th>Domain</th>
                    <th>Status</th>
                    <th>Message</th>
                    <th>Edit Distance Check</th>
                </tr>
            </thead>
            <tbody>
    `;

    displayResults.forEach(result => {
        let statusClass, statusIcon, statusText;

        if (result.is_invalid || !result.domain || result.domain === 'Invalid') {
            statusClass = 'error';
            statusIcon = '❌';
            statusText = 'INVALID DOMAIN';
        } else {
            statusClass = result.is_trusted ? 'safe' : 'phishing';
            statusIcon = result.is_trusted ? '✅' : '⚠️';
            statusText = result.is_trusted ? 'SAFE' : 'PHISHING';
        }

        tableHTML += `
            <tr class="${statusClass}">
                <td>${result.email || 'N/A'}</td>
                <td>${result.domain || 'Invalid'}</td>
                <td>${statusIcon} ${statusText}</td>
                <td>${result.message}</td>
                <td>${(result.edit_distance && result.edit_distance.message) || ''}</td>
            </tr>
        `;
    });

    tableHTML += `
            </tbody>
        </table>
        </div>
    `;

    if (results.length > 100) {
        tableHTML += `<p>Showing first 100 results. Total records: ${results.length}</p>`;
    }

    tableHTML += `
        <button id="downloadResultsBtn" class="download-btn">Download Full Results as CSV</button>
    `;

    csvResults.innerHTML = tableHTML;

    document.getElementById('downloadResultsBtn').addEventListener('click', function () {
        downloadCSVResults(results);
    });
}

function downloadCSVResults(results) {
    const csvContent = [
        ['Email', 'Domain', 'Status', 'Message', 'Edit Distance Check'],
        ...results.map(r => {
            let status;
            if (r.is_invalid || !r.domain || r.domain === 'Invalid') {
                status = 'INVALID DOMAIN';
            } else {
                status = r.is_trusted ? 'SAFE' : 'PHISHING';
            }

            return [
                r.email || '',
                r.domain || '',
                status,
                r.message || '',
                (r.edit_distance && r.edit_distance.message) || ''
            ];
        })
    ].map(e => e.join(',')).join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', 'domains_validation_results.csv');
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function error_msg(message) {
    resultsSection.style.display = 'block';
    resultsTitle.textContent = 'Error';
    processingProgress.innerHTML = '';
    detectionInfo.innerHTML = '';
    singleResult.innerHTML = `
        <div class="result-item phishing">
            <p>❌ ${message}</p>
        </div>
    `;
    csvResults.innerHTML = '';
}
