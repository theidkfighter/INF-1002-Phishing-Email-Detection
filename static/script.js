const singleDomainForm = document.getElementById('singleDomainForm');
const csvForm = document.getElementById('csvForm');
const domainInput = document.getElementById('domainInput');
const subjectTitleInput = document.getElementById('subjectTitleInput')
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

// Handles CSV file uploads
csvFileInput.addEventListener('change', function () {
    if (!csvFileInput.files || csvFileInput.files.length === 0) {
        fileInfo.innerHTML = '';
        csvFormat.value = 'Detected Headers...';
        return;
    }

    const file = csvFileInput.files[0];
    const fileSize = FileSize(file.size);
    fileInfo.innerHTML = `<strong>Selected file</strong>: ${file.name} (${fileSize})`;

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

    // Shows list of whitelisted email domains
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

    csvResults.innerHTML = '';
    detectionInfo.innerHTML = '';
    
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

// Results from the Single Domain Validation
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
    
    // Formats risk message
    if (!result.bodyRiskMsg || result.bodyRiskMsg.length === 0) {
        riskMsg = 'No suspicious URLs detected';
    } else {
        riskMsg = result.bodyRiskMsg.map(msg => `• ${msg}`).join('<br>');
    }

    // Formats flagged keywords
    let keywordDisplay = 'No suspicious keywords detected';
    if (result.flagged_keyword && result.flagged_keyword.length > 0) {
        keywordDisplay = result.flagged_keyword.map(word => `• "${word}"`).join('<br>');
    }

    // Formats edit distance message
    let editDistanceMsg = 'No similar domains found';
    if (result.edit_distance && result.edit_distance.message) {
        editDistanceMsg = result.edit_distance.message;
    }

    // Formats scoring details
    let detailsDisplay = '';
    if (result.details && result.details.length > 0) {
        detailsDisplay = result.details.map(detail => `• ${detail}`).join('<br>');
    }

    // Display validation result message
    singleResult.innerHTML = `
        <div class="result-item ${statusClass}">
            <div class="result-header">
                <h3>${statusIcon} ${statusText}</h3>
                <p class="result-message">${result.message}</p>
            </div>
            
            <div class="result-details">
                <div class="detail-row">
                    <span class="detail-label">Email/Domain:</span>
                    <span class="detail-value">${result.email || 'Invalid format'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Domain:</span>
                    <span class="detail-value">${result.domain || 'N/A'}</span>
                </div>
                
                <div class="risk-section">
                    <h4>Risk Assessment</h4>
                    <div class="detail-row">
                        <span class="detail-label">Risk Level:</span>
                        <span class="detail-value risk-${result.risk_level?.toLowerCase() || 'na'}">${result.risk_level || 'N/A'}</span>
                    </div>
                    ${result.final_score !== undefined && result.final_score !== null && result.final_score !== 'N/A' ? `
                    <div class="detail-row">
                        <span class="detail-label">Risk Score:</span>
                        <span class="detail-value">${result.final_score}</span>
                    </div>
                    ` : ''}
                </div>
                
                <div class="detection-section">
                    <h4>Detection Details</h4>
                    
                    <div class="detection-item">
                        <strong>URL Analysis:</strong>
                        <div class="detection-content">${riskMsg}</div>
                    </div>
                    
                    <div class="detection-item">
                        <strong>Keyword Analysis:</strong>
                        <div class="detection-content">
                            <span class="risk-rating">${result.keyword_risk_level || 'N/A'} chance of phishing</span>
                            ${keywordDisplay !== 'No suspicious keywords detected' ? `<div class="flagged-keywords">${keywordDisplay}</div>` : ''}
                        </div>
                    </div>
                    
                    <div class="detection-item">
                        <strong>Domain Similarity Check:</strong>
                        <div class="detection-content">${editDistanceMsg}</div>
                    </div>
                    
                    ${detailsDisplay ? `
                    <div class="detection-item">
                        <strong>Scoring Details:</strong>
                        <div class="detection-content">${detailsDisplay}</div>
                    </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `;

}

// Validation of CSV file contents
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
                const trustedCount = data.trusted_count || 0;
                const phishingCount = data.phishing_count || 0;
                const invalidCount = data.invalid_count || 0;
                const noEmailCount = data.no_email_count || 0;
                const rowCount = data.row_count || results.length;

                CSVResult(results, rowCount, trustedCount, phishingCount, invalidCount, noEmailCount);    

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

// CSV file validation results (ignores rows with invalid/no email domains)
function CSVResult(results, rowCount, trustedCount, phishingCount, invalidCount, noEmailCount) {
    resultsSection.style.display = 'block';
    resultsTitle.textContent = `CSV Validation Results (${rowCount} records processed)`;
    processingProgress.innerHTML = '';
    singleResult.innerHTML = '';

    if (results.length === 0) {
        detectionInfo.innerHTML = '<div class="detection-info"><p>❌ <strong>No data found in the CSV file.</strong></p></div>';
        csvResults.innerHTML = '<p>Please check if your CSV file contains valid domain data.</p>';
        return;
    }

    // CSV Summary Validation Results
    detectionInfo.innerHTML = `
        <div class="detection-info">
        <p>📊 <strong>File Analysis:</strong> ${rowCount} data rows processed</p>
        <p>🔍 <strong>Detection Summary:</strong> ${trustedCount} safe domains, ${phishingCount} phishing domains, ${invalidCount} invalid domains</p>
        ${noEmailCount > 0 ? `<p>📝 <strong>Note:</strong> ${noEmailCount} rows contained no email addresses</p>` : ''}
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
                    <th>Risk Level</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
    `;

    // Display format for CSV file validaion results
    displayResults.forEach(result => {
        let statusClass, statusIcon, statusText;
        
        if (result.risk_level === "SAFE") {
            statusClass = 'safe';
            statusIcon = '✅';
            statusText = 'SAFE';
        } else if (result.risk_level === "PHISHING") {
            statusClass = 'phishing';
            statusIcon = '⚠️';
            statusText = 'PHISHING';
        } else if (result.risk_level === "INVALID DOMAIN") {
            statusClass = 'error';
            statusIcon = '';
            statusText = 'INVALID DOMAIN';
        } else {
            statusClass = 'error';
            statusIcon = '';
            statusText = result.risk_level || 'UNKNOWN';
        }
        
        // Add relevant details to the result
        let details = [];
        if (result.edit_distance_message && result.edit_distance_message !== "Domain is trusted") {
            details.push(`• ${result.edit_distance_message}`);
        }
        if (result.url_detection_messages && result.url_detection_messages.length > 0) {
            details.push(`• ${result.url_detection_messages.length} suspicious URL(s)`);
        }
        if (result.flagged_keywords && result.flagged_keywords.length > 0) {
            details.push(`• ${result.flagged_keywords.length} suspicious keyword(s)`);
        }
        
        const detailsText = details.length > 0 ? details.join('<br>') : 'No suspicious indicators';
        
        tableHTML += `
            <tr class="${statusClass}">
                <td>${result.email || 'N/A'}</td>
                <td>${result.domain || 'N/A'}</td>
                <td>${statusIcon} ${statusText}</td>
                <td>${detailsText}</td>
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
    
    document.getElementById('downloadResultsBtn').addEventListener('click', function() {
        downloadCSVResults(results);
    });

}



// Download CSV file validation results
function downloadCSVResults(results) {
    const csvContent = [
        ['Email', 'Domain', 'Status', 'Message', 'Keyword Warnings', 'URL Warnings'],
        ...results.map(r => {
            
            const urlWarnings = r.url_detection_messages ? r.url_detection_messages.join('; ') : '';
            const keywordWarnings = r.flagged_keywords ? r.flagged_keywords.join('; ') : '';

            return [
                r.email || '',
                r.domain || '',
                r.risk_level || '',
                r.edit_distance_message || '',
                keywordWarnings,
                urlWarnings
            ];
        })
    ].map(e => e.map(field => `"${field}"`).join(',')).join('\n');

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
            <p>${message}</p>
        </div>
    `;
    csvResults.innerHTML = '';
}
