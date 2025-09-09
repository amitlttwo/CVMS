document.addEventListener('DOMContentLoaded', function() {
    const domainInput = document.getElementById('domainInput');
    const searchBtn = document.getElementById('searchBtn');
    const exportTxtBtn = document.getElementById('exportTxtBtn');
    const exportJsonBtn = document.getElementById('exportJsonBtn');
    const resultsContainer = document.getElementById('resultsContainer');
    const loader = document.getElementById('loader');
    const countElement = document.getElementById('resultsCount');
    const progressSection = document.getElementById('progressSection');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const scanStage = document.getElementById('scanStage');
    const filters = document.getElementById('filters');
    const filterInput = document.getElementById('filterInput');
    const statusFilter = document.getElementById('statusFilter');
    const cloudflareFilter = document.getElementById('cloudflareFilter');
    const protocolFilter = document.getElementById('protocolFilter');
    const statsSection = document.getElementById('statsSection');
    const statFound = document.getElementById('statFound');
    const statActive = document.getElementById('statActive');
    const statCloudflare = document.getElementById('statCloudflare');
    const statTime = document.getElementById('statTime');
    
    let currentScanId = null;
    let progressInterval = null;
    let currentResults = [];
    let startTime = null;
    
    searchBtn.addEventListener('click', startSearch);
    domainInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') startSearch();
    });
    
    exportTxtBtn.addEventListener('click', () => exportResults('txt'));
    exportJsonBtn.addEventListener('click', () => exportResults('json'));
    
    filterInput.addEventListener('input', applyFilters);
    statusFilter.addEventListener('change', applyFilters);
    cloudflareFilter.addEventListener('change', applyFilters);
    protocolFilter.addEventListener('change', applyFilters);
    
    function showNotification(message, type = 'success') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }
    
    function startSearch() {
        const domain = domainInput.value.trim();
        
        if (!domain) {
            showNotification('Please enter a domain name', 'error');
            return;
        }
        
        // Clear previous results
        resultsContainer.innerHTML = '';
        loader.style.display = 'block';
        progressSection.style.display = 'block';
        statsSection.style.display = 'grid';
        filters.style.display = 'none';
        countElement.textContent = '0';
        statFound.textContent = '0';
        statActive.textContent = '0';
        statCloudflare.textContent = '0';
        statTime.textContent = '0s';
        exportTxtBtn.disabled = true;
        exportJsonBtn.disabled = true;
        
        // Reset progress and start timer
        updateProgress(0, 'Initializing scan engine...');
        startTime = Date.now();
        updateTimer();
        
        // Send request to backend
        fetch('/api/enumerate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ domain: domain })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showNotification('Error: ' + data.error, 'error');
                loader.style.display = 'none';
                progressSection.style.display = 'none';
                return;
            }
            
            currentScanId = data.scan_id;
            
            // Start polling for results
            progressInterval = setInterval(checkScanProgress, 1000);
        })
        .catch(error => {
            loader.style.display = 'none';
            progressSection.style.display = 'none';
            showNotification('Error connecting to the server: ' + error, 'error');
        });
    }
    
    function updateTimer() {
        if (!startTime) return;
        
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        statTime.textContent = `${elapsed}s`;
        
        if (progressInterval) {
            setTimeout(updateTimer, 1000);
        }
    }
    
    function checkScanProgress() {
        if (!currentScanId) return;
        
        fetch(`/api/scan/${currentScanId}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'completed') {
                    // Scan completed
                    clearInterval(progressInterval);
                    loader.style.display = 'none';
                    progressSection.style.display = 'none';
                    filters.style.display = 'grid';
                    updateProgress(100, 'Scan completed!');
                    currentResults = data.subdomains;
                    displayResults(currentResults);
                    updateStats(currentResults);
                    showNotification(`Scan completed! Found ${data.count} subdomains in ${statTime.textContent}.`);
                    exportTxtBtn.disabled = false;
                    exportJsonBtn.disabled = false;
                } else if (data.status === 'error') {
                    // Scan error
                    clearInterval(progressInterval);
                    loader.style.display = 'none';
                    progressSection.style.display = 'none';
                    showNotification('Scan error: ' + data.error, 'error');
                } else if (data.progress) {
                    // Update progress
                    updateProgress(data.progress, data.status || 'Processing...');
                    
                    // Update stats with partial results
                    if (data.subdomains && data.subdomains.length > 0) {
                        currentResults = data.subdomains;
                        displayResults(currentResults);
                        updateStats(currentResults);
                    }
                } else {
                    // Still processing
                    updateProgress(5, 'Starting scan...');
                }
            })
            .catch(error => {
                console.error('Error checking scan status:', error);
            });
    }
    
    function updateProgress(percentage, stage) {
        progressFill.style.width = `${percentage}%`;
        progressText.textContent = `Progress: ${Math.round(percentage)}%`;
        scanStage.textContent = stage;
    }
    
    function updateStats(subdomains) {
        if (!subdomains) return;
        
        const active = subdomains.filter(sub => sub.http_status || sub.https_status).length;
        const cloudflare = subdomains.filter(sub => sub.cloudflare === 'Enabled').length;
        
        statFound.textContent = subdomains.length;
        statActive.textContent = active;
        statCloudflare.textContent = cloudflare;
        countElement.textContent = subdomains.length;
    }
    
    function displayResults(subdomains) {
        if (!subdomains || subdomains.length === 0) {
            resultsContainer.innerHTML = '<tr><td colspan="7" class="no-results">No subdomains found yet. Scanning in progress...</td></tr>';
            return;
        }
        
        let html = '';
        
        subdomains.forEach(subdomain => {
            const isActive = subdomain.http_status || subdomain.https_status;
            const statusClass = isActive ? 'status-active' : 'status-inactive';
            const statusText = isActive ? 'Active' : 'Inactive';
            
            const cfClass = `cf-${subdomain.cloudflare.toLowerCase()}`;
            
            html += `
                <tr>
                    <td><strong>${subdomain.subdomain}</strong></td>
                    <td>${subdomain.ip || 'N/A'}</td>
                    <td><span class="status-badge ${subdomain.http_status ? 'status-active' : 'status-inactive'}">${subdomain.http_status || 'N/A'}</span></td>
                    <td><span class="status-badge ${subdomain.https_status ? 'status-active' : 'status-inactive'}">${subdomain.https_status || 'N/A'}</span></td>
                    <td>${subdomain.server || 'N/A'}</td>
                    <td><span class="${cfClass}">${subdomain.cloudflare}</span></td>
                    <td>
                        <button class="action-btn" onclick="window.open('http://${subdomain.subdomain}', '_blank')">View</button>
                    </td>
                </tr>
            `;
        });
        
        resultsContainer.innerHTML = html;
    }
    
    function applyFilters() {
        if (!currentResults.length) return;
        
        const searchText = filterInput.value.toLowerCase();
        const statusValue = statusFilter.value;
        const cloudflareValue = cloudflareFilter.value;
        const protocolValue = protocolFilter.value;
        
        const filteredResults = currentResults.filter(subdomain => {
            // Text filter
            if (searchText && !subdomain.subdomain.toLowerCase().includes(searchText)) {
                return false;
            }
            
            // Status filter
            const isActive = subdomain.http_status || subdomain.https_status;
            if (statusValue === 'active' && !isActive) return false;
            if (statusValue === 'inactive' && isActive) return false;
            
            // Cloudflare filter
            if (cloudflareValue === 'enabled' && subdomain.cloudflare !== 'Enabled') return false;
            if (cloudflareValue === 'disabled' && subdomain.cloudflare !== 'Disabled') return false;
            
            // Protocol filter
            if (protocolValue === 'http' && !subdomain.http_status) return false;
            if (protocolValue === 'https' && !subdomain.https_status) return false;
            
            return true;
        });
        
        displayResults(filteredResults);
        countElement.textContent = filteredResults.length;
    }
    
    function exportResults(format) {
        if (!currentScanId) {
            showNotification('No scan results to export', 'error');
            return;
        }
        
        window.open(`/api/export/${currentScanId}/${format}`, '_blank');
    }
});
