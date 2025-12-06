const API_URL = '/api/cves'; 
const STATS_URL = '/api/stats';
const UPLOAD_URL = '/api/upload';
const LIMIT = 20; 

// --- CHART DEFAULTS ---
Chart.defaults.color = '#94a3b8'; 
Chart.defaults.borderColor = '#334155'; 

// --- State ---
let currentPage = 1;
let currentQuery = '';
let currentSearchResults = []; 
let cvssChartInstance = null;
let trendChartInstance = null; 
let cweChartInstance = null;   

// --- DOM Elements ---
const searchInput = document.getElementById('search-input');
const resultsContainer = document.getElementById('results-container');
const loadingIndicator = document.getElementById('loading-indicator');
const prevPageButton = document.getElementById('prev-page');
const nextPageButton = document.getElementById('next-page');
const pageStatus = document.getElementById('page-status');
const sortSelect = document.getElementById('sort-select');
const detailsView = document.getElementById('details-view');

// --- TAB SWITCHING ---
function switchTab(tabName) {
    const tabs = ['browser', 'overview', 'loader', 'help'];
    tabs.forEach(t => {
        const btn = document.getElementById(`tab-${t}`);
        const view = document.getElementById(`view-${t}`);
        if (t === tabName) {
            view.classList.remove('hidden');
            btn.classList.remove('text-slate-300', 'hover:bg-slate-800');
            btn.classList.add('bg-rimini-yellow', 'text-black');
        } else {
            view.classList.add('hidden');
            btn.classList.add('text-slate-300', 'hover:bg-slate-800');
            btn.classList.remove('bg-rimini-yellow', 'text-black');
        }
    });
}

// --- UTILS ---
function getSeverity(score) {
    if (!score) return { level: 'UNKNOWN', color: 'bg-slate-600 text-white' };
    const s = parseFloat(score);
    if (s >= 9.0) return { level: 'CRITICAL', color: 'bg-red-600 text-white' };
    if (s >= 7.0) return { level: 'HIGH', color: 'bg-orange-500 text-white' };
    if (s >= 4.0) return { level: 'MEDIUM', color: 'bg-yellow-400 text-black' }; 
    return { level: 'LOW', color: 'bg-green-600 text-white' };
}

// Helper: Safe Local Fetch (Swallows errors to allow fallback)
async function safeLocalFetch(url, options = {}) {
    try {
        const response = await fetch(url, options);
        if (response.ok) return await response.json();
        return null; // Server error (500, 404, etc)
    } catch (e) {
        console.warn("Local server connection failed. Ignoring...");
        return null; // Network error (Offline)
    }
}

// --- EXTERNAL FETCH LOGIC (NVD + OSV) ---
async function fetchExternalCveData(cveId) {
    try {
        const [nvdRes, epssRes, osvRes] = await Promise.all([
            fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`).catch(e => null),
            fetch(`https://api.first.org/data/v1/epss?cve=${cveId}`).catch(e => null),
            fetch(`https://api.osv.dev/v1/vulns/${cveId}`).catch(e => null)
        ]);

        let item = null;
        let source = '';

        if (nvdRes && nvdRes.ok) {
            const nvdData = await nvdRes.json();
            if (nvdData.vulnerabilities && nvdData.vulnerabilities.length > 0) {
                item = nvdData.vulnerabilities[0].cve;
                source = 'NIST NVD';
            }
        }

        let osvData = null;
        if (!item && osvRes && osvRes.ok) {
            osvData = await osvRes.json();
            if (osvData && osvData.id) {
                item = {
                    id: osvData.id,
                    published: osvData.published,
                    vulnStatus: 'PUBLISHED',
                    sourceIdentifier: 'OSV.dev',
                    descriptions: [{ lang: 'en', value: osvData.details || osvData.summary || "No description provided." }],
                    metrics: {}, weaknesses: [], configurations: [],
                    references: (osvData.references || []).map(r => ({ url: r.url, source: r.type }))
                };
                if (osvData.severity) {
                    const cvssEntry = osvData.severity.find(s => s.type === 'CVSS_V3');
                    if (cvssEntry) item.metrics.cvssMetricV31 = [{ cvssData: { baseScore: 0, vectorString: cvssEntry.score } }];
                }
                if (osvData.affected) {
                    item.configurations = [{ nodes: osvData.affected.map(aff => ({ cpeMatch: [{ criteria: `cpe:2.3:a:${aff.package?.ecosystem||'OSS'}:${aff.package?.name||'Unk'}:${aff.versions?.[0]||'*'}:*:*:*:*:*:*:*` }] })) }];
                }
                source = 'OSV.dev';
            }
        }

        if (!item) return null;

        const epssJson = epssRes && epssRes.ok ? await epssRes.json() : null;
        const epssScore = epssJson?.data?.[0]?.epss || 0;
        const metrics = item.metrics?.cvssMetricV31?.[0] || item.metrics?.cvssMetricV30?.[0];

        return {
            isExternal: true, sourceLabel: source,
            cveMetadata: { cveId: item.id, datePublished: item.published, state: item.vulnStatus || 'PUBLISHED', assignerShortName: item.sourceIdentifier || source },
            containers: { cna: { descriptions: item.descriptions, metrics: [{ cvssV3_1: metrics?.cvssData ? { baseScore: metrics.cvssData.baseScore || 0, vectorString: metrics.cvssData.vectorString || "N/A", attackVector: metrics.cvssData.attackVector || "N/A", attackComplexity: metrics.cvssData.attackComplexity || "N/A", privilegesRequired: metrics.cvssData.privilegesRequired || "N/A", userInteraction: metrics.cvssData.userInteraction || "N/A", confidentialityImpact: metrics.cvssData.confidentialityImpact || "N/A", integrityImpact: metrics.confidentialityImpact || "N/A", availabilityImpact: metrics.cvssData.availabilityImpact || "N/A" } : null }], problemTypes: [{ descriptions: (item.weaknesses || []).map(w => ({ description: w.description?.[0]?.value || w.cweId || "N/A" })) }], affected: (item.configurations || []).flatMap(c => (c.nodes || []).flatMap(n => (n.cpeMatch || []).map(m => { const parts = m.criteria.split(':'); return { vendor: parts[3] || 'Unknown', product: parts[4] || 'Unknown', versions: [{ version: parts[5] === '*' ? 'All' : parts[5], status: 'affected' }] }; }))).slice(0, 10), references: (item.references || []).map(r => ({ url: r.url, name: r.source || 'External Ref' })) } },
            epss: epssScore
        };
    } catch (e) { return null; }
}

// --- SEARCH LOGIC ---
async function searchCVE(page) {
    currentQuery = searchInput.value.trim();
    if (page === 1) currentPage = 1; else currentPage = page;
    
    loadingIndicator.innerHTML = '<div class="animate-spin rounded-full h-12 w-16 border-4 border-slate-700 border-t-rimini-yellow mx-auto"></div><p class="mt-4 text-slate-400 font-mono animate-pulse">Scanning Database...</p>';
    loadingIndicator.classList.remove('hidden');
    resultsContainer.innerHTML = '';
    
    let results = [];
    // STEP 1: Attempt Local Search (Safe Fetch)
    const skip = (currentPage - 1) * LIMIT;
    const sortValue = sortSelect.value.split('_');
    const url = `${API_URL}?search=${encodeURIComponent(currentQuery)}&limit=${LIMIT}&skip=${skip}&sortField=${sortValue[0]}&sortOrder=${sortValue[1]}`;
    
    const localData = await safeLocalFetch(url);
    if (localData) {
        console.log("localData");
        results = localData;
    }
    console.log("DOPINUIDNQUOIDQDBQHKIJDNQJODJQODHQUIDHQUIODJ9");
    // STEP 2: External Fallback (Only if local empty & is CVE-ID)
    if (results.length === 0 || results.length === 0 && /^CVE-\d{4}-\d{4,}$/i.test(currentQuery)) {
        console.log("PRINT OU JE TETRANGLE");
        loadingIndicator.innerHTML = '<div class="animate-spin rounded-full h-16 w-16 border-4 border-slate-700 border-t-rimini-yellow mx-auto"></div><p class="mt-4 text-rimini-yellow font-medium">Local Data Missing. Querying NIST NVD & OSV...</p>';
        const externalData = await fetchExternalCveData(currentQuery.toUpperCase());
        if (externalData) results = [externalData];
    }
    
    loadingIndicator.classList.add('hidden');
    currentSearchResults = results;
    renderResults(results);
    updatePagination(results.length);
}

function renderResults(cves) {
    resultsContainer.innerHTML = ''; 
    if (cves.length === 0 && currentPage === 1) {
        resultsContainer.innerHTML = `<div class="text-center p-20 border border-slate-800 rounded-2xl bg-slate-900/50"><i class="fas fa-search text-6xl text-slate-800 mb-4"></i><p class="text-slate-500 text-xl font-light">No results found.</p><p class="text-slate-600 mt-2">Try a valid CVE-ID.</p></div>`;
        return;
    }

    cves.forEach(cve => {
        const id = cve.cveMetadata.cveId || 'N/A';
        const desc = cve.containers?.cna?.descriptions?.find(d => d.lang === 'en')?.value || 'No summary.';
        const dateStr = cve.cveMetadata.datePublished ? new Date(cve.cveMetadata.datePublished).toLocaleDateString() : 'N/A';
        let score = null;
        const metrics = cve.containers?.cna?.metrics || [];
        for (const m of metrics) { if (m.cvssV3_1) score = m.cvssV3_1.baseScore; else if (m.cvssV3_0) score = m.cvssV3_0.baseScore; }
        const severity = getSeverity(score);

        let badgeHtml = '';
        let cardClass = 'rimini-card bg-slate-800 border-slate-700'; 
        if (cve.isExternal) {
            const label = cve.sourceLabel || 'NIST NVD';
            cardClass = 'bg-slate-900 border border-yellow-500 shadow-[0_0_15px_rgba(251,231,0,0.1)]'; 
            badgeHtml = `<div class="mb-4"><span class="inline-flex items-center px-3 py-1 rounded text-xs font-bold bg-rimini-yellow text-black uppercase tracking-wide"><i class="fas fa-cloud-download-alt mr-2"></i> Loaded from ${label}</span></div>`;
        }

        const card = document.createElement('div');
        card.className = `${cardClass} p-6 rounded-xl cursor-pointer group`;
        card.onclick = () => openDetails(id); 
        
        card.innerHTML = `
            ${badgeHtml}
            <div class="flex justify-between items-start mb-3">
                <h2 class="text-2xl font-black text-white group-hover:text-rimini-yellow transition">${id}</h2>
                <span class="px-3 py-1 text-xs font-bold rounded uppercase tracking-wide ${severity.color}">${severity.level}</span>
            </div>
            <p class="text-slate-400 text-sm mb-4 line-clamp-2 leading-relaxed">${desc}</p>
            <div class="flex justify-between text-xs text-slate-500 font-mono pt-4 border-t border-slate-700/50">
                <span><i class="far fa-calendar-alt mr-2"></i> ${dateStr}</span>
                <span class="text-rimini-yellow opacity-0 group-hover:opacity-100 transition font-bold">VIEW DETAILS &rarr;</span>
            </div>
        `;
        resultsContainer.appendChild(card);
    });
}

// --- DETAILS VIEW ---
async function openDetails(cveId) {
    detailsView.classList.remove('hidden');
    document.body.style.overflow = 'hidden'; 
    try {
        let cve = currentSearchResults.find(c => c.cveMetadata.cveId === cveId);
        
        if (!cve) {
            // SAFEGUARDED LOCAL FETCH
            cve = await safeLocalFetch(`${API_URL}/${cveId}`);
            
            if (!cve) {
                // If local failed (offline or 404), try External
                cve = await fetchExternalCveData(cveId);
            }
            
            if (!cve) throw new Error("CVE not found.");
        }
        
        const banner = document.getElementById('detail-external-banner');
        if (banner) {
            if (cve.isExternal) {
                banner.classList.remove('hidden');
                const label = cve.sourceLabel || 'External Source';
                banner.querySelector('span').innerHTML = `Loaded from ${label}`;
            } else { banner.classList.add('hidden'); }
        }
        document.getElementById('detail-id').textContent = cve.cveMetadata.cveId;
        document.getElementById('detail-state').textContent = cve.cveMetadata.state || 'PUBLISHED';
        document.getElementById('detail-source').textContent = cve.cveMetadata.assignerShortName || 'Unknown';
        document.getElementById('detail-date').textContent = cve.cveMetadata.datePublished ? new Date(cve.cveMetadata.datePublished).toLocaleDateString() : 'N/A';
        document.getElementById('nvd-link').href = `https://nvd.nist.gov/vuln/detail/${cve.cveMetadata.cveId}`;
        const desc = cve.containers?.cna?.descriptions?.find(d => d.lang === 'en')?.value || 'No description.';
        document.getElementById('detail-desc').textContent = desc;
        const metrics = cve.containers?.cna?.metrics || [];
        let cvssData = null;
        for (const m of metrics) { if (m.cvssV3_1) cvssData = m.cvssV3_1; else if (m.cvssV3_0 && !cvssData) cvssData = m.cvssV3_0; }
        if (cvssData) {
            const score = cvssData.baseScore;
            const sev = getSeverity(score);
            document.getElementById('detail-cvss-score').textContent = score;
            document.getElementById('detail-severity').textContent = sev.level;
            document.getElementById('detail-severity').className = `px-3 py-1 rounded text-sm font-black border border-slate-700 ${sev.color}`;
            document.getElementById('detail-vector').textContent = cvssData.vectorString;
            renderRadarChart(cvssData);
        } else {
            document.getElementById('detail-cvss-score').textContent = 'N/A';
            document.getElementById('detail-severity').textContent = 'UNKNOWN';
            document.getElementById('detail-vector').textContent = 'No Data';
            if (cvssChartInstance) cvssChartInstance.destroy();
        }
        const problems = cve.containers?.cna?.problemTypes || [];
        let cweText = 'N/A';
        if (problems.length > 0 && problems[0].descriptions) cweText = problems[0].descriptions.map(p => p.description).join(', ');
        document.getElementById('detail-cwe').textContent = cweText;
        const affected = cve.containers?.cna?.affected || [];
        const tbody = document.getElementById('affected-table-body');
        tbody.innerHTML = '';
        if (affected.length === 0) tbody.innerHTML = '<tr><td colspan="3" class="px-4 py-2 italic text-slate-600">No info available.</td></tr>';
        else affected.forEach(a => { const vendor = a.vendor||'N/A'; const product = a.product||'N/A'; let versions = 'All'; if (a.versions && Array.isArray(a.versions)) versions = a.versions.map(v => { if(typeof v === 'string') return v; if(v.version === 'unspecified') return v.lessThan ? `< ${v.lessThan}` : 'Unknown'; return v.version; }).join(', '); tbody.innerHTML += `<tr class="border-b border-slate-800 hover:bg-slate-900"><td class="px-4 py-3 font-bold text-white">${vendor}</td><td class="px-4 py-3 text-slate-300">${product}</td><td class="px-4 py-3 text-slate-500 font-mono text-xs">${versions}</td></tr>`; });
        const refs = cve.containers?.cna?.references || [];
        const refsList = document.getElementById('detail-refs');
        refsList.innerHTML = '';
        if (refs.length === 0) refsList.innerHTML = '<li class="text-slate-600">No references.</li>';
        else refs.slice(0, 5).forEach(r => { let shortUrl = r.url.length > 50 ? r.url.substring(0, 50) + '...' : r.url; refsList.innerHTML += `<li><a href="${r.url}" target="_blank" class="flex items-center p-3 rounded bg-slate-950 border border-slate-800 hover:border-rimini-yellow hover:text-rimini-yellow transition text-slate-400"><i class="fas fa-link mr-3 text-xs"></i><span class="truncate">${r.name || shortUrl}</span></a></li>`; });
    } catch (e) { 
        console.error(e); 
        closeDetails(); 
        alert("Error: " + e.message); 
    }
}

// --- FILE UPLOAD LOGIC ---
async function handleFileUpload(input) {
    if (!input.files || input.files.length === 0) return;
    const file = input.files[0];
    const formData = new FormData();
    formData.append('file', file);
    const resultsDiv = document.getElementById('loader-results');
    const listDiv = document.getElementById('loader-list');
    resultsDiv.classList.remove('hidden');
    listDiv.innerHTML = '<p class="text-center text-slate-500 py-8">Parsing...</p>';
    try {
        const res = await fetch(UPLOAD_URL, { method: 'POST', body: formData }).catch(() => null);
        if (!res || !res.ok) throw new Error("Upload failed (Local server likely offline)");
        //res = await fetchExternalCveData(currentQuery.toUpperCase());
        const data = await res.json();
        const totalFileIds = data.totalFileIds;
        const resolvedLocalCount = data.resolvedLocal.length;
        const missingIds = data.missingIds;
        
        let allCves = data.resolvedLocal;
        let externalCves = [];

        if (missingIds && missingIds.length > 0) {
            listDiv.innerHTML = `<p class="text-center text-orange-400 py-4">Found ${missingIds.length} missing IDs locally. Querying external APIs...</p>`;
            const externalPromises = missingIds.map(id => fetchExternalCveData(id));
            const externalResults = await Promise.all(externalPromises);
            externalCves = externalResults.filter(cve => cve !== null);
            allCves = [...allCves, ...externalCves];
        }

        const totalResolved = resolvedLocalCount + externalCves.length;
        document.getElementById('loader-count-total').textContent = totalFileIds;
        document.getElementById('loader-count-found').textContent = totalResolved;
        listDiv.innerHTML = '';
        
        if (allCves.length === 0) { listDiv.innerHTML = '<p class="text-center text-slate-500 py-4">No matches.</p>'; return; }
        allCves.sort((a, b) => b.cveMetadata.cveId.localeCompare(a.cveMetadata.cveId));

        allCves.forEach(cve => {
            const id = cve.cveMetadata.cveId;
            const desc = cve.containers?.cna?.descriptions?.find(d => d.lang === 'en')?.value || 'No summary.';
            let score = null;
            const metrics = cve.containers?.cna?.metrics || [];
            for (const m of metrics) { if (m.cvssV3_1) score = m.cvssV3_1.baseScore; else if (m.cvssV3_0) score = m.cvssV3_0.baseScore; }
            const severity = getSeverity(score);
            
            const externalHighlight = cve.isExternal ? 'border-rimini-yellow bg-slate-900 shadow-yellow-900/10' : '';
            const sourceTag = cve.isExternal ? `<span class="text-xs font-bold text-rimini-yellow ml-3">${cve.sourceLabel || 'External'}</span>` : '';

            const card = document.createElement('div');
            card.className = `${externalHighlight} bg-slate-800 p-4 rounded-lg border border-slate-700 hover:border-rimini-yellow transition cursor-pointer flex justify-between items-center`;
            card.onclick = () => openDetails(id);
            card.innerHTML = `<div class="flex-grow"><div class="flex items-center gap-3"><h3 class="font-bold text-white text-lg">${id}</h3><span class="px-2 py-0.5 text-xs font-bold rounded ${severity.color}">${severity.level}</span>${sourceTag}</div><p class="text-slate-500 text-sm mt-1 line-clamp-1">${desc}</p></div><div class="text-slate-600"><i class="fas fa-chevron-right"></i></div>`;
            listDiv.appendChild(card);
        });
        currentSearchResults = [...currentSearchResults, ...allCves];
    } catch (e) { console.error(e); listDiv.innerHTML = `<p class="text-red-500 text-center">Error: ${e.message}</p>`; }
    input.value = '';
}

// --- DASHBOARD LOGIC ---
async function loadDashboard() {
    const keyword = document.getElementById('stats-keyword').value.trim();
    const duration = document.getElementById('stats-duration').value;
    const loading = document.getElementById('stats-loading');
    const content = document.getElementById('dashboard-content');
    content.classList.add('hidden');
    loading.classList.remove('hidden');
    try {
        const url = `${STATS_URL}?search=${encodeURIComponent(keyword)}&duration=${duration}`;
        const response = await fetch(url).catch(() => null);
        if (!response || !response.ok) throw new Error("Dashboard API Unavailable (Local server offline)");
        const stats = await response.json();
        document.getElementById('stat-total-count').textContent = stats.averages?.[0]?.count || 0;
        document.getElementById('stat-avg-cvss').textContent = (stats.averages?.[0]?.avgCvss || 0).toFixed(2);
        document.getElementById('stat-avg-epss').textContent = stats.criticalCount?.[0]?.count || 0;
        document.getElementById('stat-kev-count').textContent = stats.exploitCount?.[0]?.count || 0;
        
        const trendCtx = document.getElementById('trendChart').getContext('2d');
        if (trendChartInstance) trendChartInstance.destroy();
        trendChartInstance = new Chart(trendCtx, { type: 'line', data: { labels: stats.trend ? stats.trend.map(t => t._id) : [], datasets: [{ label: 'Avg Severity', data: stats.trend ? stats.trend.map(t => t.avgScore) : [], borderColor: '#FBE700', backgroundColor: 'rgba(251, 231, 0, 0.1)', tension: 0.3, fill: true }] }, options: { responsive: true, maintainAspectRatio: false, scales: { x: { grid: { color: '#334155' }, ticks: { color: '#94a3b8' } }, y: { grid: { color: '#334155' }, ticks: { color: '#94a3b8' } } } } });

        const cweCtx = document.getElementById('cweChart').getContext('2d');
        if (cweChartInstance) cweChartInstance.destroy();
        cweChartInstance = new Chart(cweCtx, { type: 'bar', data: { labels: stats.topCwes ? stats.topCwes.map(c => c._id ? c._id.substring(0, 30) + '...' : 'Unk') : [], datasets: [{ label: 'Frequency', data: stats.topCwes ? stats.topCwes.map(c => c.count) : [], backgroundColor: '#FBE700', borderRadius: 4 }] }, options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, scales: { x: { grid: { color: '#334155' }, ticks: { color: '#94a3b8' } }, y: { grid: { display: false }, ticks: { color: '#fff', font: { weight: 'bold' } } } } } });

        const tbody = document.getElementById('top-10-body');
        tbody.innerHTML = '';
        if (stats.topCvss) stats.topCvss.forEach(cve => { tbody.innerHTML += `<tr class="hover:bg-slate-900 transition border-b border-slate-800"><td class="px-6 py-4 font-bold text-white">${cve.cveMetadata.cveId}</td><td class="px-6 py-4 text-slate-400">${cve.cveMetadata.datePublished ? new Date(cve.cveMetadata.datePublished).toLocaleDateString() : 'N/A'}</td><td class="px-6 py-4 font-bold text-rimini-yellow">${cve.score.toFixed(1)}</td><td class="px-6 py-4"><button onclick="openDetails('${cve.cveMetadata.cveId}')" class="text-xs font-bold uppercase tracking-wider text-slate-400 hover:text-white transition">View</button></td></tr>`; });
        loading.classList.add('hidden');
        content.classList.remove('hidden');
    } catch (e) { console.error(e); loading.innerHTML = `<p class="text-red-500">Error loading dashboard: ${e.message}</p>`; }
}

function updatePagination(count) {
    prevPageButton.disabled = currentPage === 1;
    nextPageButton.disabled = count < LIMIT;
    const start = ((currentPage - 1) * LIMIT) + 1;
    const end = start + count - 1;
    pageStatus.textContent = count > 0 ? `${start}-${end}` : '0';
}

function changePage(dir) {
    const newPage = currentPage + dir;
    if (newPage >= 1) {
        window.scrollTo({ top: 0, behavior: 'smooth' });
        searchCVE(newPage);
    }
}

function closeDetails() {
    detailsView.classList.add('hidden');
    document.body.style.overflow = 'auto';
}

function renderRadarChart(cvssData) {
    const ctx = document.getElementById('cvssChart').getContext('2d');
    const mapMetric = (val) => { if (!val) return 0; const v = val.toUpperCase(); if (v === 'CRITICAL') return 4; if (v === 'HIGH') return 3; if (v === 'MEDIUM') return 2; if (v === 'LOW') return 1; return 0; };
    const dataValues = [mapMetric(cvssData.attackVector), mapMetric(cvssData.attackComplexity), mapMetric(cvssData.privilegesRequired), mapMetric(cvssData.userInteraction), mapMetric(cvssData.confidentialityImpact), mapMetric(cvssData.integrityImpact), mapMetric(cvssData.availabilityImpact)];
    if (cvssChartInstance) cvssChartInstance.destroy();
    cvssChartInstance = new Chart(ctx, { 
        type: 'radar', 
        data: { 
            labels: ['Vector', 'Complexity', 'Privileges', 'User Interact', 'Confidentiality', 'Integrity', 'Availability'], 
            datasets: [{ 
                label: 'Impact', 
                data: dataValues, 
                fill: true, 
                backgroundColor: 'rgba(251, 231, 0, 0.2)', 
                borderColor: '#FBE700', 
                pointBackgroundColor: '#FFF', 
                pointBorderColor: '#FBE700'
            }] 
        }, 
        options: { 
            scales: { r: { 
                suggestedMin: 0, suggestedMax: 4, ticks: { display: false, backdropColor: 'transparent' }, 
                grid: { color: '#334155' }, angleLines: { color: '#334155' }, pointLabels: { color: '#94a3b8' } 
            } }, 
            plugins: { legend: { display: false } }, 
            maintainAspectRatio: false 
        } 
    });
}

document.addEventListener('DOMContentLoaded', () => searchCVE(1));
