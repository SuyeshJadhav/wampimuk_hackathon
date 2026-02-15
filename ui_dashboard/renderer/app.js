document.addEventListener('DOMContentLoaded', () => {
	// 1. Navigation Logic
	const navItems = document.querySelectorAll('.nav-links li');
	const panels = document.querySelectorAll('.panel');

	navItems.forEach(item => {
		item.addEventListener('click', () => {
			// Remove active classes
			navItems.forEach(n => n.classList.remove('active'));
			panels.forEach(p => p.classList.remove('active'));

			// Add active class
			item.classList.add('active');
			const panelId = item.getAttribute('data-panel');
			document.getElementById(panelId).classList.add('active');
		});
	});

	// 2. Traffic Monitor (Polling)
	const trafficBody = document.getElementById('traffic-table-body');

	async function fetchTraffic() {
		try {
			const res = await fetch('http://localhost:5000/api/traffic');
			const data = await res.json();

			trafficBody.innerHTML = ''; // Clear table

			if (data.length === 0) {
				trafficBody.innerHTML = '<tr><td colspan="6" class="placeholder">No traffic logged yet...</td></tr>';
				return;
			}

			data.forEach(log => {
				const row = document.createElement('tr');
				row.innerHTML = `
                    <td>${log.timestamp.split(' ')[1]}</td>
                    <td><span class="badge method-${log.method}">${log.method}</span></td>
                    <td>${log.domain}</td>
                    <td>${log.full_url.substring(0, 30)}...</td>
                    <td>${log.content_type || '-'}</td>
                    <td>${log.raw_body_size_bytes} B</td>
                `;
				trafficBody.appendChild(row);
			});
		} catch (err) {
			console.error("Traffic fetch failed:", err);
		}
	}

	// Poll every 2 seconds
	setInterval(fetchTraffic, 2000);

	// 3. DLP Scanner
	const dropZone = document.getElementById('drop-zone');
	const fileInput = document.getElementById('file-input');
	const dlpResults = document.getElementById('dlp-results');
	const findingsList = document.getElementById('findings-list');
	const textPreview = document.getElementById('text-preview');

	dropZone.addEventListener('click', () => fileInput.click());

	fileInput.addEventListener('change', async (e) => {
		const file = e.target.files[0];
		if (!file) return;

		const formData = new FormData();
		formData.append('file', file);

		try {
			// Update UI state
			dropZone.innerHTML = `<div class="icon-lg">⏳</div><h3>Scanning ${file.name}...</h3>`;

			const res = await fetch('http://localhost:5000/api/scan-pdf', {
				method: 'POST',
				body: formData
			});
			const data = await res.json();

			if (data.error) throw new Error(data.error);

			// Hide upload zone, show results
			dropZone.classList.add('hidden');
			dlpResults.classList.remove('hidden');

			// Render Findings
			if (data.findings && data.findings.length > 0) {
				findingsList.innerHTML = data.findings.map(f => `
                    <div class="finding-item">
                        <span class="badge danger">${f.type.toUpperCase()}</span>
                        <span class="finding-val">${f.value}</span>
                    </div>
                `).join('');
			} else {
				findingsList.innerHTML = `<div class="safe-message">✅ No sensitive data found.</div>`;
			}

			// Render Preview
			textPreview.textContent = data.text_preview;

		} catch (err) {
			alert("Scan failed: " + err.message);
			dropZone.innerHTML = `<div class="icon-lg">❌</div><h3>Error</h3><p>${err.message}</p>`;
		}
	});

	// 4. T&C Analyzer
	const tncInput = document.getElementById('tnc-input');
	const analyzeBtn = document.getElementById('analyze-tnc-btn');
	const riskCard = document.getElementById('risk-card');
	const tncFindings = document.getElementById('tnc-findings');
	const percentageText = document.querySelector('.percentage');
	const circlePath = document.querySelector('.circular-chart .circle');

	analyzeBtn.addEventListener('click', async () => {
		const text = tncInput.value;
		if (!text) return;

		try {
			analyzeBtn.textContent = 'Running Analysis...';

			const res = await fetch('http://localhost:5000/api/analyze-tnc', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ text })
			});

			const data = await res.json();

			// Show Results
			riskCard.classList.remove('hidden');
			analyzeBtn.textContent = 'Analyze Risk';

			// Animate Gauge
			const score = Math.round(data.tnc_score);
			percentageText.textContent = score;
			const offset = 100 - score; // Calculate dash offset
			circlePath.style.strokeDashoffset = offset;

			// Color Logic
			circlePath.setAttribute('stroke', score > 70 ? '#f87171' : (score > 30 ? '#fbbf24' : '#4ade80'));

			// Render Findings
			if (data.findings.length > 0) {
				tncFindings.innerHTML = data.findings.map(f => `
                    <li>
                        <strong>${f.category.replace('_', ' ')}</strong>
                        <p class="subtitle">${f.snippet}</p>
                    </li>
                `).join('');
			} else {
				tncFindings.innerHTML = `<li>No major risks detected.</li>`;
			}

		} catch (err) {
			console.error(err);
			analyzeBtn.textContent = 'Analysis Failed';
		}
	});

	document.getElementById('start-time').innerText = new Date().toLocaleString();
});
