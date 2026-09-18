document.addEventListener('DOMContentLoaded', () => {
    // ___________________________ Navigation ___________________
    const pages = document.querySelectorAll('.page');
    const navButtons = document.querySelectorAll('[data-nav]');

    function goToPage(pageId) {
        pages.forEach(p => p.classList.toggle('active', p.id === 'page-' + pageId));
        navButtons.forEach(b => b.classList.toggle('active', pageId === b.dataset.nav));
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => goToPage(btn.dataset.nav));
    });

    // ___________________________ Auth & Profile State ___________________
    const profileBtn = document.getElementById('profileBtn');
    const profileDropdown = document.getElementById('profileDropdown');

    function updateAuthUI() {
        if (!profileDropdown) return;
        const currentToken = localStorage.getItem('token');
        const email = localStorage.getItem('userEmail');

        if (currentToken) {
            profileDropdown.innerHTML = `
                <button disabled style="color: var(--accent-cyan); font-size: 13px; cursor: default;">${email || 'Signed in'}</button>
                <button id="logoutBtn" style="color: #ef4444;">Sign out</button>
            `;
            const logoutBtn = document.getElementById('logoutBtn');
            if (logoutBtn) {
                logoutBtn.addEventListener('click', async () => {
                    try {
                        await fetch('/api/auth/logout', {
                            method: 'POST',
                            headers: { 'Authorization': `Bearer ${currentToken}` }
                        });
                    } catch (e) {}
                    localStorage.removeItem('token');
                    localStorage.removeItem('userEmail');
                    updateAuthUI();
                    goToPage('home');
                });
            }
        } else {
            profileDropdown.innerHTML = `
                <button data-nav="register">Create an account</button>
                <button data-nav="login">Sign in</button>
            `;
            profileDropdown.querySelectorAll('[data-nav]').forEach(btn => {
                btn.addEventListener('click', () => {
                    goToPage(btn.dataset.nav);
                    profileDropdown.classList.remove('show');
                });
            });
        }
    }

    updateAuthUI();

    profileBtn.addEventListener('click', () => {
        profileDropdown.classList.toggle('show');
    });

    profileDropdown.querySelectorAll('[data-nav]').forEach(btn => {
        btn.addEventListener('click', () => {
            profileDropdown.classList.remove('show');
        });
    });

    goToPage('home');

    // ___________________________ Hero Tabs _____________________________
    const heroTabs = document.querySelectorAll('.hero-tab');
    heroTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            heroTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            goToPage(tab.dataset.nav);
        });
    });

    // ___________________________ Login Form _____________________________
    const loginForm = document.getElementById('loginForm');
    const loginStatus = document.getElementById('loginStatus');

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('loginEmail').value.trim();
            const password = document.getElementById('loginPassword').value;

            loginStatus.hidden = false;
            loginStatus.textContent = 'Signing in...';
            loginStatus.style.color = 'var(--text-secondary)';

            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await res.json();

                if (data.success && data.data?.session?.accessToken) {
                    localStorage.setItem('token', data.data.session.accessToken);
                    localStorage.setItem('userEmail', data.data.user?.email || email);
                    loginStatus.textContent = 'Signed in successfully!';
                    loginStatus.style.color = 'var(--accent-green)';
                    updateAuthUI();
                    setTimeout(() => {
                        loginStatus.hidden = true;
                        loginForm.reset();
                        goToPage('home');
                    }, 1200);
                } else {
                    loginStatus.textContent = data.error?.message || 'Login failed.';
                    loginStatus.style.color = '#ef4444';
                }
            } catch (err) {
                loginStatus.textContent = 'Network or server error.';
                loginStatus.style.color = '#ef4444';
            }
        });
    }

    // ___________________________ Register Form _____________________________
    const registerForm = document.getElementById('registerForm');
    const registerStatus = document.getElementById('registerStatus');

    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('registerEmail').value.trim();
            const password = document.getElementById('registerPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;

            if (password !== confirmPassword) {
                registerStatus.hidden = false;
                registerStatus.textContent = 'Passwords do not match.';
                registerStatus.style.color = '#ef4444';
                return;
            }

            registerStatus.hidden = false;
            registerStatus.textContent = 'Creating account...';
            registerStatus.style.color = 'var(--text-secondary)';

            try {
                const res = await fetch('/api/auth/signup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await res.json();

                if (data.success) {
                    registerStatus.textContent = data.data?.message || 'Account created successfully! Please sign in.';
                    registerStatus.style.color = 'var(--accent-green)';
                    setTimeout(() => {
                        registerStatus.hidden = true;
                        registerForm.reset();
                        goToPage('login');
                    }, 2000);
                } else {
                    registerStatus.textContent = data.error?.message || 'Registration failed.';
                    registerStatus.style.color = '#ef4444';
                }
            } catch (err) {
                registerStatus.textContent = 'Network or server error.';
                registerStatus.style.color = '#ef4444';
            }
        });
    }

    // ___________________________ URL Page & Scanning _____________________________
    const urlForm = document.getElementById('urlForm');
    const urlInput = document.getElementById('urlInput');
    const resultBanner = document.getElementById('resultBanner');

    async function runUrlScan(url) {
        const currentToken = localStorage.getItem('token');
        if (!currentToken) {
            alert('Please sign in to run scans.');
            goToPage('login');
            return;
        }

        resultBanner.hidden = false;
        const titleEl = document.getElementById('resultTitle');
        const msgEl = document.getElementById('resultMessage');
        
        if (titleEl) titleEl.textContent = 'Scanning URL...';
        if (msgEl) msgEl.textContent = `Analyzing ${url} across engines and local threat rules.`;

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${currentToken}`
                },
                body: JSON.stringify({ url })
            });
            const json = await res.json();

            if (json.success) {
                if (titleEl) titleEl.textContent = `URL Scan Complete (${res.status} OK)`;
                if (msgEl) {
                    msgEl.innerHTML = buildDetailedReportHtml(json);
                    const toggleBtn = document.getElementById('toggleRawJsonBtn');
                    const rawPre = document.getElementById('rawJsonContainer');
                    if (toggleBtn && rawPre) {
                        rawPre.textContent = JSON.stringify(json, null, 2);
                        toggleBtn.addEventListener('click', () => {
                            const isHidden = rawPre.style.display === 'none';
                            rawPre.style.display = isHidden ? 'block' : 'none';
                            toggleBtn.textContent = isHidden ? '📋 Hide Raw Postman JSON' : '📋 Toggle Raw Postman JSON';
                        });
                    }
                }
            } else {
                if (titleEl) titleEl.textContent = 'Scan Error';
                if (msgEl) {
                    msgEl.innerHTML = `
                        <pre id="jsonPreOutput" style="background: #080e1d; border: 1px solid #ef4444; padding: 16px; border-radius: 10px; overflow-x: auto; font-family: 'Courier New', Courier, monospace; font-size: 12px; color: #ef4444; max-height: 450px; text-align: left; margin: 0; line-height: 1.5;"></pre>
                    `;
                    const preOut = document.getElementById('jsonPreOutput');
                    if (preOut) preOut.textContent = JSON.stringify(json, null, 2);
                }
            }
        } catch (err) {
            if (titleEl) titleEl.textContent = 'Error';
            if (msgEl) msgEl.textContent = 'Network error while contacting scanner backend.';
        }
    }

    if (urlForm) {
        urlForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const val = urlInput.value.trim();
            if (!val) return;
            runUrlScan(val);
        });
    }

    // ___________________________ Files Page & Scanning _____________________________
    const fileInput = document.getElementById('fileInput');
    const chooseBtn = document.getElementById('chooseBtn');
    const dropzone = document.getElementById('dropzone');

    if (chooseBtn && fileInput) {
        chooseBtn.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', async () => {
            if (fileInput.files.length > 0) {
                await runFileScan(fileInput.files[0]);
            }
        });
    }

    if (dropzone) {
        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.style.borderColor = 'var(--accent-blue)';
        });
        dropzone.addEventListener('dragleave', () => {
            dropzone.style.borderColor = 'var(--border-strong)';
        });
        dropzone.addEventListener('drop', async (e) => {
            e.preventDefault();
            dropzone.style.borderColor = 'var(--border-strong)';
            if (e.dataTransfer.files.length > 0) {
                await runFileScan(e.dataTransfer.files[0]);
            }
        });
    }

    async function runFileScan(file) {
        const currentToken = localStorage.getItem('token');
        if (!currentToken) {
            alert('Please sign in to scan files.');
            goToPage('login');
            return;
        }

        const dropzoneTitle = dropzone.querySelector('h3');
        const originalText = dropzoneTitle ? dropzoneTitle.textContent : '';
        if (dropzoneTitle) dropzoneTitle.textContent = `Scanning ${file.name}...`;

        const formData = new FormData();
        formData.append('file', file);

        try {
            const res = await fetch('/api/scan/file', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${currentToken}`
                },
                body: formData
            });
            const json = await res.json();

            const fileResultBanner = document.getElementById('fileResultBanner');
            const fileResultTitle = document.getElementById('fileResultTitle');
            const fileResultMessage = document.getElementById('fileResultMessage');
            if (fileResultBanner) fileResultBanner.hidden = false;
            if (fileResultTitle) fileResultTitle.textContent = `File Scan Complete (${file.name})`;
            if (fileResultMessage) {
                fileResultMessage.innerHTML = buildDetailedReportHtml(json);
                const toggleBtn = document.getElementById('toggleRawJsonBtn');
                const rawPre = document.getElementById('rawJsonContainer');
                if (toggleBtn && rawPre) {
                    rawPre.textContent = JSON.stringify(json, null, 2);
                    toggleBtn.addEventListener('click', () => {
                        const isHidden = rawPre.style.display === 'none';
                        rawPre.style.display = isHidden ? 'block' : 'none';
                        toggleBtn.textContent = isHidden ? '📋 Hide Raw Postman JSON' : '📋 Toggle Raw Postman JSON';
                    });
                }
            }
        } catch (err) {
            alert('Network error during file upload and scan.');
        } finally {
            if (dropzoneTitle) dropzoneTitle.textContent = originalText;
        }
    }

    function buildDetailedReportHtml(json) {
        const data = json.data || json;
        const riskScore = data.riskScore ?? 0;
        const riskLevel = data.riskLevel ?? 'LOW';
        const verdict = data.verdict ?? 'Unknown';
        const scanId = data.scanId || data.fileHash || 'N/A';
        const scannedAt = data.scannedAt || new Date().toISOString();
        const findings = data.findings || [];
        const recommendations = data.recommendations || [];
        const threatEngine = data.threatEngine || {};
        const vt = data.virusTotal || {};
        const urlAnalysis = data.urlAnalysis || data.fileAnalysis || {};

        let levelColor = 'var(--accent-green)';
        if (riskLevel === 'MEDIUM') levelColor = '#f59e0b';
        if (riskLevel === 'HIGH') levelColor = '#f97316';
        if (riskLevel === 'CRITICAL') levelColor = '#ef4444';

        return `
            <div style="display: flex; flex-direction: column; gap: 16px; text-align: left; margin-top: 12px; font-family: inherit;">
                <!-- Summary Header Card -->
                <div style="background: var(--bg-card-alt); border: 1px solid var(--border-strong); border-radius: 12px; padding: 18px; display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 14px; align-items: center;">
                    <div>
                        <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;">Verdict</div>
                        <div style="font-size: 16px; font-weight: 700; color: ${levelColor}; margin-top: 2px;">${verdict}</div>
                    </div>
                    <div>
                        <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;">Risk Level</div>
                        <div style="display: inline-block; padding: 3px 10px; border-radius: 20px; background: ${levelColor}22; color: ${levelColor}; font-weight: 700; font-size: 12px; border: 1px solid ${levelColor}44; margin-top: 2px;">${riskLevel}</div>
                    </div>
                    <div>
                        <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;">Risk Score</div>
                        <div style="font-size: 16px; font-weight: 700; color: var(--text-primary); margin-top: 2px;">${riskScore} / 100</div>
                    </div>
                    <div>
                        <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;">Scan ID</div>
                        <div style="font-size: 12px; font-family: monospace; color: var(--accent-cyan); margin-top: 2px; word-break: break-all;">${scanId}</div>
                    </div>
                </div>

                <!-- Recommendations Section -->
                ${recommendations.length > 0 ? `
                    <div style="background: var(--bg-card-alt); border: 1px solid var(--border-subtle); border-radius: 12px; padding: 16px;">
                        <div style="font-weight: 700; font-size: 13.5px; color: var(--accent-cyan); margin-bottom: 10px; display: flex; align-items: center; gap: 6px;">💡 Recommendations</div>
                        <ul style="margin: 0; padding-left: 18px; color: var(--text-secondary); font-size: 13px; line-height: 1.6;">
                            ${recommendations.map(r => `<li style="margin-bottom: 4px;">${r}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}

                <!-- Findings Section -->
                <div style="background: var(--bg-card-alt); border: 1px solid var(--border-subtle); border-radius: 12px; padding: 16px;">
                    <div style="font-weight: 700; font-size: 13.5px; color: var(--accent-cyan); margin-bottom: 10px; display: flex; align-items: center; gap: 6px;">🔍 Security Findings (${findings.length})</div>
                    ${findings.length === 0 ? `
                        <div style="color: var(--accent-green); font-size: 13px; background: rgba(34, 197, 94, 0.08); padding: 10px; border-radius: 8px; border: 1px solid rgba(34, 197, 94, 0.2);">No suspicious security findings detected.</div>
                    ` : `
                        <div style="display: flex; flex-direction: column; gap: 8px; max-height: 220px; overflow-y: auto;">
                            ${findings.map(f => {
                                let sevColor = '#3b6cf6';
                                if (f.severity === 'critical') sevColor = '#ef4444';
                                else if (f.severity === 'high') sevColor = '#f97316';
                                else if (f.severity === 'medium') sevColor = '#f59e0b';
                                else if (f.severity === 'low') sevColor = '#3b82f6';
                                return `
                                    <div style="background: var(--bg-input); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 10px 12px; display: flex; justify-content: space-between; align-items: flex-start; gap: 10px;">
                                        <div>
                                            <div style="font-weight: 600; font-size: 13px; color: var(--text-primary);">${f.message || f.rule}</div>
                                            <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">Category: ${f.category} | Rule: ${f.rule}</div>
                                        </div>
                                        <span style="font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 10px; background: ${sevColor}22; color: ${sevColor}; border: 1px solid ${sevColor}44; text-transform: uppercase; white-space: nowrap;">${f.severity}</span>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    `}
                </div>

                <!-- Engine Breakdown Grid -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px;">
                    <!-- Threat Engine -->
                    <div style="background: var(--bg-card-alt); border: 1px solid var(--border-subtle); border-radius: 12px; padding: 16px;">
                        <div style="font-weight: 700; font-size: 13.5px; color: var(--accent-cyan); margin-bottom: 10px;">🛡️ Local Threat Engine</div>
                        <div style="font-size: 13px; color: var(--text-secondary); display: flex; flex-direction: column; gap: 6px;">
                            <div><strong style="color: var(--text-primary);">Classification:</strong> <span style="text-transform: uppercase; font-weight: 600; color: ${threatEngine.classification === 'clean' ? 'var(--accent-green)' : '#f97316'};">${threatEngine.classification || 'N/A'}</span></div>
                            <div><strong style="color: var(--text-primary);">Score Contribution:</strong> ${threatEngine.score ?? 0}/100</div>
                            <div><strong style="color: var(--text-primary);">Signals Detected:</strong> ${threatEngine.signalsDetected ?? 0}</div>
                        </div>
                    </div>

                    <!-- VirusTotal -->
                    <div style="background: var(--bg-card-alt); border: 1px solid var(--border-subtle); border-radius: 12px; padding: 16px;">
                        <div style="font-weight: 700; font-size: 13.5px; color: var(--accent-cyan); margin-bottom: 10px;">🌐 VirusTotal Intelligence</div>
                        <div style="font-size: 13px; color: var(--text-secondary); display: flex; flex-direction: column; gap: 6px;">
                            <div><strong style="color: var(--text-primary);">Status:</strong> <span style="text-transform: uppercase; font-weight: 600;">${vt.status || (vt.available ? 'Completed' : 'Not Configured')}</span></div>
                            <div><strong style="color: var(--text-primary);">Detection Ratio:</strong> ${vt.detectionRatio || '0/0'}</div>
                            <div><strong style="color: var(--text-primary);">Malicious / Suspicious:</strong> <span style="color: ${(vt.malicious || 0) > 0 ? '#ef4444' : 'var(--text-primary)'};">${vt.malicious ?? 0}</span> / <span style="color: ${(vt.suspicious || 0) > 0 ? '#f59e0b' : 'var(--text-primary)'};">${vt.suspicious ?? 0}</span></div>
                            ${vt.permalink ? `<div><a href="${vt.permalink}" target="_blank" style="color: var(--accent-cyan); text-decoration: underline; font-size: 12px;">View on VirusTotal ↗</a></div>` : ''}
                        </div>
                    </div>
                </div>

                <!-- Target Analysis Details -->
                <div style="background: var(--bg-card-alt); border: 1px solid var(--border-subtle); border-radius: 12px; padding: 16px;">
                    <div style="font-weight: 700; font-size: 13.5px; color: var(--accent-cyan); margin-bottom: 10px;">📊 Target Details</div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; font-size: 13px; color: var(--text-secondary);">
                        ${Object.entries(urlAnalysis).map(([k, v]) => `
                            <div style="background: var(--bg-input); padding: 8px 10px; border-radius: 6px; border: 1px solid var(--border-subtle);">
                                <span style="color: var(--text-muted); font-size: 11.5px; display: block; text-transform: uppercase;">${k}</span>
                                <span style="color: var(--text-primary); font-weight: 600; word-break: break-all;">${typeof v === 'boolean' ? (v ? 'Yes' : 'No') : (Array.isArray(v) ? (v.length ? v.join(', ') : 'None') : (v ?? 'N/A'))}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- Toggle Raw JSON Button -->
                <div>
                    <button type="button" id="toggleRawJsonBtn" style="background: transparent; border: 1px solid var(--border-strong); color: var(--accent-cyan); padding: 8px 14px; border-radius: 8px; font-size: 12.5px; font-weight: 600; cursor: pointer;">
                        📋 Toggle Raw Postman JSON
                    </button>
                    <pre id="rawJsonContainer" style="display: none; background: #080e1d; border: 1px solid var(--border-strong); padding: 16px; border-radius: 10px; overflow-x: auto; font-family: 'Courier New', Courier, monospace; font-size: 12px; color: #4fd1e8; max-height: 400px; text-align: left; margin-top: 10px; line-height: 1.5;"></pre>
                </div>
            </div>
        `;
    }

    // ___________________________ Contact Page _____________________________
    const contactForm = document.getElementById('contactForm');
    const formStatus = document.getElementById('formStatus');

    if (contactForm) {
        contactForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('name').value.trim();
            const email = document.getElementById('email').value.trim();
            const message = document.getElementById('message').value.trim();

            if (!name || !email || !message) return;

            formStatus.hidden = false;
            formStatus.textContent = 'Preparing message for linkscannr@gmail.com...';
            formStatus.style.color = 'var(--text-secondary)';

            try {
                // Submit to backend API
                await fetch('/api/contact', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, email, message })
                });

                formStatus.textContent = 'Opening email client to send to linkscannr@gmail.com...';
                formStatus.style.color = 'var(--accent-green)';

                // Open mail client addressed to linkscannr@gmail.com
                const subject = encodeURIComponent(`Contact Inquiry from ${name} (${email})`);
                const body = encodeURIComponent(`Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}`);
                const mailtoUrl = `mailto:linkscannr@gmail.com?subject=${subject}&body=${body}`;
                
                setTimeout(() => {
                    window.location.href = mailtoUrl;
                    contactForm.reset();
                    formStatus.textContent = 'Email client opened successfully for linkscannr@gmail.com!';
                    setTimeout(() => { formStatus.hidden = true; }, 5000);
                }, 800);
            } catch (err) {
                const subject = encodeURIComponent(`Contact Inquiry from ${name} (${email})`);
                const body = encodeURIComponent(`Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}`);
                window.location.href = `mailto:linkscannr@gmail.com?subject=${subject}&body=${body}`;
                formStatus.textContent = 'Email client opened for linkscannr@gmail.com!';
                formStatus.style.color = 'var(--accent-green)';
            }
        });
    }

    // ___________________________ Mobile Menu _____________________________
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const mobileMenu = document.getElementById('mobileMenu');

    if (mobileMenuBtn && mobileMenu) {
        mobileMenuBtn.addEventListener('click', () => {
            mobileMenu.classList.toggle('show');
        });
        mobileMenu.querySelectorAll('[data-nav]').forEach(btn => {
            btn.addEventListener('click', () => {
                mobileMenu.classList.remove('show');
            });
        });
    }
});
