const $ = (id) => document.getElementById(id);

let currentReport = null;
let currentUploadedFiles = null; // [{name, bytes}]

function setStatus(msg, isError) {
  const el = $('status');
  el.textContent = msg || '';
  el.classList.toggle('error', !!isError);
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatBytes(n) {
  if (n == null) return '–';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(2) + ' MB';
}

function baseName(name) {
  return String(name).split('/').pop().split('\\').pop();
}

// Reads a raw FileList/array of File objects into {name, bytes}[],
// transparently expanding a single .zip into its contained entries.
async function collectUploadedFiles(fileList) {
  const files = Array.from(fileList);
  if (files.length === 1 && /\.zip$/i.test(files[0].name)) {
    const buf = await files[0].arrayBuffer();
    const zip = await JSZip.loadAsync(buf);
    const out = [];
    for (const entry of Object.values(zip.files)) {
      if (entry.dir) continue;
      const bytes = await entry.async('uint8array');
      out.push({ name: baseName(entry.name), bytes });
    }
    return out;
  }
  const out = [];
  for (const f of files) {
    const buf = await f.arrayBuffer();
    out.push({ name: f.name, bytes: new Uint8Array(buf) });
  }
  return out;
}

function textFromBytes(bytes) {
  return new TextDecoder('utf-8').decode(bytes);
}

async function handleFiles(fileList) {
  ['identityCard', 'filesCard', 'warningsCard'].forEach((id) => { $(id).style.display = 'none'; });
  currentReport = null;
  currentUploadedFiles = null;
  setStatus('Reading files…');
  try {
    const uploaded = await collectUploadedFiles(fileList);
    $('fname').textContent = uploaded.map((f) => f.name).join(', ');
    currentUploadedFiles = uploaded;

    const deploymentFile = uploaded.find((f) => /\.(application|vsto)$/i.test(f.name));
    if (!deploymentFile) {
      throw new Error('No .application (or .vsto) deployment manifest found among the files you provided. That file is required to identify the app.');
    }
    const deploymentText = textFromBytes(deploymentFile.bytes);
    const deployment = ClickOnceParser.parseDeploymentManifest(deploymentText);

    let applicationText = null;
    const warnings = [];
    if (deployment.dependentAssemblies.length) {
      const declaredManifestName = deployment.dependentAssemblies[0].codebase;
      const match = ClickOnceParser.findUploadedFile(uploaded, declaredManifestName);
      if (match) {
        applicationText = textFromBytes(match.file.bytes);
      } else {
        // Fall back to any single *.manifest file present, in case its
        // name doesn't exactly match what the deployment manifest
        // declares (e.g. it was renamed).
        const anyManifest = uploaded.filter((f) => /\.manifest$/i.test(f.name.replace(/\.deploy$/i, '')));
        if (anyManifest.length === 1) {
          applicationText = textFromBytes(anyManifest[0].bytes);
          warnings.push(`Used "${anyManifest[0].name}" as the application manifest by guesswork (its name didn't match "${declaredManifestName}" declared in the deployment manifest).`);
        } else {
          warnings.push(`The application manifest "${declaredManifestName}" was not found among the files provided. Only the deployment manifest's own details are shown below.`);
        }
      }
    }

    setStatus('Parsing manifests and verifying files…');
    const report = await ClickOnceParser.buildReport(deploymentText, applicationText, uploaded);
    report.warnings = warnings;
    currentReport = report;
    render(report);
    const verifiedCount = report.rows.filter((r) => r.status === 'verified').length;
    setStatus(`Parsed. ${verifiedCount} of ${report.rows.length} declared file(s) verified against what you provided.`);
  } catch (err) {
    setStatus((err && err.message) || String(err), true);
  }
}

function render(report) {
  renderIdentity(report);
  renderFiles(report);
  if (report.warnings && report.warnings.length) {
    $('warningsCard').style.display = '';
    $('warningsList').innerHTML = report.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join('');
  }
}

function renderIdentity(report) {
  const d = report.deployment;
  const a = report.application;
  $('identityCard').style.display = '';
  const desc = (a && a.description.product) || d.description.product || '(untitled)';
  const publisher = (a && a.description.publisher) || d.description.publisher || '(unknown)';
  const version = (a && a.identity.version) || d.identity.version || '(unknown)';
  const rows = [
    ['Application', escapeHtml(desc)],
    ['Publisher', escapeHtml(publisher)],
    ['Version', escapeHtml(version)],
    ['Install mode', d.install ? 'Installed (available offline)' : 'Online-only'],
    ['Files renamed with .deploy', d.mapFileExtensions ? 'Yes' : 'No'],
  ];
  if (d.deploymentProviderCodebase) rows.push(['Update location', escapeHtml(d.deploymentProviderCodebase)]);
  if (a) {
    rows.push(['Entry point', escapeHtml(a.entryPointFile || '(unknown)')]);
    rows.push(['Trust level', escapeHtml(a.trustLevel)]);
    if (a.requestedExecutionLevel) rows.push(['Execution level', escapeHtml(a.requestedExecutionLevel)]);
  } else {
    rows.push(['Trust level', 'unknown — application manifest not available']);
  }
  $('identityBody').innerHTML = rows.map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('');
}

const STATUS_CLASS = {
  verified: 'status-verified',
  'HASH MISMATCH': 'status-mismatch',
  missing: 'status-missing',
};

function statusClass(status) {
  return STATUS_CLASS[status] || 'status-present';
}

function renderFiles(report) {
  $('filesCard').style.display = '';
  $('filesBody').innerHTML = report.rows.map((r) => {
    const nameSuffix = r.hadDeploySuffix ? ' <span style="color:var(--muted);">(as .deploy)</span>' : '';
    return `<tr>
      <td>${escapeHtml(r.name)}${nameSuffix}</td>
      <td class="size-cell">${formatBytes(r.actualSize != null ? r.actualSize : r.declaredSize)}</td>
      <td class="${statusClass(r.status)}">${escapeHtml(r.status)}</td>
    </tr>`;
  }).join('');
}

function download(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function downloadRecovered() {
  if (!currentReport || !currentUploadedFiles) return;
  const btn = $('downloadRecoveredBtn');
  btn.disabled = true;
  const prevText = btn.textContent;
  btn.textContent = 'Building ZIP…';
  try {
    const zip = new JSZip();
    let included = 0;
    for (const row of currentReport.rows) {
      if (row.status !== 'verified' && !String(row.status).startsWith('present')) continue;
      const match = ClickOnceParser.findUploadedFile(currentUploadedFiles, row.name);
      if (!match) continue;
      zip.file(row.name, match.file.bytes);
      included++;
    }
    if (!included) {
      setStatus('Nothing to recover — no files were both provided and verified.', true);
      return;
    }
    const blob = await zip.generateAsync({ type: 'blob' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'recovered-app.zip';
    a.click();
  } catch (err) {
    setStatus('Error building ZIP: ' + ((err && err.message) || String(err)), true);
  } finally {
    btn.disabled = false;
    btn.textContent = prevText;
  }
}

function exportJson() {
  if (!currentReport) return;
  const plain = {
    deployment: currentReport.deployment,
    application: currentReport.application,
    files: currentReport.rows,
  };
  download('clickonce-report.json', JSON.stringify(plain, null, 2), 'application/json');
}

function bindDrop() {
  const dz = $('dropzone');
  const input = $('fileInput');
  const setDrag = (on) => dz.classList.toggle('drag', on);
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); setDrag(true); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); setDrag(false); }));
  dz.addEventListener('drop', (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
  });
  dz.addEventListener('click', () => input.click());
  dz.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  input.addEventListener('change', () => {
    if (input.files && input.files.length) handleFiles(input.files);
    input.value = '';
  });
}

bindDrop();
$('downloadRecoveredBtn').addEventListener('click', downloadRecovered);
$('exportJsonBtn').addEventListener('click', exportJson);
