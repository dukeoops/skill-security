const API = '/api';

async function api(path, options = {}) {
  const res = await fetch(API + path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function formatSize(bytes) {
  if (!bytes) return '—';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('zh-CN');
}

function riskBadgeClass(level) {
  const map = { safe: 'badge-safe', low: 'badge-low', medium: 'badge-medium', high: 'badge-high', critical: 'badge-critical' };
  return map[level] || 'badge-low';
}

function pollProgress(scanId, onUpdate, onDone) {
  const interval = setInterval(async () => {
    try {
      const p = await api(`/scans/${scanId}/progress`);
      onUpdate(p);
      if (p.status === 'completed' || p.status === 'failed') {
        clearInterval(interval);
        onDone(p);
      }
    } catch (e) {
      clearInterval(interval);
      onDone({ status: 'failed', progress_message: e.message });
    }
  }, 1500);
  return interval;
}

window.SkillGuard = { api, formatSize, formatDate, riskBadgeClass, pollProgress };
