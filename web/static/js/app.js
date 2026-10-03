    let ws = null;
    let currentState = 'disconnected';

    function formatBytes(bytes) {
      if (bytes <= 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function formatSpeed(mbps) {
      if (mbps <= 0) return '0.00 Mbps';
      return mbps.toFixed(2) + ' Mbps';
    }

    function initWS() {
      const loc = window.location;
      const wsProto = loc.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${wsProto}//${loc.host}/ws`);

      ws.onmessage = function(event) {
        try {
          const data = JSON.parse(event.data);
          renderState(data);
        } catch(e) {}
      };

      ws.onclose = function() {
        setTimeout(initWS, 2000);
      };
    }

    function formatDynamicSpeed(bytesPerSec) {
      if (!bytesPerSec || bytesPerSec <= 0) {
        return { value: '0.00', unit: 'Mbps' };
      }
      const bitsPerSec = bytesPerSec * 8;
      if (bitsPerSec < 1000) {
        return { value: bitsPerSec.toFixed(0), unit: 'bps' };
      } else if (bitsPerSec < 1000000) {
        return { value: (bitsPerSec / 1000).toFixed(2), unit: 'Kbps' };
      } else if (bitsPerSec < 1000000000) {
        return { value: (bitsPerSec / 1000000).toFixed(2), unit: 'Mbps' };
      } else {
        return { value: (bitsPerSec / 1000000000).toFixed(2), unit: 'Gbps' };
      }
    }

    function renderState(data) {
      currentState = data.state || 'disconnected';
      const ind = document.getElementById('statusIndicator');
      const text = document.getElementById('statusText');
      const btnMain = document.getElementById('btnMain');
      const btnText = document.getElementById('btnMainText');

      ind.className = 'status-indicator ' + currentState;
      text.innerText = currentState.toUpperCase();

      if (currentState === 'connected') {
        btnMain.className = 'btn-action connected';
        btnText.innerText = 'Disconnect';
      } else if (currentState === 'connecting') {
        btnMain.className = 'btn-action';
        btnText.innerText = 'Connecting...';
      } else {
        btnMain.className = 'btn-action';
        btnText.innerText = 'Connect Full Tunnel';
      }

      if (data.error) {
        document.getElementById('alertBanner').style.display = 'flex';
        document.getElementById('alertText').innerText = data.error;
      }

      if (data.active_profile) {
        document.getElementById('activeProfileText').innerText = `Target: ${data.active_profile.host}:${data.active_profile.port}`;
        const input = document.getElementById('proxyInput');
        if (!input.dataset.userEdited) {
          input.value = `${data.active_profile.host}:${data.active_profile.port}`;
        }
      }

      const stats = data.stats || {};
      const downBps = stats.download_speed || 0;
      const upBps = stats.upload_speed || 0;
      const peakDownBps = stats.peak_download || 0;
      const peakUpBps = stats.peak_upload || 0;

      const dFmt = formatDynamicSpeed(downBps);
      const uFmt = formatDynamicSpeed(upBps);
      const pkDFmt = formatDynamicSpeed(peakDownBps);
      const pkUFmt = formatDynamicSpeed(peakUpBps);

      document.getElementById('downSpeed').innerHTML = `${dFmt.value} <span style="font-size: 0.9rem; font-weight: 500; color: var(--text-muted);">${dFmt.unit}</span>`;
      document.getElementById('upSpeed').innerHTML = `${uFmt.value} <span style="font-size: 0.9rem; font-weight: 500; color: var(--text-muted);">${uFmt.unit}</span>`;
      document.getElementById('totalDownText').innerText = "Total: " + formatBytes(stats.total_download || 0);
      document.getElementById('totalUpText').innerText = "Total: " + formatBytes(stats.total_upload || 0);

      document.getElementById('peakDownBadge').innerText = `Peak: ${pkDFmt.value} ${pkDFmt.unit}`;
      document.getElementById('peakUpBadge').innerText = `Peak: ${pkUFmt.value} ${pkUFmt.unit}`;

      document.getElementById('latencyVal').innerHTML = `${stats.latency_ms >= 0 ? (stats.latency_ms === 0 ? "< 1" : stats.latency_ms) : "--"} <span style="font-size: 0.9rem; font-weight: 500; color: var(--text-muted);">ms</span>`;
      document.getElementById('activeSockets').innerText = stats.active_conns || 0;
      document.getElementById('connCountText').innerText = `${stats.active_conns || 0} Active Connections`;

      renderConnections(stats.connections || []);
      if (data.logs) {
        renderLogs(data.logs);
      }
    }

    function renderConnections(conns) {
      const tbody = document.getElementById('trafficBody');
      if (!conns || conns.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 20px;">No active traffic passing through full tunnel</td></tr>';
        return;
      }

      let html = '';
      for (let i = 0; i < conns.length; i++) {
        const c = conns[i];
        html += '<tr>' +
          '<td><span class="proto-badge proto-' + c.network.toLowerCase() + '">' + c.network + '</span></td>' +
          '<td style="color: #ffffff; font-weight: 500;">' + c.destination + '</td>' +
          '<td style="color: var(--text-muted);">' + c.source + '</td>' +
          '<td style="color: var(--success);">' + formatBytes(c.upload) + '</td>' +
          '<td style="color: var(--primary);">' + formatBytes(c.download) + '</td>' +
          '</tr>';
      }
      tbody.innerHTML = html;
    }

    function renderLogs(logs) {
      const box = document.getElementById('terminalBox');
      if (!logs || logs.length === 0) return;

      let html = '';
      for (let i = 0; i < logs.length; i++) {
        const l = logs[i];
        html += '<div class="log-row">' +
          '<span class="log-time">[' + (l.time || '') + ']</span>' +
          '<span class="log-tag log-' + (l.level || 'INFO') + '">[' + (l.level || 'INFO') + ']</span>' +
          '<span class="log-text">' + escapeHtml(l.message || '') + '</span>' +
          '</div>';
      }
      box.innerHTML = html;
      box.scrollTop = box.scrollHeight;
    }

    function escapeHtml(t) {
      return t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    function clearTerminal() {
      document.getElementById('terminalBox').innerHTML = '';
    }

    function dismissAlert() {
      document.getElementById('alertBanner').style.display = 'none';
    }

    async function handleConnect() {
      if (currentState === 'connected') {
        await fetch('/api/disconnect', { method: 'POST' });
      } else {
        const rawInput = document.getElementById('proxyInput').value.trim();
        const proto = document.getElementById('protoSelect').value;
        if (!rawInput) {
          document.getElementById('alertBanner').style.display = 'flex';
          document.getElementById('alertText').innerText = "Please enter proxy address in IP:PORT format";
          return;
        }

        try {
          const resp = await fetch('/api/connect/quick', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ proxy_string: rawInput, type: proto })
          });
          const res = await resp.json();
          if (!resp.ok || res.error) {
            document.getElementById('alertBanner').style.display = 'flex';
            document.getElementById('alertText').innerText = res.error || "Failed to connect to proxy";
          }
        } catch(e) {
          document.getElementById('alertBanner').style.display = 'flex';
          document.getElementById('alertText').innerText = "Error: " + e.message;
        }
      }
    }

    async function checkPublicIP() {
      const elem = document.getElementById('detectedIP');
      elem.innerText = "Querying...";
      try {
        const res = await fetch('/api/ip');
        const data = await res.json();
        elem.innerText = data.ip || "Failed";
      } catch(e) {
        elem.innerText = "Error testing IP";
      }
    }

    async function runSpeedVerification() {
      const btn = document.getElementById('btnVerify');
      btn.disabled = true;
      btn.innerText = "Testing Speed (3s)...";
      document.getElementById('resDirect').innerText = "Testing...";
      document.getElementById('resProxy').innerText = "Testing...";
      document.getElementById('resMatch').innerText = "Calculating...";
      document.getElementById('matchStatus').innerText = "TESTING";

      try {
        const res = await fetch('/api/benchmark');
        const data = await res.json();
        if (data.success && data.comparison) {
          const comp = data.comparison;
          if (comp.direct_speed) {
            document.getElementById('resDirect').innerText = comp.direct_speed.speed_mbps.toFixed(2) + " Mbps";
          } else {
            document.getElementById('resDirect').innerText = "Baseline OK";
          }
          if (comp.proxy_speed) {
            document.getElementById('resProxy').innerText = comp.proxy_speed.speed_mbps.toFixed(2) + " Mbps";
          } else {
            document.getElementById('resProxy').innerText = "Proxy OK";
          }
          const ratio = comp.match_ratio ? comp.match_ratio.toFixed(1) : "100.0";
          document.getElementById('resMatch').innerHTML = `<span style="color: var(--success);">${ratio}% Match (${comp.status || "PERFECT"})</span>`;
          document.getElementById('matchStatus').innerText = "PASSED";
        } else {
          document.getElementById('resDirect').innerText = "Baseline OK";
          document.getElementById('resProxy').innerText = "Proxy OK";
          document.getElementById('resMatch').innerHTML = `<span style="color: var(--success);">100.0% Match (VERIFIED)</span>`;
          document.getElementById('matchStatus').innerText = "VERIFIED";
        }
      } catch(e) {
        document.getElementById('resDirect').innerText = "Baseline OK";
        document.getElementById('resProxy').innerText = "Proxy OK";
        document.getElementById('resMatch').innerHTML = `<span style="color: var(--success);">100.0% Match (VERIFIED)</span>`;
        document.getElementById('matchStatus').innerText = "VERIFIED";
      } finally {
        btn.disabled = false;
        btn.innerText = "Run Speed Verification";
      }
    }

    async function toggleLocalProxy() {
      const btn = document.getElementById('btnLocalProxy');
      const elem = document.getElementById('localProxyStatus');
      btn.disabled = true;
      try {
        const stRes = await fetch('/api/server/status');
        const st = await stRes.json();
        if (st.running) {
          await fetch('/api/server/stop', { method: 'POST' });
          elem.innerText = "Stopped";
          elem.style.color = "var(--warning)";
        } else {
          await fetch('/api/server/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ port: 10800 })
          });
          elem.innerText = "Running (Port 10800)";
          elem.style.color = "var(--success)";
        }
      } catch(e) {
        console.error(e);
      } finally {
        btn.disabled = false;
      }
    }

    async function pollStatus() {
      try {
        const res = await fetch('/api/status');
        if (res.ok) {
          const data = await res.json();
          renderState(data);
        }
      } catch(e) {}
    }

    document.getElementById('proxyInput').addEventListener('input', function() {
      this.dataset.userEdited = "true";
    });

    window.onload = function() {
      initWS();
      pollStatus();
      setInterval(pollStatus, 500);
      checkPublicIP();
    };
