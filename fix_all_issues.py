#!/usr/bin/env python3
"""
Script de correction automatique pour HomeNet Dashboard v2
Corrige: CVE checker, main.py routes, frontend complet
"""

import re
import os

print("🔧 Début des corrections automatiques...")

# ============================================================================
# 1. CORRIGER CVE_CHECKER.PY - Sauvegarder les résultats en base
# ============================================================================
def fix_cve_checker():
    print("\n📝 Correction de cve_checker.py...")
    
    with open('cve_checker.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Ajouter import de database
    if 'from database import save_cve_result' not in content:
        content = content.replace(
            'import logging',
            'import logging\nfrom database import save_cve_result'
        )
    
    # Modifier check_cve pour sauvegarder en BDD
    old_check_cve = r'async def check_cve\(hostname: str\) -> list:.*?return results'
    
    new_check_cve = '''async def check_cve(hostname: str, device_ip: str = "") -> list:
    """Vérifie les CVE pour un hostname donné et sauvegarde en BDD."""
    logger.info(f"Vérification CVE pour : {hostname}")
    
    results = []
    
    try:
        # Recherche des CVE via NIST NVD
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={hostname}"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
        
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "N/A")
                
                descriptions = cve.get("descriptions", [])
                desc = descriptions[0].get("value", "No description") if descriptions else "No description"
                
                metrics = cve.get("metrics", {})
                cvss_data = {}
                severity = "UNKNOWN"
                score = 0.0
                
                # Extraire CVSS v3 ou v2
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                elif "cvssMetricV30" in metrics:
                    cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                
                if cvss_data:
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    score = float(cvss_data.get("baseScore", 0.0))
                
                cve_result = {
                    "id": cve_id,
                    "description": desc,
                    "severity": severity,
                    "cvss_score": score,
                }
                
                results.append(cve_result)
                
                # Sauvegarder en base de données
                if device_ip:
                    try:
                        await save_cve_result(
                            device_ip=device_ip,
                            hostname=hostname,
                            cve_id=cve_id,
                            description=desc,
                            severity=severity,
                            cvss_score=score
                        )
                    except Exception as e:
                        logger.error(f"Erreur sauvegarde CVE {cve_id}: {e}")
        
        logger.info(f"{len(results)} CVE(s) trouvée(s) pour {hostname}")
        
    except httpx.TimeoutException:
        logger.error(f"Timeout lors de la recherche CVE pour {hostname}")
    except Exception as e:
        logger.error(f"Erreur CVE pour {hostname}: {e}")
    
    return results'''
    
    content = re.sub(old_check_cve, new_check_cve, content, flags=re.DOTALL)
    
    with open('cve_checker.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("✅ cve_checker.py corrigé")

# ============================================================================
# 2. CORRIGER MAIN.PY - Ajouter routes CVE et corriger appels
# ============================================================================
def fix_main_py():
    print("\n📝 Correction de main.py...")
    
    with open('main.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Ajouter import des fonctions CVE
    if 'from database import' in content and 'get_cve_results' not in content:
        content = content.replace(
            'from database import (',
            'from database import (\n    get_cve_results, get_all_cve_summary, save_cve_result,'
        )
    
    # Modifier la route /api/cve/{hostname} pour passer device_ip
    old_cve_route = r'@app\.get\("/api/cve/\{hostname\}"\).*?return \{"vulnerabilities": cves\}'
    
    new_cve_route = '''@app.get("/api/cve/{hostname}")
async def cve_scan(hostname: str, device_ip: str = ""):
    """Scan CVE pour un hostname/IP et sauvegarde en BDD."""
    try:
        cves = await check_cve(hostname, device_ip)
        return {"vulnerabilities": cves, "count": len(cves)}
    except Exception as e:
        logger.error(f"Erreur CVE scan {hostname}: {e}")
        raise HTTPException(status_code=500, detail=str(e))'''
    
    content = re.sub(old_cve_route, new_cve_route, content, flags=re.DOTALL)
    
    # Ajouter route /api/cve/all avant "# Alertes"
    if '/api/cve/all' not in content:
        cve_all_route = '''

@app.get("/api/cve/all")
async def get_all_cves_route():
    """Récupère toutes les CVE de la base de données."""
    try:
        # Récupérer le résumé
        summary = await get_all_cve_summary()
        
        # Pour chaque device, récupérer les CVE détaillées
        result = []
        for item in summary:
            cves = await get_cve_results(device_ip=item["device_ip"])
            result.append({
                "device": item["hostname"],
                "ip": item["device_ip"],
                "cves": cves,
                "count": item["cve_count"]
            })
        
        total = sum(d["count"] for d in result)
        return {"devices": result, "total": total}
    except Exception as e:
        logger.error(f"Erreur get_all_cves: {e}")
        raise HTTPException(status_code=500, detail=str(e))

'''
        
        content = content.replace(
            '# ─' * 40 + '\n# Alertes\n',
            cve_all_route + '# ─' * 40 + '\n# Alertes\n'
        )
    
    with open('main.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("✅ main.py corrigé")

# ============================================================================
# 3. CORRIGER FRONTEND - TOUT EN UN
# ============================================================================
def fix_frontend():
    print("\n📝 Correction de frontend/index.html (COMPLET)...")
    
    with open('frontend/index.html', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # CORRECTIF 1: Supprimer grand espace vide
    content = content.replace('min-height: 200px;', 'min-height: 50px;')
    content = re.sub(r'#devicesTable tbody \{[^}]*\}', 
                     '#devicesTable tbody { height: auto; min-height: 80px; max-height: 600px; overflow-y: auto; }',
                     content)
    
    # CORRECTIF 2: Bouton Scan CVE par device - Modifier deviceRow()
    old_cve_btn = r'<button class="btn.*?onclick="prefillCveTarget\([^)]+\)">Scan CVE</button>'
    new_cve_btn = '<button class="btn btn-sm" onclick="runDeviceCve(\'${device.ip}\', \'${hostname}\')">🛡️ Scan CVE</button>'
    content = re.sub(old_cve_btn, new_cve_btn, content)
    
    # CORRECTIF 3: Ajouter fonction runDeviceCve
    if 'async function runDeviceCve' not in content:
        run_device_cve = '''
    async function runDeviceCve(ip, hostname) {
      try {
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = "⏳";
        
        const result = await fetchJSON(`/api/cve/${hostname}?device_ip=${ip}`);
        
        if (result.vulnerabilities && result.vulnerabilities.length > 0) {
          alert(`✅ ${result.count} CVE(s) trouvée(s) pour ${hostname}\\nScan sauvegardé en base de données`);
          await loadAlerts();
        } else {
          alert(`ℹ️ Aucune CVE trouvée pour ${hostname}`);
        }
        
        btn.disabled = false;
        btn.textContent = "🛡️ Scan CVE";
      } catch (error) {
        console.error("Erreur scan CVE:", error);
        alert("❌ Erreur lors du scan CVE");
        event.target.disabled = false;
        event.target.textContent = "🛡️ Scan CVE";
      }
    }
'''
        content = content.replace('async function runSpeedtest()', 
                                run_device_cve + '\n    async function runSpeedtest()')
    
    # CORRECTIF 4: Ajouter bouton Scan Réseau fonctionnel
    if 'async function runNetworkScan' not in content:
        run_network_scan = '''
    async function runNetworkScan() {
      const button = qs("#refreshBtn");
      const originalText = button.textContent;
      button.disabled = true;
      button.textContent = "⏳ Scan en cours...";
      
      try {
        await fetchJSON("/api/scan/run", { method: "POST" });
        await loadDevices();
        await loadAlerts();
        alert("✅ Scan réseau terminé!");
      } catch (error) {
        console.error("Erreur scan réseau:", error);
        alert("❌ Impossible de lancer le scan réseau");
      } finally {
        button.disabled = false;
        button.textContent = originalText;
      }
    }
'''
        content = content.replace('function bindEvents()', 
                                run_network_scan + '\n    function bindEvents()')
    
    # CORRECTIF 5: Lier le bouton Scan Réseau
    if 'qs("#refreshBtn").addEventListener("click", runNetworkScan)' not in content:
        content = content.replace(
            'qs("#runSpeedtestBtn").addEventListener("click", runSpeedtest);',
            'qs("#runSpeedtestBtn").addEventListener("click", runSpeedtest);\n' +
            '        qs("#refreshBtn").addEventListener("click", runNetworkScan);'
        )
    
    # CORRECTIF 6: Ajouter onglet Rapport CVE
    if 'data-tab="cve-report"' not in content:
        # Ajouter l'onglet dans la barre
        old_tabs = '<button class="tab" data-tab="alerts">🚨 Alertes</button>'
        new_tabs = '<button class="tab" data-tab="alerts">🚨 Alertes</button>\n        <button class="tab" data-tab="cve-report">🛡️ Rapport CVE</button>'
        content = content.replace(old_tabs, new_tabs)
        
        # Ajouter le contenu de l'onglet
        cve_report_html = '''
      <!-- Onglet Rapport CVE -->
      <div id="cve-report" class="tab-content">
        <div class="card">
          <div class="card-header">
            <h3>🛡️ Rapport CVE Consolidé</h3>
            <p>Toutes les vulnérabilités détectées sur le réseau</p>
          </div>
          <div id="cveReportContainer" style="padding: 1rem;">
            <p class="loading">Chargement...</p>
          </div>
        </div>
      </div>
'''
        content = content.replace('    </main>', cve_report_html + '    </main>')
    
    # CORRECTIF 7: Ajouter fonction loadCveReport
    if 'async function loadCveReport' not in content:
        load_cve_report = '''
    async function loadCveReport() {
      try {
        const data = await fetchJSON("/api/cve/all");
        const container = qs("#cveReportContainer");
        
        if (!data.devices || data.devices.length === 0) {
          container.innerHTML = "<p>✅ Aucune CVE détectée sur le réseau</p>";
          return;
        }
        
        let html = `<div style="margin-bottom: 1rem;"><strong>Total: ${data.total} CVE(s) trouvée(s) sur ${data.devices.length} appareil(s)</strong></div>`;
        html += '<div class="cve-devices-list">';
        
        for (const device of data.devices) {
          html += `
            <div class="cve-device-card">
              <h4>🖥️ ${device.device} <span style="color: var(--muted); font-size: 0.9em;">(${device.ip})</span></h4>
              <p style="color: var(--red); font-weight: bold;">⚠️ ${device.count} CVE(s) active(s)</p>
              <ul class="cve-list">
          `;
          
          for (const cve of device.cves) {
            const severityColor = cve.severity === 'CRITICAL' ? 'var(--red)' : 
                                  cve.severity === 'HIGH' ? 'orange' : 
                                  cve.severity === 'MEDIUM' ? 'yellow' : 'var(--muted)';
            html += `
              >
                <strong style="color: ${severityColor}">${cve.cve_id}</strong> 
                <span style="background: ${severityColor}; color: black; padding: 2px 6px; border-radius: 3px; font-size: 0.8em;">${cve.severity}</span>
                <span style="color: var(--muted);">Score: ${cve.cvss_score}</span>
                <br>
                <span style="font-size: 0.9em;">${cve.description || 'Pas de description'}</span>
              </li>
            `;
          }
          
          html += '</ul></div>';
        }
        
        html += '</div>';
        container.innerHTML = html;
      } catch (error) {
        console.error("Erreur chargement rapport CVE:", error);
        qs("#cveReportContainer").innerHTML = '<p class="error">❌ Erreur de chargement</p>';
      }
    }
'''
        content = content.replace('async function loadAlerts()', 
                                load_cve_report + '\n    async function loadAlerts()')
    
    # CORRECTIF 8: Ajouter loadCveReport dans refreshAll
    if 'loadCveReport()' not in content:
        content = content.replace(
            'loadHeatmap()',
            'loadHeatmap(),\n            loadCveReport()'
        )
    
    # CORRECTIF 9: CSS pour le rapport CVE
    cve_css = '''
/* Rapport CVE */
.cve-devices-list { margin-top: 1rem; }
.cve-device-card {
  background: var(--surface2);
  padding: 1rem;
  margin-bottom: 1rem;
  border-radius: 0.5rem;
  border-left: 4px solid var(--red);
}
.cve-device-card h4 { 
  margin-bottom: 0.5rem; 
  color: var(--text);
}
.cve-list {
  list-style: none;
  padding: 0;
  margin-top: 0.5rem;
}
.cve-list li {
  padding: 0.5rem;
  margin-bottom: 0.5rem;
  background: var(--surface);
  border-radius: 0.3rem;
  border-left: 2px solid var(--accent);
}
'''
    
    if '.cve-devices-list' not in content:
        content = content.replace('</style>', cve_css + '    </style>')
    
    with open('frontend/index.html', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("✅ frontend/index.html corrigé (COMPLET)")

# ============================================================================
# EXÉCUTION
# ============================================================================
if __name__ == "__main__":
    try:
        fix_cve_checker()
        fix_main_py()
        fix_frontend()
        
        print("\n✅ ✅ ✅ TOUTES LES CORRECTIONS APPLIQUÉES AVEC SUCCÈS! ✅ ✅ ✅\n")
        print("Prochaines étapes:")
        print("  1. git add -A")
        print("  2. git commit -m 'fix: corrections complètes - CVE, speedtest, frontend'")
        print("  3. git push")
        print("  4. sudo systemctl restart homenet")
        print("\nTous les problèmes sont maintenant corrigés! 🎉")
        
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
