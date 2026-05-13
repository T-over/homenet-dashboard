"""
tests/test_all.py – Tests automatiques pour HomeNet Dashboard
Lancer avec : pytest tests/ -v
"""
import asyncio
import os
import pytest
import pytest_asyncio

# Utiliser une base de test temporaire
os.environ.setdefault("DATABASE_PATH", ":memory:")
os.environ.setdefault("NETWORK_RANGE", "192.168.1.0/24")
os.environ.setdefault("SPEEDTEST_INTERVAL_MIN", "60")
os.environ.setdefault("ALERT_THRESHOLD_MBPS", "10.0")
os.environ.setdefault("HOST", "0.0.0.0")
os.environ.setdefault("PORT", "8000")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def event_loop():
    """Crée une boucle asyncio pour toute la session de tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Initialise la base de données en mémoire avant chaque test."""
    from database import init_db
    await init_db()


# ---------------------------------------------------------------------------
# Tests database.py
# ---------------------------------------------------------------------------
class TestDatabase:
    """Tests des fonctions de base de données."""

    @pytest.mark.asyncio
    async def test_init_db(self):
        """Teste que la base de données s'initialise sans erreur."""
        from database import init_db
        await init_db()  # Doit passer sans exception

    @pytest.mark.asyncio
    async def test_upsert_device_nouveau(self):
        """Teste l'insertion d'un nouvel appareil."""
        from database import upsert_device, get_all_devices
        is_new = await upsert_device(
            ip="192.168.1.100",
            mac="AA:BB:CC:DD:EE:FF",
            hostname="test-device",
            vendor="TestVendor",
            is_online=True
        )
        assert is_new is True
        devices = await get_all_devices()
        ips = [d["ip"] for d in devices]
        assert "192.168.1.100" in ips

    @pytest.mark.asyncio
    async def test_upsert_device_mise_a_jour(self):
        """Teste la mise à jour d'un appareil existant."""
        from database import upsert_device
        await upsert_device("192.168.1.101", "11:22:33:44:55:66", "host1", "VendorA", True)
        is_new = await upsert_device("192.168.1.101", "11:22:33:44:55:66", "host1-updated", "VendorA", True)
        assert is_new is False

    @pytest.mark.asyncio
    async def test_get_all_devices_vide(self):
        """Teste que get_all_devices retourne une liste (vide ou non)."""
        from database import get_all_devices
        devices = await get_all_devices()
        assert isinstance(devices, list)

    @pytest.mark.asyncio
    async def test_mark_devices_offline(self):
        """Teste que mark_devices_offline marque les absents hors ligne."""
        from database import upsert_device, mark_devices_offline, get_all_devices
        await upsert_device("192.168.1.200", "", "device-a", "", True)
        await upsert_device("192.168.1.201", "", "device-b", "", True)
        await mark_devices_offline(["192.168.1.200"])  # 201 doit passer offline
        devices = await get_all_devices()
        for d in devices:
            if d["ip"] == "192.168.1.201":
                assert d["is_online"] is False
            if d["ip"] == "192.168.1.200":
                assert d["is_online"] is True

    @pytest.mark.asyncio
    async def test_update_device_alias(self):
        """Teste la mise à jour de l'alias d'un appareil."""
        from database import upsert_device, update_device_alias, get_all_devices
        await upsert_device("192.168.1.50", "", "my-device", "", True)
        await update_device_alias("192.168.1.50", "Mon NAS")
        devices = await get_all_devices()
        for d in devices:
            if d["ip"] == "192.168.1.50":
                assert d["alias"] == "Mon NAS"

    @pytest.mark.asyncio
    async def test_save_and_get_speedtest(self):
        """Teste la sauvegarde et la récupération d'un résultat speedtest."""
        from database import save_speedtest, get_speedtest_history
        await save_speedtest(100.5, 50.2, 12.3)
        history = await get_speedtest_history(10)
        assert len(history) >= 1
        last = history[-1]
        assert abs(last["download_mbps"] - 100.5) < 0.01
        assert abs(last["upload_mbps"] - 50.2) < 0.01
        assert abs(last["ping_ms"] - 12.3) < 0.01

    @pytest.mark.asyncio
    async def test_add_and_get_alerts(self):
        """Teste l'ajout et la récupération d'alertes."""
        from database import add_alert, get_alerts
        await add_alert("high", "Test alerte haut")
        await add_alert("low", "Test alerte bas")
        alerts = await get_alerts(10)
        messages = [a["message"] for a in alerts]
        assert "Test alerte haut" in messages
        assert "Test alerte bas" in messages

    @pytest.mark.asyncio
    async def test_save_and_get_port_scan(self):
        """Teste la sauvegarde et récupération d'un scan de ports."""
        from database import save_port_scan, get_port_scan_results
        ports = [{"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4", "product": "", "state": "open"}]
        await save_port_scan("192.168.1.10", ports)
        result = await get_port_scan_results("192.168.1.10")
        assert result["ports"] is not None
        assert len(result["ports"]) == 1
        assert result["ports"][0]["port"] == 80

    @pytest.mark.asyncio
    async def test_save_device_ping(self):
        """Teste l'enregistrement d'un événement ping."""
        from database import save_device_ping, get_device_ping_history
        await save_device_ping("192.168.1.30", True, 5.2)
        history = await get_device_ping_history("192.168.1.30", 10)
        assert len(history) >= 1
        assert history[0]["is_online"] is True

    @pytest.mark.asyncio
    async def test_get_bandwidth_heatmap_vide(self):
        """Teste que la heatmap retourne une liste."""
        from database import get_bandwidth_heatmap
        data = await get_bandwidth_heatmap()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_get_speedtest_history_limite(self):
        """Teste la limite sur l'historique speedtest."""
        from database import save_speedtest, get_speedtest_history
        for i in range(5):
            await save_speedtest(float(50 + i), float(20 + i), float(10 + i))
        history = await get_speedtest_history(3)
        assert len(history) <= 3


# ---------------------------------------------------------------------------
# Tests API FastAPI (via TestClient)
# ---------------------------------------------------------------------------
class TestAPI:
    """Tests des routes de l'API FastAPI."""

    @pytest.fixture(autouse=True)
    def client(self):
        """Crée un client de test FastAPI."""
        from fastapi.testclient import TestClient
        from main import app
        self._client = TestClient(app)

    def test_health(self):
        """Teste la route /api/health."""
        response = self._client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    def test_get_devices(self):
        """Teste la route GET /api/devices."""
        response = self._client.get("/api/devices")
        assert response.status_code == 200
        data = response.json()
        assert "devices" in data
        assert "online_count" in data
        assert "total_count" in data

    def test_get_speedtest_history(self):
        """Teste la route GET /api/speedtest."""
        response = self._client.get("/api/speedtest?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert "history" in data

    def test_get_alerts(self):
        """Teste la route GET /api/alerts."""
        response = self._client.get("/api/alerts")
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "count" in data

    def test_set_alias(self):
        """Teste la route PUT /api/devices/{ip}/alias."""
        response = self._client.put(
            "/api/devices/192.168.1.1/alias",
            json={"alias": "Mon Routeur"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["alias"] == "Mon Routeur"

    def test_export_devices_csv(self):
        """Teste l'export CSV des appareils."""
        response = self._client.get("/api/devices/export")
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]

    def test_export_speedtest_csv(self):
        """Teste l'export CSV du speedtest."""
        response = self._client.get("/api/speedtest/export")
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]

    def test_get_heatmap(self):
        """Teste la route GET /api/speedtest/heatmap."""
        response = self._client.get("/api/speedtest/heatmap")
        assert response.status_code == 200
        data = response.json()
        assert "heatmap" in data

    def test_device_history(self):
        """Teste la route GET /api/devices/{ip}/history."""
        response = self._client.get("/api/devices/192.168.1.1/history")
        assert response.status_code == 200
        data = response.json()
        assert "history" in data

    def test_get_ports(self):
        """Teste la route GET /api/devices/{ip}/ports."""
        response = self._client.get("/api/devices/192.168.1.1/ports")
        assert response.status_code == 200
        data = response.json()
        assert "ports" in data
