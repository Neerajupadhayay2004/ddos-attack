"""
locustfile.py  —  DDoS Traffic Simulator using Locust
Run: locust -f locustfile.py --host=http://localhost:5000
  Or headless: locust -f locustfile.py --headless -u 500 -r 10 --host=http://localhost:5000
"""
import json
import random
from locust import HttpUser, task, between, events

ATTACK_TYPES = ['DrDoS_UDP', 'DrDoS_LDAP', 'DrDoS_MSSQL']

FAKE_IPS = [
    f'192.168.{random.randint(0,255)}.{random.randint(1,254)}'
    for _ in range(100)
] + [
    f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
    for _ in range(50)
]


class NormalUser(HttpUser):
    """Simulates legitimate users — low request rate"""
    wait_time = between(1, 3)
    weight    = 70   # 70% of users are normal

    @task(3)
    def get_dashboard(self):
        self.client.get('/', name='GET /')

    @task(2)
    def get_status(self):
        self.client.get('/api/status', name='GET /api/status')

    @task(1)
    def get_traffic(self):
        self.client.get('/api/traffic', name='GET /api/traffic')

    @task(1)
    def get_alerts(self):
        self.client.get('/api/alerts', name='GET /api/alerts')


class AttackUser(HttpUser):
    """Simulates DDoS attack traffic — high frequency"""
    wait_time = between(0.01, 0.1)
    weight    = 30   # 30% of users are attackers

    def on_start(self):
        self.src_ip      = random.choice(FAKE_IPS)
        self.attack_type = random.choice(ATTACK_TYPES)

    @task(10)
    def flood_simulate(self):
        """Send attack simulation bursts"""
        payload = {
            'type':  self.attack_type,
            'count': random.randint(10, 50),
            'ip':    self.src_ip,
        }
        with self.client.post(
            '/api/simulate',
            json=payload,
            name=f'POST /api/simulate [{self.attack_type}]',
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f'HTTP {response.status_code}')

    @task(3)
    def spam_status(self):
        """Flood status endpoint"""
        self.client.get('/api/status', name='GET /api/status [attack]')

    @task(1)
    def change_ip(self):
        """Rotate IPs to simulate botnet"""
        self.src_ip = random.choice(FAKE_IPS)


# ── Stats reporting ────────────────────────────────────────────────────────
@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, **kwargs):
    if exception:
        print(f'[FAIL] {request_type} {name} — {exception}')


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    print("=" * 50)
    print("  DDoS Simulation Started")
    print("  Normal Users (weight=70) + Attack Users (weight=30)")
    print("=" * 50)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    print("=" * 50)
    print("  DDoS Simulation Stopped")
    stats = environment.stats.total
    print(f"  Total Requests:  {stats.num_requests}")
    print(f"  Failures:        {stats.num_failures}")
    print(f"  Avg Response:    {stats.avg_response_time:.0f}ms")
    print("=" * 50)