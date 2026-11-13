"""Real FastAPI ASGI request tests against a file-backed account database."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from fastapi.testclient import TestClient
from tahr.secure_service import IdentityStore, create_app, PERMISSIONS

PASSWORD = "a-strong-training-password-2035"


class SecureApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        authdb = str(Path(self.tmp.name) / "auth.db")
        workflowdb = str(Path(self.tmp.name) / "workflow.db")
        self.app = create_app(authdb, workflowdb)
        self.identity = self.app.state.auth
        for username, role in [("root.admin","admin"),("talent.recruiter","recruiter"),
                               ("hiring.manager","hiring_manager"),("report.analyst","analyst"),
                               ("risk.auditor","auditor")]:
            self.identity.create_user(username, PASSWORD, role)
        self.clients = []

    def client(self, role: str) -> tuple[TestClient, str]:
        accounts = {"admin":"root.admin","recruiter":"talent.recruiter","hiring_manager":"hiring.manager", "analyst":"report.analyst","auditor":"risk.auditor"}
        client = TestClient(self.app)
        self.clients.append(client)
        data = client.post("/api/auth/login",json={"username":accounts[role],"password":PASSWORD})
        self.assertEqual(data.status_code, 200, data.text)
        return client, data.json()["csrf_token"]

    def post(self, client: TestClient, route: str, data: dict, csrf: str | None = None):
        return client.post(route,json=data,headers={"X-CSRF-Token":csrf} if csrf else {})

    def test_login_logout_cookie_security_headers(self):
        client, csrf = self.client("admin")
        cookie = client.cookies.get("tahr_session")
        self.assertTrue(cookie and len(cookie) > 32)
        r = client.get("/api/auth/me")
        self.assertEqual(r.json()["role"], "admin")
        self.assertIn("nosniff",r.headers["x-content-type-options"])
        self.assertIn("frame-ancestors 'none'",r.headers["content-security-policy"])
        self.assertIn("no-store",r.headers["cache-control"])
        self.assertNotIn("password",r.text)
        self.assertNotIn("token",r.text)
        logout=self.post(client,"/api/auth/logout",{},csrf)
        self.assertEqual(logout.status_code,200)
        self.assertEqual(client.get("/api/auth/me").status_code,401)
        self.assertIsNone(self.identity.identity(cookie))

    def test_anonymous_denied_every_sensitive_resource(self):
        c=TestClient(self.app)
        for path in ["/api/auth/me","/api/requisitions","/api/applications","/api/metrics","/api/audit"]:
            with self.subTest(path=path):
                self.assertEqual(c.get(path).status_code,401)
        self.assertEqual(self.post(c,"/api/requisitions", {"title":"Testing", "department":"Analytics", "budget_usd":70000}).status_code,401)

    def test_all_roles_permissions_and_least_privilege(self):
        routes = {"requisitions:read":("GET","/api/requisitions"),
                  "applications:read":("GET","/api/applications"),
                  "metrics:read":("GET","/api/metrics"),
                  "audit:read":("GET","/api/audit"),
                  "requisitions:create":("POST","/api/requisitions"),
                  "requisitions:approve":("POST","/api/requisitions/approve"),
                  "applications:create":("POST","/api/applications"),
                  "applications:advance":("POST","/api/applications/advance"),
                  "interviews:schedule":("POST","/api/interviews")}
        payloads={"requisitions:create":{"title":"Simulated Analyst", "department":"Analytics","budget_usd":75000},
                  "requisitions:approve":{"req_id":"REQ-D0001"},
                  "applications:create":{"req_id":"REQ-D0001","source":"Careers Site"},
                  "applications:advance":{"app_id":"APP-D0001","stage":"Final"},
                  "interviews:schedule":{"app_id":"APP-D0001","scheduled_at":"2035-01-01T10:00:00+00:00", "interviewer":"Synthetic interviewer"}}
        for role in PERMISSIONS:
            c, csrf=self.client(role)
            for permission,(method,path) in routes.items():
                with self.subTest(role=role,permission=permission):
                    r=c.get(path) if method=="GET" else self.post(c,path,payloads[permission],csrf)
                    if permission in PERMISSIONS[role]:
                        # 422 is business validation and proves the role check passed.
                        self.assertNotIn(r.status_code,(401,403),r.text)
                    else:
                        self.assertEqual(r.status_code,403,r.text)

    def test_csrf_origin_content_type_and_spoofing(self):
        c,csrf=self.client("admin")
        job={"title":"Synthetic Ops Analyst", "department":"Analytics", "budget_usd":78000, "requestor":"impersonated_admin"}
        self.assertEqual(self.post(c,"/api/requisitions",job).status_code,403)
        self.assertEqual(self.post(c,"/api/requisitions",job,"wrong").status_code,403)
        r=c.post("/api/requisitions",json=job,headers={"X-CSRF-Token":csrf,"Origin":"https://evil.test"})
        self.assertEqual(r.status_code,403)
        r=c.post("/api/requisitions",data='{"title":"x"}',headers={"Content-Type":"text/plain","X-CSRF-Token":csrf})
        self.assertEqual(r.status_code,415)
        r=self.post(c,"/api/requisitions",job,csrf)
        self.assertEqual(r.status_code,201,r.text)
        # Body actor is untrusted; server always attributes the logged-in account.
        self.assertEqual(r.json()["result"]["requestor"],"root.admin")

    def test_no_self_approval_even_as_admin(self):
        c,csrf=self.client("admin")
        created=self.post(c,"/api/requisitions",{"title":"HR Ops Coordinator","department":"People & Culture","budget_usd":62000},csrf)
        req_id=created.json()["result"]["id"]
        denied=self.post(c,"/api/requisitions/approve",{"req_id":req_id},csrf)
        self.assertEqual(denied.status_code,422)
        m,mtoken=self.client("hiring_manager")
        result=self.post(m,"/api/requisitions/approve",{"req_id":req_id},mtoken)
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.json()["result"]["status"],"Open")

    def test_locked_accounts_and_session_revocation(self):
        c=TestClient(self.app)
        for n in range(6):
            r=c.post("/api/auth/login",json={"username":"talent.recruiter","password":"incorrect-passphrase"})
            self.assertEqual(r.status_code,401)
        r=c.post("/api/auth/login",json={"username":"talent.recruiter","password":PASSWORD})
        self.assertEqual(r.status_code,401)
        m,csrf=self.client("hiring_manager")
        self.identity.set_role("hiring.manager", "auditor")
        self.assertEqual(m.get("/api/auth/me").status_code,401)
        m2,_=self.client("hiring_manager")
        self.assertEqual(m2.get("/api/auth/me").json()["role"],"auditor")
        self.identity.disable("hiring.manager")
        self.assertEqual(m2.get("/api/auth/me").status_code,401)

    def test_admin_provider_probe_requires_real_operator_credentials(self):
        a,csrf=self.client("admin")
        for provider in ("greenhouse","workday"):
            result=self.post(a,"/api/integrations/probe",{"provider":provider},csrf)
            self.assertEqual(result.status_code,503, result.text)
            self.assertNotIn("CLIENT_SECRET",result.text)

    def test_responses_do_not_leak_private_user_store(self):
        a,csrf=self.client("analyst")
        data=a.get("/api/metrics").json()
        self.assertTrue(data["synthetic"])
        self.assertNotIn("applications",data.get("by_stage",{}))
        self.assertEqual(a.get("/api/applications").status_code,403)
        self.assertEqual(a.get("/api/audit").status_code,403)
        self.assertEqual(self.post(a,"/api/integrations/probe",{"provider":"greenhouse"},csrf).status_code,403)
        r=a.get("/")
        self.assertIn('lang="en"',r.text)
        self.assertNotIn(PASSWORD,r.text)
        self.assertIn("form-action 'self'",r.headers["content-security-policy"])

if __name__ == "__main__":
    unittest.main()
