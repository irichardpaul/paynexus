# PayNexus Security Operations Simulation

A shared, web-based learning environment for the IT 403 Week 17 Capstone Security Case Study. The app uses fictional records and simulates events locally; it does not connect to banks, process payments, or ingest live security telemetry.

## Run locally

Requires Python 3.10 or newer and no third-party packages.

```powershell
python app.py
```

Open `http://localhost:8000`. SQLite data is stored in `paynexus.sqlite3` beside the app by default. Set `PORT` or `PAYNEXUS_DB` to change those values.

### First sign-in

The first launch seeds an administrator account and three sample role accounts:

| Role | Username | Initial password |
|---|---|---|
| Security Administrator | `instructor` | `PayNexus!2026` |
| Student Analyst | `student1` | `Analyst!2026` |
| SOC Analyst | `soc1` | `SOC!2026` |
| Executive | `exec1` | `Executive!2026` |

Sign in as `instructor`, change the initial password using the **Password** control in the header, open **Instructor**, and create an individual account for each class member. Seed accounts are only created when the database is empty; they are not recreated after the first setup.

## Included workflows

- Role-aware overview, transaction records, alert triage, and control register.
- SIEM-style search over authentication, API, application, and database simulation events.
- Investigation findings with evidence and recommendations; administrator scoring and feedback.
- Incident lifecycle: Detection, Analysis, Containment, Eradication, Recovery, and Closed.
- Controlled scenario generator that creates linked synthetic logs, alerts, and incidents.
- Instructor console for account provisioning, account access, and recent activity.
- Administrator-only reset of generated scenario records.

Role boundaries: Students submit and view their own findings. SOC Analysts triage alerts, manage the incident workflow, launch scenarios, and submit findings. Security Administrators manage accounts, controls, evaluations, and scenario resets. Executives have read-only access to the operational views.

## Hosting for shared class access

`render.yaml` is configured for a single Render Docker web service with a 1 GB persistent disk mounted at `/data`. Connect this repository as a Render Blueprint to create the service. Render provides the HTTPS `onrender.com` URL after the first deployment. The persistent disk requires a paid web service plan and supports only one instance, so this starter is intended for a class simulation rather than high availability.

This lightweight starter uses SQLite and a single application process for its database. For larger classes, multiple application instances, or production-grade availability, move records to a managed PostgreSQL database and use a production identity/session service, HTTPS, backups, and operational monitoring. Do not use real personal, payment, or credential data. The built-in accounts and event data are instructional examples.

## Project context

See [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) for the assignment setting and handoff notes about the original browser prototype, which was not available in this workspace.
