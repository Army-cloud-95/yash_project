# OT Sentinel: pitch kit

## One line
One platform that shows plant operators and security teams the same live picture: what is connected, how the process is behaving, and what looks wrong, with the evidence.

## Problem (say this first)
- OT security tools and process analytics tools are separate, so a security event and a process deviation are investigated by different teams with different data.
- Most plants have no reliable asset inventory, and many industrial protocols (Modbus, DNP3) carry no authentication or encryption.
- Teams cannot tell quickly whether a write command and a pressure spike are related.

## What is different
1. Security and process data on one timeline, tied to one asset inventory.
2. Evidence on every finding, and a label for how it was obtained (simulated, observed, inferred, analyst-confirmed).
3. The platform never claims timing proves cause, and never writes to a controller.
4. Role-based view: company admin sees every plant, plant users see only their own.
5. A transparent posture score and an IEC 62443-themed readiness checklist, each calculated from the data.

## Five-minute demo (use the Guided tour button)
1. Sign in as company.admin. Fleet Overview: compare four plants.
2. Open Plant A. Live Operations: connect the PLC, watch live analysis, then the Cybersecurity tab (write from unlisted host).
3. Add the event to the report. Threat Intel: ATT&CK mapping with rationale.
4. Correlation: widen the time window, read the uncertainty note.
5. Risk & Compliance: show how the score is calculated. Sign in as plant.b to show restricted access.

## Questions judges will ask (prepare answers)
- Is the live data real? No. This version simulates it. Real collection uses a passive SPAN/TAP mirror or read-only OPC UA, through a collector service.
- Is the login secure? The web demo logs in inside the browser, so no. The backend folder implements server-side scrypt passwords, signed expiring tokens, per-plant authorization and lockout, with 33 passing tests. Show the Validation page.
- How is it different from existing OT security products? Process analytics and security share one asset model and one timeline, and the platform stays read-only.
- Business model and cost? Prepare this: per-plant subscription, collector hardware or VM, and who pays.
- How accurate is detection? The rules are deterministic and tested on generated scenarios (see Validation). Real accuracy needs real captures. Correlation is a lead, not proof: at a 120 s window about one in three unrelated cases still links.
- What would you build next? Connect the web app to the backend API, a live collector service, adaptive baselines, validation on real captures.

## Do before the competition
- Run the full demo three times on the device you will present from, with and without internet.
- Have the zip, a screen recording of the demo, and screenshots as backups.
- Build one real end-to-end flow in the backend if time allows (upload a capture, store findings, show them).
