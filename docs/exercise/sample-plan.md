# Sample exercise plan — invented company (illustrative only)

> **Entirely fictional.** Target "Northwind Robotics" and all addresses below are
> invented for illustration. `@northwind.example` uses the reserved `.example` domain and
> reaches no one. Nothing here is sent by this repository.

## Context
- Client: Northwind Robotics (fictional, ~400 staff)
- Objective: measure susceptibility to a credential-harvesting phish and the reporting rate.
- Authorization: signed scope & sign-off (see template); window 2 weeks.

## Pretext
- Theme: "Mandatory benefits portal re-enrolment before year end."
- Sender (spoofed, in-scope lookalike): `hr-no-reply@northwind-benefits.example`
- Landing page: branded re-enrolment form on a lab-controlled `.example` host; records
  click and, if submitted, a salted hash only — never plaintext credentials.

## Target cohort
- 60 employees across HR, Finance, Engineering (no executives, no contractors).

## Timeline
| Day | Activity |
|---|---|
| 0 | Send wave 1 (20 recipients) at 09:30 local. |
| 0 | Monitor clicks/reports; deconfliction contact on standby. |
| 2 | Waves 2–3; adjust send times. |
| 5 | Stop sending; close landing page. |
| 7 | Debrief using the debrief template; destroy captured data. |

## Safety
- Stop conditions: any real incident, media attention, or signatory request.
- Follow-up: short "you were part of an authorized test" notice + 3-minute training to all
  recipients, regardless of outcome.
