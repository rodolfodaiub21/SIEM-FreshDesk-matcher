# Parity Check: SIEM and Freshdesk Event Comparison

A simple interface that fetches events from Wazuh (a SIEM) and compares them with tickets in Freshdesk. This project identifies whether each event in the SIEM has a corresponding ticket in Freshdesk, streamlining incident management for cybersecurity operations.

---

## Features

- **Fetch Wazuh Events:** Retrieves events from Wazuh servers for the last 24 hours.
- **Compare with Freshdesk Tickets:** Matches Wazuh events with Freshdesk tickets based on agent names and rule IDs.
- **Display Results:** Visualizes matched and unmatched events in a user-friendly interface.
- **Multi-threading:** Performs Freshdesk comparisons in a separate thread to keep the interface responsive.

---

## Requirements

This project requires the following dependencies:

- Python 3.8+
- Libraries:
  - `requests`
  - `tkinter`
  - `urllib3`
  - `pytz`

Install dependencies with:
```bash
pip install dependecy_name
