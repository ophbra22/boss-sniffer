# Maintenance notes

This is a restored educational networking project. The cleanup preserves its small script-based design, JSON record layout, and original dashboard appearance.

## File organization

- `standalone_aigent.py` → `agent.py`
- `manger.py` → `manager.py`
- `test.py` (the report generator, not a test suite) → `report.py`
- One template lives in `templates/report.html`; its static files live in `assets/`.
- Duplicate template trees, historical generated reports, editor metadata, and the legacy Windows upload executable are omitted from the repository.

## Correctness fixes

- Replaced the obsolete `scapy3k` import with maintained Scapy.
- Resolved resources relative to the project rather than an old absolute Windows path.
- Corrected incoming/outgoing counts and remote TCP/UDP port selection.
- Compared IP addresses exactly and retained packets without an Ethernet layer.
- Handled partial/short captures, failed lookups, and missing Windows process information.
- Read complete TCP batches, close sockets, retain one listening socket, and report errors.
- Validate incoming records before changing manager state.
- Fixed blacklist matching, including a match followed by a nonmatching entry.
- Render empty and small datasets without indexing errors; encode chart labels as JSON and escape HTML.
- Label charts as packet counts, and start bar-chart scales at zero.
- Bundle Chart.js for offline report viewing and fit charts to their containers.
- Remove the hard-coded upload to the historical class server; make external geolocation opt-in.

## Verification boundary

The automated suite exercises constructed Scapy packets, real local TCP connections, report rendering, and the manager process end to end. The demo is also intended for a visual browser check. Live capture still requires the platform's packet-capture permissions and drivers. Windows process lookup is tested with representative `netstat` output, not a running Windows application.
