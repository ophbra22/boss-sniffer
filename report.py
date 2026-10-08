"""Aggregate the original packet records and render the HTML dashboard."""

import datetime
from html import escape
from ipaddress import IPv4Address
import json
from operator import itemgetter
from pathlib import Path
import re
import shutil

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT = BASE_DIR / "output" / "report.html"


def load_settings(settings_path=None):
    """Read the original WORKERS / BLACKLIST configuration format."""
    if settings_path is None:
        settings_path = BASE_DIR / "settings.dat"
        if not settings_path.exists():
            settings_path = BASE_DIR / "settings.example.dat"
    settings = {}
    for line in Path(settings_path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError("Settings must use KEY = value")
        settings[key.strip()] = [item.strip() for item in value.split(",") if item.strip()]
    return settings.get("WORKERS", []), settings.get("BLACKLIST", [])


def validate_data(data):
    """Validate one JSON batch before accepting it into manager state."""
    if not isinstance(data, dict):
        raise ValueError("Traffic data must be an object keyed by IPv4 address")
    for ip, records in data.items():
        IPv4Address(ip)
        if not isinstance(records, list):
            raise ValueError("Each IP must contain a list of packet records")
        for record in records:
            if not isinstance(record, list) or len(record) != 6:
                raise ValueError("Each packet must contain six fields")
            port, outgoing, length, country, program, mac = record
            if type(port) is not int or not 0 <= port <= 65535:
                raise ValueError("Invalid remote port")
            if outgoing not in ("True", "False"):
                raise ValueError("Direction must be 'True' (outgoing) or 'False' (incoming)")
            if type(length) is not int or length < 0:
                raise ValueError("Invalid packet length")
            if not all(isinstance(value, str) for value in (country, program, mac)):
                raise ValueError("Country, program and MAC must be strings")


def ip_statistic(data, settings_path=None):
    """Count packets by direction, remote IP, remote port, country and app."""
    validate_data(data)
    worker, black_list = load_settings(settings_path)
    list1 = []
    income = 0
    outcome = 0
    port_dict = {}
    dict_of_country = {}
    dict_of_apps = {}

    for ip in data:
        count = 0
        for value in data[ip]:
            if value[1] == "True":
                outcome += 1
            else:
                income += 1
            port_dict[value[0]] = port_dict.get(value[0], 0) + 1
            dict_of_country[value[3]] = dict_of_country.get(value[3], 0) + 1
            dict_of_apps[value[4]] = dict_of_apps.get(value[4], 0) + 1
            count += 1
        if count:
            list1.append([ip, count])

    matched = any(data.get(entry.partition(":")[0].strip()) for entry in black_list)
    worker_in_black_list = (worker or ["Local agent"]) if matched else []
    list1 = sorted(list1, key=itemgetter(1), reverse=True)
    sorted_ports = sorted(port_dict.items(), key=itemgetter(1), reverse=True)
    sort_countries = sorted(dict_of_country.items(), key=itemgetter(1), reverse=True)
    sort_apps = sorted(dict_of_apps.items(), key=itemgetter(1), reverse=True)
    return income, outcome, list1, sorted_ports, sort_countries, sort_apps, worker_in_black_list


def _script_json(value):
    """JSON for an inline script, including labels supplied by packet data."""
    return (json.dumps(value).replace("<", "\\u003c")
            .replace(">", "\\u003e").replace("&", "\\u0026"))


def html_upload(inc, out, ip_list, port_list, country_list, sorted_apps, worker_black,
                output_path=DEFAULT_OUTPUT):
    """Render up to three entries per chart and save a local HTML report."""
    read_file = (BASE_DIR / "templates" / "report.html").read_text(encoding="utf-8")
    values = {
        "TIMESTAMP": escape(datetime.datetime.now().isoformat(sep=" ", timespec="seconds")),
        "AGENTS_IN_KEYS": _script_json(["Local agent"]),
        "AGENTS_IN_VALUES": _script_json([inc]),
        "AGENTS_OUT_KEYS": _script_json(["Local agent"]),
        "AGENTS_OUT_VALUES": _script_json([out]),
        "ALERTS": ("<p>Blacklist traffic detected for: "
                   + ", ".join(escape(worker) for worker in worker_black) + "</p>"
                   if worker_black else "<p>No blacklist matches.</p>"),
    }
    for name, entries in (("COUNTRIES", country_list), ("IPS", ip_list),
                          ("APPS", sorted_apps), ("PORTS", port_list)):
        values[name + "_KEYS"] = _script_json([entry[0] for entry in entries[:3]])
        values[name + "_VALUES"] = _script_json([entry[1] for entry in entries[:3]])
    read_file = re.sub(r"%%([A-Z_]+)%%", lambda match: values[match[1]], read_file)
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    asset_dir = output_path.parent / "assets"
    if asset_dir != BASE_DIR / "assets":
        shutil.copytree(BASE_DIR / "assets", asset_dir, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("desktop.ini", ".DS_Store"))
    output_path.write_text(read_file, encoding="utf-8")
    return read_file


def generate_report(data, output_path=DEFAULT_OUTPUT, settings_path=None):
    """Generate a local dashboard; no report is uploaded to an external server."""
    html_upload(*ip_statistic(data, settings_path), output_path=output_path)
    return Path(output_path).resolve()
