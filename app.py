"""
Subdomain Finder
----------------
Passive subdomain discovery using Certificate Transparency (CT) logs via crt.sh.
No API keys, no brute forcing, and no traffic sent to the target.
"""

import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

import pandas as pd
import requests
import streamlit as st

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
st.set_page_config(page_title="Subdomain Finder", page_icon="🔎", layout="wide")

CRT_URL = "https://crt.sh/"
HEADERS = {"User-Agent": "subdomain-finder-streamlit/1.0"}
DOMAIN_RE = re.compile(r"^([a-z0-9-]+\.)+[a-z0-9-]{2,}$")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def clean_domain(raw: str) -> str:
    """Normalise user input like 'https://www.GitHub.com/path' -> 'github.com'."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split("?")[0].split(":")[0].strip(".")
    return d.removeprefix("www.")


def short_issuer(issuer_name: str) -> str:
    match = re.search(r"O=([^,]+)", issuer_name or "") or re.search(r"CN=([^,]+)", issuer_name or "")
    return match.group(1).strip('" ') if match else "Unknown"


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_ct_records(domain: str, attempts: int = 3) -> list[dict]:
    """Query crt.sh for every certificate that mentions *.domain (with retries)."""
    last_error = None
    for attempt in range(attempts):
        try:
            resp = requests.get(
                CRT_URL,
                params={"q": f"%.{domain}", "output": "json"},
                headers=HEADERS,
                timeout=60,
            )
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            last_error = exc
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"crt.sh did not respond after {attempts} attempts: {last_error}")


def build_dataframe(records: list[dict], domain: str) -> pd.DataFrame:
    """Aggregate certificate records into one row per unique subdomain."""
    found: dict[str, dict] = {}

    for rec in records:
        not_before = pd.to_datetime(rec.get("not_before"), errors="coerce")
        not_after = pd.to_datetime(rec.get("not_after"), errors="coerce")
        issuer = short_issuer(rec.get("issuer_name", ""))

        for raw_name in str(rec.get("name_value", "")).splitlines():
            name = raw_name.strip().lower()
            if not name or "@" in name:
                continue
            is_wildcard = name.startswith("*.")
            name = name.removeprefix("*.")
            if name != domain and not name.endswith("." + domain):
                continue

            row = found.setdefault(
                name,
                {
                    "subdomain": name,
                    "first_seen": not_before,
                    "latest_expiry": not_after,
                    "certificates": 0,
                    "issuer": issuer,
                    "wildcard": False,
                    "_latest_start": not_before,
                },
            )
            row["certificates"] += 1
            row["wildcard"] = row["wildcard"] or is_wildcard
            if pd.notna(not_before) and (pd.isna(row["first_seen"]) or not_before < row["first_seen"]):
                row["first_seen"] = not_before
            if pd.notna(not_after) and (pd.isna(row["latest_expiry"]) or not_after > row["latest_expiry"]):
                row["latest_expiry"] = not_after
            if pd.notna(not_before) and (pd.isna(row["_latest_start"]) or not_before > row["_latest_start"]):
                row["_latest_start"] = not_before
                row["issuer"] = issuer

    if not found:
        return pd.DataFrame()

    df = pd.DataFrame(found.values()).drop(columns="_latest_start")
    return df.sort_values("subdomain").reset_index(drop=True)


def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""


@st.cache_data(ttl=3600, show_spinner=False)
def resolve_hosts(hosts: tuple[str, ...]) -> dict[str, str]:
    """Resolve hostnames to IPv4 in parallel."""
    with ThreadPoolExecutor(max_workers=30) as pool:
        return dict(zip(hosts, pool.map(_resolve, hosts)))


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Options")
    do_resolve = st.toggle("Resolve DNS (check which are live)", value=True)
    max_resolve = st.slider("Max hosts to resolve", 25, 500, 200, step=25, disabled=not do_resolve)
    st.divider()
    st.caption(
        "Passive recon only: results come from public Certificate Transparency logs "
        "through [crt.sh](https://crt.sh). Use on domains you own or are authorised to assess."
    )

# --------------------------------------------------------------------------
# Header + input
# --------------------------------------------------------------------------
st.title("🔎 Subdomain Finder")
st.caption("Discover subdomains of any domain from Certificate Transparency logs. No API key needed.")

with st.form("search_form"):
    col_in, col_btn = st.columns([4, 1], vertical_alignment="bottom")
    raw_input = col_in.text_input("Domain", placeholder="example.com")
    submitted = col_btn.form_submit_button("Find subdomains", use_container_width=True, type="primary")

if submitted:
    domain = clean_domain(raw_input)
    if not DOMAIN_RE.match(domain):
        st.session_state.pop("domain", None)
        st.error("Please enter a valid domain such as `example.com`.")
    else:
        st.session_state["domain"] = domain

domain = st.session_state.get("domain")

# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------
if domain:
    try:
        with st.spinner(f"Querying certificate transparency logs for {domain}... (can take up to a minute)"):
            records = fetch_ct_records(domain)
    except RuntimeError as exc:
        st.error(f"{exc}. crt.sh is often busy, so please try again in a moment.")
        st.stop()

    df = build_dataframe(records, domain)
    if df.empty:
        st.warning(f"No subdomains found for **{domain}** in CT logs.")
        st.stop()

    if do_resolve:
        hosts = tuple(df["subdomain"].head(max_resolve))
        with st.spinner(f"Resolving {len(hosts)} hosts..."):
            ip_map = resolve_hosts(hosts)
        df["ip"] = df["subdomain"].map(ip_map)
        df["status"] = df.apply(
            lambda r: "Not checked" if pd.isna(r["ip"]) else ("Live" if r["ip"] else "No DNS record"),
            axis=1,
        )
    else:
        df["ip"] = None
        df["status"] = "Not checked"

    # ---- Metric cards
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Unique subdomains", f"{len(df):,}")
    m2.metric("Certificates scanned", f"{len(records):,}")
    m3.metric("Resolving (live)", f"{(df['status'] == 'Live').sum():,}" if do_resolve else "n/a")
    m4.metric("Issuers", df["issuer"].nunique())

    # ---- Filters
    f1, f2, f3 = st.columns([3, 1, 1], vertical_alignment="bottom")
    query = f1.text_input("Filter results", placeholder="e.g. api, dev, staging")
    only_live = f2.toggle("Only live", value=False, disabled=not do_resolve)
    hide_wildcard = f3.toggle("Hide wildcard", value=False)

    view = df.copy()
    if query:
        view = view[view["subdomain"].str.contains(query.strip().lower(), regex=False)]
    if only_live:
        view = view[view["status"] == "Live"]
    if hide_wildcard:
        view = view[~view["wildcard"]]

    st.subheader(f"Results for {domain} ({len(view):,} shown)")
    st.dataframe(
        view[["subdomain", "status", "ip", "first_seen", "latest_expiry", "certificates", "issuer", "wildcard"]],
        hide_index=True,
        use_container_width=True,
        height=450,
        column_config={
            "subdomain": "Subdomain",
            "status": "DNS status",
            "ip": "IPv4",
            "first_seen": st.column_config.DateColumn("First seen", format="YYYY-MM-DD"),
            "latest_expiry": st.column_config.DateColumn("Latest expiry", format="YYYY-MM-DD"),
            "certificates": st.column_config.NumberColumn("Certs"),
            "issuer": "Issuer",
            "wildcard": st.column_config.CheckboxColumn("Wildcard"),
        },
    )

    d1, d2 = st.columns(2)
    d1.download_button(
        "⬇️ Download results (CSV)",
        view.to_csv(index=False),
        file_name=f"{domain}_subdomains.csv",
        mime="text/csv",
        use_container_width=True,
    )
    d2.download_button(
        "⬇️ Download subdomain list (TXT)",
        "\n".join(view["subdomain"]),
        file_name=f"{domain}_subdomains.txt",
        mime="text/plain",
        use_container_width=True,
    )

    # ---- Insights
    with st.expander("📊 Certificate issuers"):
        st.bar_chart(df["issuer"].value_counts().head(10))

    with st.expander("🔎 Raw crt.sh response (first 50 records)"):
        st.json(records[:50])
else:
    st.info("Enter a domain above to start. Try `github.com` or a domain you own.")
