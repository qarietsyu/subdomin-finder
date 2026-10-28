# 🔎 Subdomain Finder

A passive subdomain discovery tool built with Python and Streamlit. It searches public **Certificate Transparency (CT) logs** through [crt.sh](https://crt.sh) to list subdomains of a domain, with **no API keys** and no traffic sent to the target.

## Features

- Accepts messy input (`https://www.Example.com/path` becomes `example.com`)
- Finds subdomains from every certificate ever logged for `*.domain`
- Per-subdomain details: first seen, latest certificate expiry, certificate count, issuer, wildcard flag
- Optional parallel DNS resolution to show which hosts are **live** and their IPv4 address
- Search box and toggles to show only live hosts or hide wildcard entries
- Metric cards, issuer chart, and a raw response viewer
- Export results as **CSV** or a plain **TXT** list
- Results cached for one hour to be gentle on crt.sh

## Data source (free, keyless)

```
https://crt.sh/?q=%25.example.com&output=json
```

## Run locally

```bash
git clone https://github.com/<your-username>/subdomain-finder.git
cd subdomain-finder
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud

1. Push `app.py`, `requirements.txt` and `README.md` to a public GitHub repository.
2. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
3. Click **Create app**, choose your repository and branch, and set the main file path to `app.py`.
4. Click **Deploy**.

## Project structure

```
subdomain-finder/
├── app.py
├── requirements.txt
└── README.md
```

## Notes and limitations

- **crt.sh can be slow or return errors (502/504)**, especially for very large domains. The app retries up to 3 times with a 60-second timeout. If it fails, try again shortly.
- CT logs only show names that appeared on public certificates. Internal hosts or sites without HTTPS may not appear.
- A subdomain in the logs may no longer exist. Use the DNS status column to check which ones still resolve.
- DNS resolution runs from the Streamlit server, so results can differ from your own network (split-horizon DNS).

## Responsible use

This tool is passive and uses public data, but use it only on domains you own or are authorised to assess.

## Credits

Built with [Streamlit](https://streamlit.io), [pandas](https://pandas.pydata.org) and data from [crt.sh](https://crt.sh).

## License

MIT
