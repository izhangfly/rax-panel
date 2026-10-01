import base64
import re
import streamlit as st
import paramiko

st.set_page_config(page_title="Router VPN Rules", page_icon="🛡️", layout="wide")

DEFAULT_HOST = ""
CONFIG_PATH = "/etc/openclash/config/clash-config.yaml"
LOG_PATH = "/tmp/openclash.log"

# ----------------------------- connection -----------------------------
st.sidebar.header("🔌 Router")
host = st.sidebar.text_input("Host", DEFAULT_HOST,
                             help="On the Germany server this is 127.0.0.1 (reverse tunnel).")
port = st.sidebar.number_input("SSH port", value=22, min_value=1, max_value=65535, step=1)
user = st.sidebar.text_input("User", "")
pw = st.sidebar.text_input("Root password", type="password", value=st.session_state.get("pw", ""))
if pw:
    st.session_state["pw"] = pw
st.sidebar.caption("Password is kept only in this browser session. The panel only ever "
                   "touches the OpenClash config + restarts OpenClash — nothing else on the router.")


def _client():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port=int(port), username=user, password=st.session_state.get("pw", ""),
              timeout=10, look_for_keys=False, allow_agent=False)
    return c


def run(cmd, timeout=90):
    c = _client()
    try:
        _, out, err = c.exec_command(cmd, timeout=timeout)
        return out.read().decode("utf-8", "replace"), err.read().decode("utf-8", "replace")
    finally:
        c.close()


def read_config():
    out, err = run(f"cat {CONFIG_PATH}")
    if err.strip():
        st.error(err)
    return out


def write_config(text):
    b64 = base64.b64encode(text.encode()).decode()
    run(f"cp {CONFIG_PATH} {CONFIG_PATH}.bak")           # backup first (revert-able)
    run(f"printf %s '{b64}' | base64 -d > {CONFIG_PATH}")


def restart_openclash():
    return run("/etc/init.d/openclash restart", timeout=120)


def classify(value):
    """Return (kind, normalized_value, no_resolve)."""
    v = value.strip().lstrip("*.")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", v):
        if "/" not in v:
            v += "/32"
        return "IP-CIDR", v, True
    return "DOMAIN-SUFFIX", v, False


def add_rule(kind, value, action, no_resolve):
    cfg = read_config()
    rule = f"  - {kind},{value},{action}" + (",no-resolve" if no_resolve else "")
    existing = [l.strip() for l in cfg.splitlines()]
    if rule.strip() in existing:
        return "exists", None
    lines = cfg.splitlines()
    try:
        idx = next(i for i, l in enumerate(lines) if l.strip() == "rules:")
    except StopIteration:
        return "no-rules-block", None
    lines.insert(idx + 1, rule)                          # top priority, right under `rules:`
    write_config("\n".join(lines) + "\n")
    return "added", rule


def apply_and_restart():
    with st.spinner("Restarting OpenClash…"):
        out, err = restart_openclash()
    ok = "Start Successful" in out or "Start Successful" in err
    (st.success if ok else st.warning)(
        "OpenClash restarted." if ok else "Restarted — verify health below.")


if not st.session_state.get("pw"):
    st.info("Enter the router root password in the sidebar to begin.")
    st.stop()

tab_health, tab_log, tab_add, tab_rules = st.tabs(
    ["🩺 Health", "📡 Log → one-click fix", "➕ Add rule", "📄 Current rules"])

# ----------------------------- health -----------------------------
with tab_health:
    st.subheader("Is the tunnel healthy?")
    if st.button("Check now", type="primary"):
        try:
            core, _ = run("pgrep -f clash_meta >/dev/null 2>&1 && echo UP || echo DOWN")
            ports, _ = run("netstat -tlnp 2>/dev/null | grep -c -E ':7893|:9090'")
            log, _ = run(f"tail -n 300 {LOG_PATH}")
            load, _ = run("uptime")
            proxy_ok = log.count("using PROXY[Reality-DE]")
            direct_ok = log.count("using DIRECT")
            timeouts = log.count("i/o timeout")
            dnsfail = log.count("couldn't find ip") + log.count("dns resolve failed")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Core", core.strip())
            c2.metric("Ports up (7893/9090)", ports.strip())
            c3.metric("PROXY ok (300 lines)", proxy_ok)
            c4.metric("Timeouts / DNS fails", f"{timeouts} / {dnsfail}")
            st.caption(f"Load: {load.strip()}")
            if timeouts > proxy_ok:
                st.warning("Lots of timeouts vs. successful proxy hits — tunnel or uplink is "
                           "struggling (see the slowness notes).")
            else:
                st.success("Core up, proxy is passing traffic.")
        except Exception as e:
            st.error(f"SSH failed: {e}")

# ----------------------------- log -> fix -----------------------------
with tab_log:
    st.subheader("Connections that fell to DIRECT and timed out (candidates to send via Germany)")
    st.caption("Foreign apps that are blocked show up here as DIRECT + timeout. "
               "Chinese hosts (.cn / cn CDNs) usually should stay DIRECT — don't proxy those.")
    if st.button("Scan log"):
        log, _ = run(f"tail -n 1500 {LOG_PATH}")
        hits = {}
        for line in log.splitlines():
            if ("i/o timeout" in line or "couldn't find ip" in line) and "-->" in line:
                m = re.search(r"-->\s+([^\s:]+):\d+", line)
                if m:
                    hits[m.group(1)] = hits.get(m.group(1), 0) + 1
        st.session_state["hits"] = dict(sorted(hits.items(), key=lambda x: -x[1]))
    for hostname, n in st.session_state.get("hits", {}).items():
        cn_hint = " · looks Chinese (keep DIRECT?)" if hostname.endswith(".cn") else ""
        col1, col2, col3, col4 = st.columns([4, 1, 1, 1])
        col1.write(f"`{hostname}`  ×{n}{cn_hint}")
        kind, val, nr = classify(hostname)
        if col2.button("→ Germany", key=f"p_{hostname}"):
            status, rule = add_rule(kind, val, "PROXY", nr)
            st.toast(f"{status}: {rule or hostname}")
            apply_and_restart()
        if col3.button("Direct", key=f"d_{hostname}"):
            status, rule = add_rule(kind, val, "DIRECT", nr)
            st.toast(f"{status}: {rule or hostname}")
            apply_and_restart()
        if col4.button("Block", key=f"r_{hostname}"):
            status, rule = add_rule(kind, val, "REJECT", nr)
            st.toast(f"{status}: {rule or hostname}")
            apply_and_restart()

# ----------------------------- manual add -----------------------------
with tab_add:
    st.subheader("Add a domain or IP by hand")
    value = st.text_input("Domain or IP / CIDR", placeholder="e.g. atomlearning.com  or  160.79.104.0/23")
    action = st.radio("Route it…", ["PROXY (→ Germany)", "DIRECT (→ local)", "REJECT (block)"],
                      horizontal=True)
    if value:
        kind, val, nr = classify(value)
        st.caption(f"Will add:  `- {kind},{val},{action.split()[0]}"
                   f"{',no-resolve' if nr else ''}`")
    if st.button("Add + deploy", type="primary", disabled=not value):
        kind, val, nr = classify(value)
        status, rule = add_rule(kind, val, action.split()[0], nr)
        if status == "added":
            st.success(f"Added `{rule}`")
            apply_and_restart()
        elif status == "exists":
            st.info("That rule already exists.")
        else:
            st.error(status)

# ----------------------------- current rules -----------------------------
with tab_rules:
    st.subheader("Current rules on the router")
    if st.button("Load"):
        cfg = read_config()
        block = cfg.split("rules:", 1)[-1] if "rules:" in cfg else cfg
        st.code("rules:" + block, language="yaml")
    st.divider()
    if st.button("↩︎ Revert to last backup (.bak) + restart"):
        run(f"cp {CONFIG_PATH}.bak {CONFIG_PATH}")
        apply_and_restart()
