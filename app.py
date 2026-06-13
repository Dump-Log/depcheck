import tempfile
import streamlit as st
from analyze import analyze, AnalysisResult

st.set_page_config(
    page_title="DepCheck",
    page_icon="🕵",
    layout="wide",
)

st.markdown("""
    <style>
        [data-testid="stToolbar"] {visibility: hidden; height: 0;}
        [data-testid="stDecoration"] {visibility: hidden;}
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

st.title("🕵 DepCheck")
st.caption("Python dependency risk scanner — detects typosquatted dependencies and known vulnerabilities")

# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------

# Input mode selector and file uploader live outside the form
# so st.file_uploader renders correctly
input_mode = st.radio("Input method", ["GitHub URL", "Upload File"], horizontal=True)

uploaded_file = None
if input_mode == "Upload File":
    uploaded_file = st.file_uploader("requirements.txt", type=["txt"])

with st.form("analysis_form"):
    source_url = None
    if input_mode == "GitHub URL":
        source_url = st.text_input(
            "GitHub repo or blob URL",
            placeholder="https://github.com/../../requirements.txt",
        )

    col1, col2 = st.columns([3, 1])
    with col2:
        skip_squats = st.checkbox("Skip typosquat detection", value=False)
        skip_vulns = st.checkbox("Skip vulnerability scan", value=False)

    run = st.form_submit_button("Analyze", type="primary")

# ---------------------------------------------------------------------------
# Run analysis
# ---------------------------------------------------------------------------

# Resolve source — either GitHub URL or uploaded file written to a temp path
source = None
tmp_path = None

if run:
    if input_mode == "Upload File" and uploaded_file:
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".txt", delete=False) as f:
            f.write(uploaded_file.read())
            tmp_path = f.name
        source = tmp_path
    elif input_mode == "GitHub URL" and source_url:
        source = source_url

if run and source:
    status_box = st.empty()
    messages = []

    def status(msg):
        messages.append(msg)
        status_box.info("\n\n".join(f"→ {m}" for m in messages))

    with st.spinner("Running analysis..."):
        try:
            result: AnalysisResult = analyze(source, status_callback=status, skip_squats=skip_squats)
        except Exception as e:
            st.error(f"Analysis failed: {e}")
            st.stop()

    status_box.empty()

    if result.errors:
        for e in result.errors:
            st.warning(e)

    # ---------------------------------------------------------------------------
    # Summary metrics
    # ---------------------------------------------------------------------------

    total = len(result.dependencies)
    direct = sum(1 for d in result.dependencies if d.is_direct)
    total_vulns = sum(len(d.vulns) for d in result.dependencies)
    high_squats = sum(1 for f in result.squat_findings if f.suspicion_score >= 0.6)
    med_squats = sum(1 for f in result.squat_findings if 0.35 <= f.suspicion_score < 0.6)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Dependencies", total, f"{direct} direct")
    m2.metric("Vulnerabilities", total_vulns)
    m3.metric("High Risk Squats", high_squats)
    m4.metric("Medium Risk Squats", med_squats)

    st.divider()

    # ---------------------------------------------------------------------------
    # 1. Typosquat findings (first)
    # ---------------------------------------------------------------------------

    if not skip_squats:
        with st.expander(f"🎭 Typosquat Findings ({len(result.squat_findings)} found)", expanded=True):
            if not result.squat_findings:
                st.success("No suspicious dependencies found.")
            else:
                st.caption(
                    "These packages in your dependency tree resemble popular legitimate packages "
                    "but are not those packages. They may be typosquats."
                )
                for f in result.squat_findings:
                    if f.suspicion_score >= 0.6:
                        color, label = "🔴", "HIGH"
                    elif f.suspicion_score >= 0.35:
                        color, label = "🟡", "MEDIUM"
                    else:
                        color, label = "🔵", "LOW"

                    with st.container(border=True):
                        # Header row
                        col_a, col_b, col_c = st.columns([2, 2, 1])
                        col_a.markdown(f"**`{f.dep_name}`** version `{f.dep_version}`")
                        col_b.markdown(f"resembles popular package **`{f.resembles}`** (edit distance {f.edit_distance})")
                        col_c.markdown(f"{color} **{label}** — score `{f.suspicion_score:.2f}`")

                        # Metadata row
                        meta_cols = st.columns(4)

                        if f.days_since_first_upload is not None:
                            years = f.days_since_first_upload / 365
                            age_str = f"{years:.1f} years" if years >= 1 else f"{f.days_since_first_upload} days"
                            meta_cols[0].metric("Package Age", age_str,
                                delta=f"first upload {f.first_upload_date}",
                                delta_color="off")
                        else:
                            meta_cols[0].metric("Package Age", "Unknown")

                        if f.days_since_latest_upload is not None:
                            meta_cols[1].metric("Last Updated",
                                f"{f.days_since_latest_upload}d ago",
                                delta=f.latest_upload_date,
                                delta_color="off")
                        else:
                            meta_cols[1].metric("Last Updated", "Unknown")

                        meta_cols[2].metric("Total Releases", f.total_releases or "?")

                        if f.pypi_url:
                            meta_cols[3].markdown(f"[View on PyPI ↗]({f.pypi_url})")

                        # Author + source info
                        info_parts = []
                        if f.author:
                            info_parts.append(f"**Author:** {f.author}")
                        if f.author_email:
                            info_parts.append(f"**Email:** {f.author_email}")
                        if f.source_url:
                            info_parts.append(f"**Source:** [{f.source_url}]({f.source_url})")
                        else:
                            info_parts.append("**Source:** ⚠️ not listed")
                        if f.license:
                            info_parts.append(f"**License:** {f.license}")
                        if f.summary:
                            info_parts.append(f"**Description:** {f.summary}")

                        dist_parts = []
                        if f.has_wheel is not None:
                            dist_parts.append(f"wheel: {'✓' if f.has_wheel else '✗'}")
                        if f.has_sdist is not None:
                            dist_parts.append(f"sdist: {'✓' if f.has_sdist else '✗'}")
                        if dist_parts:
                            info_parts.append(f"**Distribution:** {', '.join(dist_parts)}")

                        if info_parts:
                            st.caption(" · ".join(info_parts))

                        # Signals
                        st.markdown("**Suspicion signals:**")
                        for signal in f.signals:
                            st.caption(f"• {signal}")

                st.caption("Score: 🔴 ≥0.60 high | 🟡 ≥0.35 medium | 🔵 <0.35 low")

    # ---------------------------------------------------------------------------
    # 2. Vulnerability findings
    # ---------------------------------------------------------------------------

    if not skip_vulns:
        vulnerable = [d for d in result.dependencies if d.vulns]
        total_v = sum(len(d.vulns) for d in vulnerable)
        with st.expander(f"🚨 Vulnerability Findings ({total_v} total)", expanded=True):
            if not vulnerable:
                st.success("No known vulnerabilities found.")
            else:
                vuln_data = [
                    {
                        "Package": d.name,
                        "Version": d.version,
                        "Vuln ID": v.vuln_id,
                        "CVE / Alias": ", ".join(v.aliases[:2]) if v.aliases else "—",
                        "Fix Version": ", ".join(v.fix_versions) if v.fix_versions else "None available",
                    }
                    for d in vulnerable
                    for v in d.vulns
                ]
                st.dataframe(vuln_data, use_container_width=True, hide_index=True)

    # ---------------------------------------------------------------------------
    # 3. Dependencies table
    # ---------------------------------------------------------------------------

    with st.expander("📦 Resolved Dependencies", expanded=True):
        dep_data = [
            {
                "Package": d.name,
                "Version": d.version,
                "Type": "direct" if d.is_direct else "transitive",
                "Vulnerabilities": len(d.vulns),
            }
            for d in sorted(result.dependencies, key=lambda d: (not d.is_direct, d.name.lower()))
        ]
        st.dataframe(dep_data, use_container_width=True, hide_index=True)

    # Clean up temp file if one was created
    if tmp_path:
        import os
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

elif run and not source:
    st.warning("Please paste a GitHub URL or upload a requirements.txt file.")