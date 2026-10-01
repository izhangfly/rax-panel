# rax-panel

A Streamlit panel for connecting to servers over SSH and triaging what shows up in their logs. You enter a host, user, and password in the sidebar, and the panel opens an SSH session and classifies the interesting lines.

## Running

```bash
pip install streamlit paramiko
streamlit run app.py
```

## Notes

- Connection details are typed into the sidebar and held in Streamlit session state; nothing is hardcoded.
- The log classifier groups lines by hostname and surfaces the notable ones.
