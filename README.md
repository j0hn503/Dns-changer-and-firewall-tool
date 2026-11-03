# Network Security Studio

A Windows desktop app for managing selected Windows Firewall rules, DNS resolvers,
and blocked domains in the Windows hosts file.

> **Use with care:** Firewall and DNS changes affect your whole computer. Review
> each action before applying it. Blocking Telegram IPs or domains can interrupt
> Telegram services, and DNS filtering depends on the selected provider. This
> tool is provided as-is and does not guarantee protection from data theft,
> malware, or other security threats.

## Features

- Add or remove the app's Telegram IP firewall rules, check their status, and
  test connectivity.
- Choose from public DNS providers by filtering category, apply DNS settings to
  active network adapters, flush the DNS cache, or restore DNS through DHCP.
- Manage domain blocks in the Windows hosts file, with backups and restore
  options.
- Follow the guided setup for a NextDNS profile and open the DNS test in a
  private browser window when a supported browser is installed.
- Start in limited mode and request administrator access only for actions that
  need it.

## Requirements

- Windows 10 or later
- Python 3.8 or later
- `customtkinter` (for running from source)

## Run from source

1. Install Python, then install the app dependency:

   ```powershell
   python -m pip install customtkinter
   ```

2. Start the app:

   ```powershell
   python firewall_gui.py
   ```

   Alternatively, double-click `firewall_gui.pyw` to launch without a console.

Some actions require administrator privileges. Use **Enable admin** in the app
when prompted.

## Build a Windows executable

Run the included builder; it installs PyInstaller if it is not already available:

```powershell
python build_exe.py
```

The executable is written to `dist/NetworkSecurityStudio.exe`. To build a
directory-based version instead, run:

```powershell
python build_exe.py --onedir
```

## License

This project is distributed under the [MIT License](LICENSE).

**Uploaded by:** [john503](https://github.com/j0hn503)
