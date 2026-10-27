
# Splunk SIEM Home Lab

A home lab I built using VirtualBox, Splunk Enterprise, and Sysmon to practice Windows log analysis and basic SOC detection workflows.

The setup consists of an Ubuntu VM running Splunk Enterprise and a Windows 11 VM forwarding event logs through Splunk Universal Forwarder.

## Lab Environment

| Component | Setup |
| SIEM | Splunk Enterprise 10.6.0.5 |
| Server | Ubuntu Desktop 24.04 |
| Endpoint | Windows 11 |
| Virtualization | VirtualBox |
| Log Collection | Splunk Universal Forwarder, Sysmon |
| Splunk Index | `windows` |

Both VMs use NAT for internet access and a host-only network for communication with each other.

Windows forwards logs to Splunk at `192.168.104.10:9997`.

## Log Collection

Configured Splunk to receive the following Windows Event Logs:

- Security
- System
- Application
- Microsoft-Windows-Sysmon/Operational

Sysmon events were ingested in XML format using `renderXml = 1`.

I used SPL field extraction to retrieve process information from Sysmon Event ID 1, including executable paths, command-line arguments, and parent processes.

## Detection Testing

### Encoded PowerShell

Ran a Base64-encoded PowerShell command on the Windows VM to generate a process creation event.

The decoded command was:

```powershell
Write-Output 'SOC Lab Test'
```

Created an SPL search to identify PowerShell processes using the `-EncodedCommand` argument.

Splunk detected the event, and I extracted and decoded the Base64 payload to confirm what was executed.

**Result:** Detected successfully. Benign test activity.

### Failed Login Attempt

Generated a failed Windows authentication attempt against a local test account.

The failed authentication produced Windows Security Event ID 4625, which was forwarded to Splunk.

Used the event to test failed-login monitoring on the dashboard.

## Dashboard

Created a dashboard with four panels:

- Windows event volume
- Failed Windows logins
- Top 10 process creations
- Encoded PowerShell detections


## Issues Encountered

**VirtualBox networking:** The Ubuntu host-only adapter wasn't receiving an IP address because DHCP was disabled. Assigned static IPs to both VMs and verified communication on TCP 9997.

**Sysmon permissions:** Splunk Universal Forwarder couldn't subscribe to the Sysmon Operational channel (`errorCode=5`). Added the forwarder's service account to the Windows Event Log Readers group.

**Log forwarding:** Forwarding stopped working after restoring saved VM states. Verified the network settings and Splunk listener, then resolved the issue with a full shutdown and restart of both VMs.

**XML field extraction:** Splunk wasn't automatically extracting the Sysmon process fields. Used `rex` to extract the necessary values from raw XML.

## Notes

The detections were tested against activity generated inside the lab. They are basic examples to show proof of concept ideas, not production-ready detection rules.
