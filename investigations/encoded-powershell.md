# Encoded PowerShell Investigation

## Test

Executed an encoded PowerShell command on the Windows 11 VM.

Original command:

    Write-Output 'SOC Lab Test'

Encoded using UTF-16LE and Base64, then executed with PowerShell's `-EncodedCommand` argument.

## Detection

Used Sysmon Event ID 1 (Process Create) to identify the command-line argument in Splunk.

The search returned one matching process creation event.

- Process: `powershell.exe`
- Parent: `powershell.exe`
- Host: `windows11-soc-e`
- Timestamp: October 25, 2026
- Detection: `-EncodedCommand` in the process command line

Detection query: [encoded-powershell.spl](../detections/encoded-powershell.spl)

## Investigation

Extracted the Base64 argument from the recorded command line and decoded it using PowerShell:

    [Text.Encoding]::Unicode.GetString(
        [Convert]::FromBase64String($payload)
    )

Decoded result:

    Write-Output 'SOC Lab Test'

The decoded command matched the original test payload.

## Conclusion

Benign test activity generated intentionally inside the lab.

The search identifies encoded PowerShell execution, but the command-line argument alone is not sufficient to determine malicious intent.
