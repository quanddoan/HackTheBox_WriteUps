# Introduction
PhantomCheck provides Windows Event logs in form of .evxt files

# Methodology
**Hayabusa** is a security tool by Yamato Security that use a collection of Sigma rule to evaluate Windows Event logs and discover IOCs.
Using Hayabusa with `dfir-timeline` option creates CSV files from .EVXT source that can be parsed into **Timeline Explorer** for further analysis.
The result CSV will contain the valuable information field such as: Timestamp, Rule title, Level, Computer, Channel, Event ID, Record ID, Details

# Answers:
**Task 1:** Search for `WMI` will yield the PowerShell commands used to retrieve model and manufacturer of the system, which utilized Win32_ComputerSystem class.

**Task 2:** Search for `WMI` also reveals the command used to retrieve current temperature with the command `SELECT * FROM MSAcpi_ThermalZoneTemperature`

**Task 3:** Once the CSV files from Hayabusa are parsed into Timeline Explorer, one of the first action for a Security Analyst is to triage the events. The Powershell script used to check virtual environment was classified as `Malicious Nishang PowerShell Commandlets` by Hayabusa with a Level High, which stands out amongst the records. Inspecting the script reveals the function Check-VM

**Task 4:** Inspecting the script further will reveal HKLM:\SYSTEM\ControlSet001\Services

**Task 5:** In the script, vboxservice.exe and vboxtray.exe are used to detect VirtualBox Env

**Task 6:** Filter for records that contains "This is a" in Details field returns records that include a "PwSh Pipeline Exec" record containing the output of the script. Hyper-V and VMware were detected.
