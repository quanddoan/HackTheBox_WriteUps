# Introduction:
RomCom is a challenge that deals with VHDK image files and file system forensics, specifically, Master File Table and Update Sequence Number Journal.

Master File Table contains "all information about a file, including its size, time and date stamps, permissions, and data content, is stored either in MFT entries, or in space outside the MFT that is described by MFT entries." ([Master File Table, Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table))
MFT files maintain 2 timestamps: Standard Information (SI) and File Name (FN). Of the 2, SI contains more forensically valuable information since it reflects user interaction with the file. For more information about the difference between SI and FN timestamps, Joseph Moronwi has a fantastic and detailed blog at [Analysis of the MFT $STANDARD INFORMATION and $FILENAME Attributes](https://digitalinvestigator.blogspot.com/2025/12/ntfs-timestamps-forensic-investigation.html)

Unique Sequence Number Journal is "highly valuable because it logs detailed file system changes, including file creations, modifications, renames, and deletions, whichmakes it possible to reconstruct timelines of file activity, recover evidence of deleted files, and detect signs of anti-forensic techniques" ([NTFS Forensics: The USN Change Journal, Joseph Moronwi](https://digitalinvestigator.blogspot.com/2026/05/ntfs-forensics-usn-change-journal.html))

# Methodology:
The provided VHDK file can be mounted directly on any system, but **FTK Imager** provides a safe and forensically sound method to mount the image file.
Once mounted, the available files in the VHDK include $MFT, $J and $MAX. The Master File Table file $MFT and USN Journal file $J are of significant forensic value.

To read $MFT and $J file, **MFTEcmd by Eric Zimmerman** can be used to parse the files into CSV. There is also MFT Explorer, which provides GUI navigation but can only works on $MFT and not USN Journal files.

Another tool by Eric Zimmerman is **Timeline Explorer**, which can import the CSV files for operations, considering the vast number of records in these files that can make Excel or LibreOffice slow or freeze.

# Answers:
**Task 1:** CVE-2025-8088
**Task 2:** Path Traversal.
**Task 3:** Searching for the location C:\Users\susan\Documents reveals the files under this directory. Pathology-Department-Research-Records.rar is the only archive file.
**Task 4:** Both $MFT and $J reports Pathology-Department-Research-Records.rar created at 2025-09-02 08:13:50
**Task 5:** The official writeup notes the last accessed time at 2025-09-02 08:14:04, as this is the the timestamp of the latest event in $J. However, $MFT file reports this timestamp under Last modified, and Last accessed actually reports the timestamp 2025-09-02 08:14:18. In a real forensic event, I'd note the Last opened timestamp at 08:14:18.
**Task 6:** When an archive file is extracted, it is not necessary to extract the content in the same directory as the archive. Still, users are more likely than not to do so due to convenience. Under Susan user's Documents folder is Genotyping_Results_B57_Positive.pdf
**Task 7:** To answer this question, it requires a bit of knowledge of how CVE-2025-8088 is exploited. The malicious archive file when extracted not only extracts the intended file but also drops a malicious payload to a different location without the user's knowledge. The genuine file and the malicious payload would be created in the file system at the same time. TimelineExplorer doesn't have the feature to filter by exact seconds, but by filtering $J file column Update Reason as File Create, and search for the timestamp when Genotyping_Results_B57_Positive.pdf was created, we find a suspicious .EXE called ApbxHelper.exe. Searching for the file in $MFT yields the absolute path: C:\Users\Susan\Appdata\Local\ApbxHelper.exe
**Task 8:** At the same time ApbxHelper.exe and Genotyping_Results_B57_Positive.pdf were created, another .lnk file was also created: Display Settings.lnk.
**Task 9:** Looking up this technique on MITRE ATT&CK yields T1547.009
**Task 10:** The Last Access timestamp of Genotyping_Results_B57_Positive.pdf in $MFT file is 2025-09-02 08:15:05
