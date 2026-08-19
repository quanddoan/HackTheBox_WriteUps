**Shellbag:** everytime a folder is accessed, the register records the interaction.

Records include full path to the folder, the timestamps associated with it, and your display preferences like whether you were viewing files as a list, as tiles, or sorted by date.

**Important Keys:**
- Bags: view the settings
- BagMRU:  folder paths and hierarchy, essentially a tree of every directory the user navigated into

USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags

**Tool:** RegistryExplorer by Eric Zimmerman

The files we want to look closely at are UsrClass.dat of users 'steve' and 'admin', since those are where the most useful artifacts at.

It is easier to map out the accessed directories from the artifacts before attempting to answer the questions.
Under **BagMRU** there are accessed folders recorded as numbers: 0,1,2,3,etc. The of these directories can be found:
- In the binary of the registry key. For example: Admin BagMRU\1\0\1\0 is Temp.
- Mapped from NodeSlot to the correspoding key under Bag. For example: A key under BagMRU has NodeSlot value of 13 can be mapped to key 13 of Bag, which has 13\Shell\SniffedFolderType value as Downloads.
- Special directories such as MyComputer, Users, MyDocuments, etc. are recognized by their binaries. All keys directly under BagMRU, such as BagMRU\0, BagMRU\1, BagMRU\2, etc. are special directories. For example: Binary of BagMRU\1 is 14-00-1F-50-E0-4F-D0-20-EA-3A-69-10-A2-D8-08-00-2B-30-30-9D-00-00. 0x1F signifies the type as Root folder shell item. 0x50 means that it is My Computer. (Joachim Metz, "Windows Shell Item format specification", https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#file_entry_shell_item)

From these three mapping methods, we can map out the last accessed folders by Admin and Steve.
I won't include the mapped result since anyone interested can map on their own.

Another key to pay attention to in **BagMRU** is **MRUListEx**. It contains the most recently accessed directories, each recorded in 4 bytes. 
For example, MRUListEx has binaries 01-00-00-00-00-00-00-00-03-00-00-00-02-00-00-00-FF-FF-FF-FF means that the most recently accessed directory is the subkey 1, second most recent is 0, then 3, and the earliest accessed is 2. Use the mapping result from above to enrich the decoded result.

MRUListEx acts like a stack. In this example, when directory 2 was first accessed, its value is 02-00-00-00-FF-FF-FF-FF. Then directory 0 was accessed, and the key was written into 00-00-00-00-02-00-00-00-FF-FF-FF-FF. So, by looking up the LastWrite timestep of the registry key containing the MRUListEx, we can deduct the time that one of its subfolder was last accessed.

**For example:** BagMRU\0\1\0 was last written at 2021-09-04 11:34:21, has subkeys 0,1,2,3, and MRUListEx is 01-00-00-00-02-00-00-00-FF-FF-FF-FF. It means MRUListEx was last updated at that timestamp. Since 1 was the most recently accessed folder, it means that BagMRU\0\1\0\1 was last accessed at that timestamp.

Below are the answer to HTB Sherlocks Baggage:

After mapping out the BagMRU artifacts for Admin and Steve, it will become quite obvious that Steve user has some suspicious activities.

Task 1: BagMRU\1\0 is the Downloads folder for Steve user. BagMRU\1\0\0 is 1.zip.

Task 2: BagMRU\2\0\0\0\0 (C:\Users\steve\AppData\Local\Temp\Temp1_1.zip\1) has zip file Everything 1.4.1.1028.zip.

Task 3: The VPN folder is BagMRU\1\1\2 (C:\Users\steve\Documents\Station 3 Internal VPN), the lastWrite timestamp of BagMRU\1 is 2025-09-03 07:31:05

Task 4: The Password folder is BagMRU\1\1\0 (C:\Users\steve\Documents\OnePassword MasterPass)

Task 5: The Shared UNC folder is BagMRU\3\0\0 (\\Prod-ns-2\prodshare)

Task 6: Inside the shared folder is a directory named Construction 2027 - BagMRU\3\0\0\0

Task 7: I assume the archive file on the network share in BagMRU\3\0\0\0\0, but we couldn't get the name of the archive through this registry key. Rather, we can find it in the the Temp folder of BagMRU\2\0\0\0\1\0\0 (C:\Users\steve\AppData\Local\Temp\Temp1_a.zip\a\Dam Construction Engineer Plans.zip)

Task 8: Since the archive file is BagMRU\3\0\0\0\0 (\\Prod-ns-2\prodshare\Construction 2027\Dam Construction Engineer Plans.zip), we checked the MRUListEx of BagMRU\3\0\0\0 (\\Prod-ns-2\prodshare\Construction 2027). However, this subkey does not have a subkey or a MRUListEx, meaning the archive file has never been accessed. In this case, we check for the last time Construction 2027 was accessed through the lastWrite timestamp of BagMRU\3\0\0 (\\Prod-ns-2\prodshare). Its MRUListEx is 00-00-00-00, which points to Construction 2027, the timestamp is 2025-09-03 07:34:04.

Task 9: Other than Documents folder, we also find the 3 important folders (OnePassword MasterPass, Station 3 Internal VPN, and Engineers Tab) in BagMRU\1\2\1\0 (C:\Users\steve\Pictures\a.zip\a), which is suspicious. We can answer C:\Users\steve\Pictures\a.

Task 10: The exfiltration archive file is C:\users\steve\Pictures\a.zip or BagMRU\1\2\1, so we can check MRUListEx of BagMRU\1\2, which points to 01 as the last accessed folder. THe lastWrite timestamp is 2025-09-03 07:34:30.


This is a manual approach. There are tools that can specifically target ShellBags when analyzing Registry, such as RegRipper and TZWorks sbag.

Much, if not all, of knowledge from this article came from the brilliant blogs [Shellbags Forensics: Addressing a Misconception (interpretation, step-by-step testing, new findings, and more)](https://www.4n6k.com/2013/12/shellbags-forensics-addressing.html) by 4n6k and [Windows Shell Item format specification](https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#windows-shell-item-format-specification) by Joachim Metz
