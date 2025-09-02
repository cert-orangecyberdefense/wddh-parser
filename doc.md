# Analyse

File is located under `[root]\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\` and is manipulated by `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`.
Structure related to this file are defined in  
* `C:\ProgramData\Microsoft\Windows Defender\Platform\*\mpsvc.dll` and 
* `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\*\mpengine.dll`

DLL analysis was performed on Windows Defender 4.18.24090.11, running on Windows 10.

## Structure
LengthTypeValue repeated during the whole file with 0 padding until 8 bits alignement.

Type is an enum and could be

| value | Length (if always the same) | Description          |
|-------|-----------------------------|----------------------|
| 0x05  | 0x04                        | uint32_t             |
| 0x06  | 0x04                        | uint32_t             |
| 0x08  | 0x08                        | uint64_t             |
| 0x0a  | 0x08                        | WINDOWS_FILETIME     |
| 0x15  | variable                    | WINDOWS_WIDE_STR     |
| 0x1e  | 0x10                        | UUID (Little endian) |
| 0x28  | variable                    | Kind of unicode dict |

Type of values  has been determined through observation and association with public available structure information (eg. [MSFT_MpThreatDetection](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpthreatdetection))

In table, Size must be read as metadata (type + length byte) + data len + padding (64 bit/8 bytes alignement padding):
8+36+4 means 8 byte for type and length, 36 byte of data and 4 byte of padding.

### Section 1 (Headers)

This section contains generic information regarding threat

| LTV position  | Offset     | LTV type              | Size     | Value                                       | Description                                                                                 |
|---------------|------------|-----------------------|----------|---------------------------------------------|---------------------------------------------------------------------------------------------|
| 0             | 0          | 0x08/uint64_t         | 8+8      | "\x08\x00\x00\x00\x08\x00\x00\x00"+<u64_le> | u4_le is ThreatID (from MSFT_MpThreatDetection)                                             |
| 1             | 16         | 0x1e/WINDOWS UUID     | 8+16     |                                             | DetectionID (filename)                                                                      |
| 2  (OPTIONAL) | 40         | 0x15/WINDOWS_WIDE_STR | 8+36+4   | L"Magic.Version:1.2"                        | Version    (OPTIONAL, sample generated on Windows server 2016 without this part were found) |
| 3             | 88 (or 40) | 0x15/WINDOWS_WIDE_STR | Variable | eg: "HackTool:Win32/Mimikatz"               | Detected threat                                                                             |

### Section 2 (Flags/ID)

This section contains unknown flag and id list

Offset and TLV position are relative to section 1.

Flags may contain (information returned by MSFT_MpThreatDetection wmi object):

* CleaningActionID (quarantined?)
* DetectionSourceTypeID
* ThreatStatus ID 

| LTV position   | Offset                | LTV type      | Size                  | Value | Description                                                                                                                                |
|----------------|-----------------------|---------------|-----------------------|-------|--------------------------------------------------------------------------------------------------------------------------------------------|
| 0              | 0                     | 0x06/uint32_t | 8+4+4                 |       | Unknown, if value ==4, section 5 is present                                                                                                |
| 1              | 16                    | 0x06/uint32_t | 8+4+4                 |       | Unknown                                                                                                                                    |
| 2              | 32                    | 0x06/uint32_t | 8+4+4                 |       | Unknown                                                                                                                                    |
| 3              | 48                    | 0x06/uint32_t | 8+4+4                 |       | Unknown                                                                                                                                    |
| 4              | 64                    | 0x06/uint32_t | 8+4+4                 |       | Unknown                                                                                                                                    |
| 5              | 80                    | 0x06/uint32_t | 8+4+4                 |       | ThreatStatusID  (see. https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpthreatdetection for enum values) |
| 6              | 96                    | 0x06/uint32_t | 8+4+4                 |       | NB_TLV_SEC_2 : Number of uint32 tlv following                                                                                              |
| 7-             | 112                   | 0x06/uint32_t | (8+4+4) *NB_TLV_SEC_2 |       | Unknown                                                                                                                                    |
| 7+NB_TLV_SEC_2 | 112+ NB_TLV_SEC_2 *16 | 0x06/uint32_t | 8+4+4                 |       | Number of section 3 repetition                                                                                                             |

### Section 3 (maybe repeated)

This section contains a dictionary like object with information related to threat. It may be repeated multiple time.

Offset and TLV position are relative to section 3 beginning.

| LTV position | Offset | LTV type              | Size     | Value                                         | Description                                                                                              |
|--------------|--------|-----------------------|----------|-----------------------------------------------|----------------------------------------------------------------------------------------------------------|
| 0            | 0      | 0x15/WINDOWS_WIDE_STR | 8+36+4   | L"Magic.Version:1.2"                          | Version                                                                                                  |
| 1            |        | 0x15/WINDOWS_WIDE_STR | Variable | eg : L"file"                                  | Ressource first part (type of threat origins)                                                            |
| 2            |        | 0x15/WINDOWS_WIDE_STR | Variable | eg : L"C:\Users\RaptorSniper\Downloads\a.zip" | Threat origin Ressource URI (eg path of malicious file)                                                  |
| 3            |        | 0x06/uint32_t         | 8+4+4    |                                               | Unknown                                                                                                  |
| 4            |        | 0x06/uint32_t         | 8+4+4    |                                               | Length of next section (type and length part not included), should be equal to next section lentgth part |
| 5            |        | 0x28                  |          |                                               | Blob containing information regarding threat (see detailed section)                                      |


Note on ressources type:

Following ressources type have been encountered:

| Ressources type  | Ressource location format                                                                 | description                                                |
|------------------|-------------------------------------------------------------------------------------------|------------------------------------------------------------|
| internalbehavior | WINDOWS_WIDE_STR (eg: `E81A4FBB742602EBAFC49F2B22728376`)                                 | Multiple format                                            |
| behaviour        | WINDOWS_WIDE_STR (eg : `process: C:\\Windows\\System32\\reg.exe, pid:7652:76635945671937` | probably : `process: program_path, pid:<PID>,<Thread_id?>` |
| file             | WINDOWS_WIDE_STR (eg  : "C:\\Users\\RaptorSniper\\Downloads\\a.zip"                       | File path of identified malware                            |

### Blob section format (0x28)

The blob section is a kind of key value list of item, containing information regarding the threat

#### Blob header

On some sample, the first 4 byte contains a repetition of the blob full size (including these 4 byte)
On some other 0x18 bytes are present, containing unidentified values

After this header, a list of key followed by associated values are present

#### Blob key format

| Length     | type     | Description |
|------------|----------|-------------|
| 0x04       | uint32_t | w_str_size  |
| w_str_size | w_str    | key content |

#### Blob value format

| Length                 | type     | Description |
|------------------------|----------|-------------|
| 0x04                   | uint32_t | date_type   |
| depending of data_type |          | content     |


#### Data type 

The following data type were identified, which are different from the one used in the rest of the file.

| value | size                                                      | Description              |
|-------|-----------------------------------------------------------|--------------------------|
| 0x03  | 4                                                         | uint32                   |
| 0x04  | 8                                                         | int64 / uint64/Filetime? |
| 0x05  | 1                                                         | bool                     |
| 0x06  | 4 first bytes contain size as unsigned long little endian | w_str                    |
| 0x07  | 4 first bytes contain size as unsigned long little endian | ascii str                |

### Section 4 (metadata)

This section contains some information regarding threat

Offset and TLV position are relative to section 3 beginning.

| LTV position | Offset | LTV type              | Size  | Value | Description                |
|--------------|--------|-----------------------|-------|-------|----------------------------|
| 0            | 0      | 0x0a/WINDOWS_FILETIME | 8+8   |       | LastThreatStatusChangeTime |
| 1            | 16     | 0x05/sint32           | 8+4+4 |       | ThreatStatusErrorCode      |
| 2            | 32     | 0x06/uint32_t         | 8+4+4 |       | Unknown                    |
| 3            | 48     | 0x1e/WINDOWS UUID     | 8+16  |       | Unknown UUID               |
| 4            | 72     | 0x06/uint32_t         | 8+4+4 |       | Unknown                    |

### Section 5 (Optional)

This section is only present if value of first flag of section 2 == 4.

| LTV position | Offset | LTV type              | Size  | Value | Description |
|--------------|--------|-----------------------|-------|-------|-------------|
| 0            | 0      | 0x15/WINDOWS_WIDE_STR |       |       | Unknown     |
| 1            |        | 0x15/WINDOWS_WIDE_STR |       |       | Unknown     |
| 2            |        | 0x06/uint32_t         | 8+4+4 |       | Unknown     |
| 3            |        | 0x06/uint32_t         | 8+4+4 |       | Unknown     |
| 4            |        | 0x15/WINDOWS_WIDE_STR |       |       | Unknown     |
| 5            |        | 0x15/WINDOWS_WIDE_STR |       |       | Unknown     |

### Section 6 (more metadata)

This section contains more metadata regarding threat


| LTV position | Offset | LTV type              | Size  | Value | Description                                                |
|--------------|--------|-----------------------|-------|-------|------------------------------------------------------------|
| 0            | 0      | 0x06/uint32_t         | 8+4+4 |       | Unknown                                                    |
| 1            | 16     | 0x15/WINDOWS_WIDE_STR |       |       | DomainUser (Username of user at the origin of the threat)? |
| 2            |        | 0x06/uint32_t         | 8+4+4 |       | Unknown                                                    |
| 3            |        | 0x15/WINDOWS_WIDE_STR |       |       | ProcessName (process related to the threat)?               |
| 4            |        | 0x06/uint32_t         | 8+4+4 |       | Unknown                                                    |
| 5            |        | 0x06/uint32_t         | 8+4+4 |       | Unknown                                                    |
| 6            |        | 0x06/uint32_t         | 8+4+4 |       | Unknown                                                    |
| 7            |        | 0x0a/WINDOWS_FILETIME | 8+8   |       | InitialDetectionTime                                       |
| 8            |        | 0x06/uint32_t         | 8+4+4 |       | Unknown                                                    |
| 9            |        | 0x0a/WINDOWS_FILETIME | 8+8   |       | RemediationTime                                            |
| 10           |        | 0x06/uint32_t         | 8+4+4 |       | Unknown                                                    |
| 11           |        | 0x00                  | 8+4+4 |       | Unknown                                                    |
| 12           |        | 0x06/uint32_t         | 8+4+4 |       | Unknown                                                    |
| 13           |        | 0x15/WINDOWS_WIDE_STR |       |       | DomainUser group?                                          |
| 14           |        | 0x06/uint32_t         | 8+4+4 |       | Unknown                                                    |
| 15           |        | 0x06/uint32_t         | 8+4+4 |       | Number of section 7 repetition                             |


### Section 7

This section is identical to section 3

### Section 8 (footer)

| LTV position | Offset | LTV type      | Size  | Value | Description |
|--------------|--------|---------------|-------|-------|-------------|
| 0            | 0      | 0x00          | 8+4+4 |       | Unknown     |
| 1            | 16     | 0x06/uint32_t | 8+4+4 |       | Unknown     |
| 2            | 32     | 0x06/uint32_t | 8+4+4 |       | Unknown     |
| 3            | 48     | 0x06/uint32_t | 8+4+4 |       | Unknown     |
| 4            | 64     | 0x06/uint32_t | 8+4+4 |       | Unknown     |

### TEST

Comparaison of result on live system could be made using wmi

```
PS C:\Windows\system32> Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" -Class MSFT_MpThreatDetection
__GENUS                        : 2
__CLASS                        : MSFT_MpThreatDetection
__SUPERCLASS                   : BaseStatus
__DYNASTY                      : BaseStatus
__RELPATH                      : MSFT_MpThreatDetection.DetectionID="{94BBE9CF-CDEB-4885-9178-CC93FB10822D}",ThreatID="2147686744"
__PROPERTY_COUNT               : 16
__DERIVATION                   : {BaseStatus}
__SERVER                       : DESKTOP-O8964S4
__NAMESPACE                    : root\Microsoft\Windows\Defender
__PATH                         : \\DESKTOP-O8964S4\root\Microsoft\Windows\Defender:MSFT_MpThreatDetection.DetectionID="{94BBE9CF-CDEB-4885-9178-CC93FB10822D}",ThreatID="2147686744"
ActionSuccess                  : True
AdditionalActionsBitMask       : 0
AMProductVersion               : 4.18.24090.11
CleaningActionID               : 2
CurrentThreatExecutionStatusID : 1
DetectionID                    : {94BBE9CF-CDEB-4885-9178-CC93FB10822D}
DetectionSourceTypeID          : 3
DomainUser                     : DESKTOP-O8964S4\RaptorSniper
InitialDetectionTime           : 20250128164451.243000+000
LastThreatStatusChangeTime     : 20250128164506.220000+000
ProcessName                    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
RemediationTime                : 20250128164506.220000+000
Resources                      : {file:_C:\Users\RaptorSniper\Downloads\a.zip}
ThreatID                       : 2147686744
ThreatStatusErrorCode          : 0 
ThreatStatusID                 : 3
PSComputerName                 : DESKTOP-O8964S4
```

## Others known documentation

* https://github.com/log2timeline/plaso/blob/main/plaso/parsers/windefender_history.py
* https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Defender%20scan%20DetectionHistory%20file%20format.asciidoc
* https://github.com/jklepsercyber/defender-detectionhistory-parser