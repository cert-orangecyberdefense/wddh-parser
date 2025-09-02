rule WindowsDefenderDetectionHistory
{
	meta:
        description = "Juste a simple yara rule looking for windows WindowsDefenderDetectionHistory sample"
		threat_level = 0
	strings:
		$magic_version = "Magic.Version" wide ascii

    condition:
        $magic_version and uint32(0) == 0x08 and uint32(4) == 0x08
}