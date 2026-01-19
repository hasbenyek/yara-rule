rule ELF_FileInspector_Tool {
    meta:
        description = "Mendeteksi tool CLI 'FileInspector' (yomo)"
        author = "Hasbi yang perbaiki"
        date = "2025-12-03"
        filetype = "ELF"

    strings:
        $s1 = "FileInspector Tool" ascii wide
        $s2 = "Enter filename: " ascii wide
        $s3 = "Error opening file." ascii wide

    condition:
        // Header ELF (0x7f 'E' 'L' 'F')
        uint32(0) == 0x464c457f and
        all of them
}