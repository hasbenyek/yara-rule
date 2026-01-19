rule ELF_DarkProcess_Loader {
    meta:
        description = "Mendeteksi file binary 'harmless' yang memuat payload DarkProcess v1.3"
        author = "Hasbi yang perbaiki"
        date = "2025-12-03"
        filetype = "ELF"
        
    strings:
        // String ASCII unik yang ditemukan di .rodata
        $s1 = "Initializing DarkProcess v1.3..." ascii wide
        $s2 = "Payload loaded into memory." ascii wide
        $s3 = "Memory allocation failed" ascii wide

        // Pola Hex: Penyusunan string "HIDDEN_PAYLOAD_12345" pada stack (Little Endian)
        // 0x505f4e4544444948 = "HIDDEN_P"
        $hex_hidden_p = { 48 b8 48 49 44 44 45 4e 5f 50 } 
        // 0x315f44414f4c5941 = "AYLOAD_1"
        $hex_ayload_1 = { 48 ba 41 59 4c 4f 41 44 5f 31 }
        
    condition:
        // Header ELF (0x7f 'E' 'L' 'F')
        uint32(0) == 0x464c457f and
        (2 of ($s*) or all of ($hex*))
}