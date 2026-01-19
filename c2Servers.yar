rule ELF_C2_PinImg_Downloader {
    meta:
        description = "Mendeteksi downloader yang mengambil payload/gambar dari i.pinimg.com"
        author = "Hasbi"
        date = "2025-12-03"
        filetype = "ELF"

    strings:
        // Indikator Utama: Domain dan Filename
        $domain = "i.pinimg.com" ascii
        $filename = "downloaded.jpg" ascii
        
        // String HTTP Request & User Agent unik
        // Terlihat dari dump: "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: SimpleClie"
        $http_req = "GET %s HTTP/1.1" ascii
        $ua_client = "User-Agent: SimpleClie" ascii

        // Error Messages yang spesifik
        $err1 = "Host lookup failed" ascii
        $err2 = "Socket creation failed" ascii
        $err3 = "Connection failed" ascii

    condition:
        // Header ELF (0x7f 'E' 'L' 'F')
        uint32(0) == 0x464c457f and
        (
            ($domain and $filename) or 
            ($http_req and $ua_client) or
            (2 of ($err*))
        )
}
