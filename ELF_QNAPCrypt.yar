import "elf"
import "hash"

// Jotform Internship Project - Linux Ransomware Analysis 

rule hash_control {
    meta:
        description = "Malware hash value detected !!"
        author = "emr4h"
        version = "1.0"

    condition:
        // Hash control for zip and file
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        hash.md5(0, filesize) == "6ffabd3e67705be52bff0d21ce13caf0" or
        hash.md5(0, filesize) == "904280c939a940faa56227176caeb48a" or
        hash.sha256(0, filesize) == "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073" or
        hash.sha256(0, filesize) == "77179669e172842cbdf70234369af51d12ba49a35e9c96fbea91b41b552a0298"
}

rule linux_ransom {

    meta:
        description = "Malware activities detected !!"
        author = "emr4h"
        version = "1.0"

    strings:
        $path = "/home/dd/GoglandProjects/src/rct_cryptor_universal/main.go" wide ascii // malicious path
        $path = "/home/dd/GoglandProjects/src/rct_cryptor_universal/checkRunning_linux.go" wide ascii // malicious path
        $url = "https://veqlxhq7ub5qze3qy56zx2cig2e6tzsgxdspkubwbayqije6oatma6id.onion" // malicious url
        $ip = "185.193.126.161:9100" // malicious ip connection
        $go_buildid = "EBOOkgYUDptRFlzzCaj2/PDpK9vOctdTnl0THFDfs/bS3kRuYQmHpfbC3ZYtOF/WB4tWqSOhlv7ra6Ho3pP" fullword


    condition:
        //elf file structure and strings control
        uint32(0) == 0x464C457F and
        (elf.type == elf.ET_EXEC and 
        elf.machine == elf.EM_ARM and 
        elf.segments[2].flags == (elf.PF_R + elf.PF_X) and 
        elf.number_of_sections == 14) and
        ($path or $url or $ip or $go_buildid) 
}



/* 
yara <options> <yara_rule_file.yar> <malware>
-------------------------------------------------------
-f --fast-scan = hızlı tarama
-m -print-meta = meta data'yı yazdırır.
-r -recursive = Alt dizinlerine kadar tarar.
-s -print-string = eşleşen string değerlerini yazdırır.
...
more info --> yara -h
...
-------------------------------------------------------
*/