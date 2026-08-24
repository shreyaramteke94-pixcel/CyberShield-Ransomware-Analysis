import { SampleAnalysis, ThreatFeedItem, AdminStats, UserProfile } from '../types';

export const INITIAL_USERS: UserProfile[] = [
  {
    id: 'usr-01',
    name: 'Security Administrator',
    email: 'admin@cybershield.sec',
    role: 'Security Admin',
    avatar: '',
    badge: 'ADMIN',
    lastLogin: 'Just now',
    analysesCount: 1428
  }
];

export const INITIAL_ADMIN_STATS: AdminStats = {
  totalUsers: 48,
  activeUsers: 37,
  totalAnalyses: 1428,
  successfulAnalyses: 1419,
  failedAnalyses: 9,
  sandboxNodesOnline: 8,
  avgAnalysisTime: '4.2s',
  storageUsed: '64.8 GB / 500 GB'
};

export const INITIAL_SAMPLES: SampleAnalysis[] = [
  {
    id: 'SMP-LB3-9901',
    fileName: 'LB3_Black_payload_x64.exe',
    fileSize: '412.8 KB',
    fileType: 'PE32+ executable (GUI) x86-64',
    uploadedAt: '2026-08-20 21:14:02',
    analyzedAt: '2026-08-20 21:14:06',
    md5: '7d8b92d6e3c114f09d842a19e88cb921',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    sha1: '356a192b7913b04c54574d18c28d46e6395428ab',
    ssdeep: '6144:mZ+jM5/9Xv+0qB1P9zZk78R1kL+93g0071n8Z62:m4jM9Xv0qB1Pk8R1kL+93g071n8Z',
    entropy: 7.94,
    verdict: 'MALICIOUS',
    threatLevel: 'CRITICAL',
    confidenceScore: 99.4,
    ransomwareFamily: 'LockBit 3.0 (Black)',
    decryptionStatus: 'DECRYPTABLE',
    decryptionMethod: 'Leaked LockBit 3.0 Builder Master Key Derivation & PRNG State Reconstruction',
    decryptionKeyCandidate: '0x8F92_A140_99CE_10AB_4420_88FA_1120_CDE5',
    decryptionSuccessRate: 98.2,
    sampleNote: 'High velocity multi-threaded file encryption observed. Targets local drives and network shares.',
    threatSummary: 'The sample exhibits critical LockBit 3.0 ransomware behavior including privilege escalation, shadow copy destruction via vssadmin, execution of high-speed AES-256 / ChaCha20 encryption with custom extension append (.HLJkNskO6), and dropping of ransom notes.',
    tags: ['LockBit', 'Ransomware-as-a-Service', 'High-Entropy', 'VSS-Wiper', 'Decryption-Available'],
    staticAnalysis: {
      isPacked: true,
      packerName: 'Custom LockBit Crypter / Themida stub',
      compiler: 'Microsoft Visual C++ v14.28 (x64)',
      subsystem: 'Windows GUI (Subsystem 2)',
      architecture: 'AMD64 / 64-bit',
      imphash: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
      sections: [
        { name: '.text', virtualSize: '0x00042000', rawSize: '270.3 KB', entropy: 7.96, characteristics: 'CODE, EXECUTE, READ', status: 'SUSPICIOUS' },
        { name: '.rdata', virtualSize: '0x00016000', rawSize: '88.0 KB', entropy: 6.42, characteristics: 'INITIALIZED_DATA, READ', status: 'NORMAL' },
        { name: '.data', virtualSize: '0x0000A000', rawSize: '32.5 KB', entropy: 5.12, characteristics: 'INITIALIZED_DATA, READ_WRITE', status: 'NORMAL' },
        { name: '.pdata', virtualSize: '0x00004000', rawSize: '16.0 KB', entropy: 4.81, characteristics: 'READ', status: 'NORMAL' },
        { name: '.reloc', virtualSize: '0x00001800', rawSize: '6.0 KB', entropy: 7.15, characteristics: 'INITIALIZED_DATA, DISCARDABLE', status: 'ANOMALOUS' }
      ],
      suspiciousStrings: [
        'vssadmin.exe Delete Shadows /all /quiet',
        'wbadmin.exe DELETE SYSTEMSTATEBACKUP -keepVersions:0',
        'bcdedit /set {default} recoveryenabled No',
        'bcdedit /set {default} bootstatuspolicy ignoreallfailures',
        'README_HLJkNskO6.txt',
        'CryptAcquireContextW',
        'CryptGenRandom',
        'WNetOpenEnumW',
        'WNetEnumResourceW',
        'http://lockbitapt...onion'
      ],
      importedDlls: [
        { dll: 'advapi32.dll', functions: ['CryptAcquireContextW', 'CryptGenRandom', 'OpenProcessToken', 'AdjustTokenPrivileges'] },
        { dll: 'kernel32.dll', functions: ['CreateThreadPoolWork', 'VirtualAlloc', 'GetLogicalDrives', 'FindFirstFileW'] },
        { dll: 'mpr.dll', functions: ['WNetOpenEnumW', 'WNetEnumResourceW', 'WNetCloseEnum'] },
        { dll: 'ntdll.dll', functions: ['NtSetInformationProcess', 'RtlAdjustPrivilege'] }
      ],
      exports: ['DllRegisterServer', 'StartPayload'],
      antiDebugDetected: true,
      antiVMDetection: true
    },
    dynamicAnalysis: {
      behaviorScore: 98,
      executionTime: '3.8s',
      sandboxOS: 'Windows 11 Enterprise x64 (Sandbox Isolated)',
      fileModifications: [
        'Modified 4,192 files under C:\\Users\\Administrator\\Documents',
        'Modified 2,340 files under C:\\DataShare\\Financials',
        'Appended extension ".HLJkNskO6" to encrypted files',
        'Dropped "README_HLJkNskO6.txt" in all processed directories',
        'Deleted 12 Volume Shadow Copies'
      ],
      registryKeys: [
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\LockBit3 = "C:\\Windows\\Temp\\LB3.exe"',
        'HKCU\\Control Panel\\Desktop\\Wallpaper = "C:\\Windows\\Temp\\lockbit_wall.bmp"',
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS -> Start: 4 (Disabled)'
      ],
      processTree: [
        { pid: 4128, name: 'LB3_Black_payload_x64.exe', action: 'Process Spawning & Token Impersonation', status: 'MALICIOUS', timestamp: '00:00.120' },
        { pid: 4892, name: 'cmd.exe', action: 'Spawned vssadmin / quiet shadow wipe', status: 'MALICIOUS', timestamp: '00:00.410' },
        { pid: 5120, name: 'vssadmin.exe', action: 'Delete Shadows /All /Quiet', status: 'MALICIOUS', timestamp: '00:00.580' },
        { pid: 5312, name: 'bcdedit.exe', action: 'Disable recovery and boot warnings', status: 'MALICIOUS', timestamp: '00:00.820' },
        { pid: 4128, name: 'LB3_Black_payload_x64.exe', action: 'Cryptographic worker threads initialized (16 threads)', status: 'MALICIOUS', timestamp: '00:01.100' }
      ],
      networkBeacons: [
        { ip: '185.220.101.5', domain: 'lockbitc2-relay.onion.to', port: 443, protocol: 'HTTPS / TLS', country: 'NL', action: 'Exfiltration & Key Sync' },
        { ip: '194.26.29.112', domain: 'api-tor-gateway.cc', port: 8080, protocol: 'HTTP', country: 'RO', action: 'Command & Control Beacon' }
      ],
      mutexes: ['Global\\{79A02B19-E912-4BD1-92A3-1120AB89210F}', 'LockBit_3.0_Mutex_Run_1'],
      ransomNoteFound: true,
      ransomNotePath: 'C:\\Users\\Administrator\\Desktop\\README_HLJkNskO6.txt',
      ransomNoteContent: '>>> LockBit 3.0 (Black) Ransomware <<<\nYour data is stolen and encrypted. If you do not pay the ransom in Bitcoin or Monero, your sensitive files will be published on our leak site.\n\nDecryption ID: HLJkNskO6-9812-4019-ABCD\nVisit our Tor portal for instant decryption verification.',
      shadowCopiesDeleted: true,
      bootConfigAltered: true
    },
    cryptoAnalysis: {
      encryptionAlgorithm: 'AES-256-CBC + Curve25519 (ChaCha20 fallback)',
      keySize: '256-bit symmetric / 256-bit elliptic curve',
      mode: 'CBC with prepended IV block',
      prngFlawDetected: true,
      flawDescription: 'Vulnerability identified in the local builder pseudo-random generator seed initialization routine. Combined with the public leaked builder keys from 2022/2023, session encryption keys can be derived mathematically without payment.',
      weakIvDetected: false,
      keyScheduleFlaw: true,
      memoryLeakKey: true,
      encryptionSpeed: '320 MB/s (Multi-threaded IO ring buffer)',
      targetedExtensions: ['.docx', '.xlsx', '.pdf', '.jpg', '.zip', '.sql', '.mdf', '.vmdk', '.vhdx', '.key', '.pem']
    },
    mlClassification: {
      modelName: 'CyberShield XGBoost + Transformer PE-Classifier v4.8',
      familyProbabilities: [
        { family: 'LockBit 3.0 (Black)', probability: 96.8 },
        { family: 'BlackMatter', probability: 2.1 },
        { family: 'DarkSide', probability: 0.7 },
        { family: 'Conti', probability: 0.4 }
      ],
      topFeatures: [
        { feature: 'Entropy of .text section > 7.92', weight: 0.38, influence: 'Malicious', description: 'Packed executable code standard in ransomware payloads' },
        { feature: 'Command line execution of vssadmin shadow wipe', weight: 0.29, influence: 'Malicious', description: 'High confidence indicator of anti-recovery mechanism' },
        { feature: 'Mass concurrent WriteFile handles to user dirs', weight: 0.21, influence: 'Malicious', description: 'Rapid encryption loop indicator' },
        { feature: 'WNetOpenEnum network share enumeration', weight: 0.12, influence: 'Malicious', description: 'Lateral network spread prep' }
      ],
      anomalyScore: 0.99
    },
    mitreTactics: [
      { id: 'T1486', name: 'Data Encrypted for Impact', phase: 'Impact', technique: 'AES-256 Mass Encryption', description: 'Encrypts user files with ransomware extension to render system unusable', detected: true },
      { id: 'T1490', name: 'Inhibit System Recovery', phase: 'Impact', technique: 'Delete Volume Shadow Copies', description: 'Executes vssadmin.exe delete shadows /all /quiet to block restoration', detected: true },
      { id: 'T1082', name: 'System Information Discovery', phase: 'Discovery', technique: 'Disk & Drive Enumeration', description: 'Enumerates logical drives A: through Z: including mounted SMB shares', detected: true },
      { id: 'T1562.001', name: 'Impair Defenses', phase: 'Defense Evasion', technique: 'Disable Windows Defender & VSS', description: 'Terminates security services and alters recovery registry entries', detected: true },
      { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', phase: 'Command and Control', technique: 'Tor .onion C2 Beacons', description: 'Communicates with threat actor servers over hidden Tor proxy gateways', detected: true }
    ],
    iocs: {
      hashes: [
        'MD5: 7d8b92d6e3c114f09d842a19e88cb921',
        'SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        'SHA1: 356a192b7913b04c54574d18c28d46e6395428ab'
      ],
      ips: ['185.220.101.5:443', '194.26.29.112:8080'],
      domains: ['lockbitapt...onion', 'api-tor-gateway.cc'],
      registry: [
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\LockBit3',
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS'
      ],
      yaraRuleName: 'CyberShield_Ransomware_LockBit3_Signature',
      yaraRuleText: `rule CyberShield_Ransomware_LockBit3 {
    meta:
        description = "Detects LockBit 3.0 Black Ransomware binary with high precision"
        author = "CyberShield Threat Research Team"
        date = "2026-08-20"
        hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    strings:
        $s1 = "vssadmin.exe Delete Shadows /all /quiet" wide ascii
        $s2 = "bcdedit /set {default} recoveryenabled No" wide ascii
        $s3 = "README_" wide ascii
        $hex_crypter = { 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 30 }
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and (2 of ($s*) and $hex_crypter)
}`
    },
    remediation: [
      'Isolate infected endpoint from the local area network immediately to prevent lateral SMB spread.',
      'Deploy the CyberShield LockBit 3.0 Decryption Tool utilizing the derived key candidate.',
      'Block outbound traffic to C2 IOC IPs: 185.220.101.5 and 194.26.29.112 on enterprise firewall.',
      'Check Domain Controller for token compromise and execute enterprise-wide password reset.',
      'Re-enable Volume Shadow Copy service (VSS) and restore registry policies via GPO.'
    ]
  },
  {
    id: 'SMP-WCR-2017',
    fileName: 'mssecsvc2.0_WannaCry.exe',
    fileSize: '3.49 MB',
    fileType: 'PE32 executable (GUI) Intel 80386',
    uploadedAt: '2026-08-20 20:45:18',
    analyzedAt: '2026-08-20 20:45:23',
    md5: '84c82835a5d21bbcf75a61706d8ab549',
    sha256: 'ed01ebf830043a1b4472515573329ab4f00e0e0189c409d7b9f0414d0ed6ce99',
    sha1: '5ff465afb3054d1b960b7b3519c62b5e16dafc18',
    ssdeep: '98304:4f00e0e0189c409d7b9f0414d0ed6ce99:4FE0E89CD7B9F4D0E',
    entropy: 7.98,
    verdict: 'MALICIOUS',
    threatLevel: 'CRITICAL',
    confidenceScore: 99.8,
    ransomwareFamily: 'WannaCry v2.0 (WanaCrypt0r)',
    decryptionStatus: 'DECRYPTABLE',
    decryptionMethod: 'WanaKiwi Prime Factorization Memory Dump Technique (CVE-2017-0144 / MS17-010)',
    decryptionKeyCandidate: '0xWANA_PRIME_P_Q_RSA2048_REC_F92A',
    decryptionSuccessRate: 99.1,
    sampleNote: 'Contains SMBv1 EternalBlue self-propagating worm component and Killswitch URL check.',
    threatSummary: 'WannaCry ransomware utilizes EternalBlue exploit to spread autonomously across internal subnets via TCP port 445. Encrypts files with RSA-2048 + AES-128 and appends .WNCRY extension.',
    tags: ['WannaCry', 'EternalBlue', 'SMB-Worm', 'KillSwitch', 'Decryption-Available'],
    staticAnalysis: {
      isPacked: true,
      packerName: 'Custom Password-Protected Zip / Resource Drop',
      compiler: 'Microsoft Visual C++ 6.0 / MFC',
      subsystem: 'Windows GUI',
      architecture: 'i386 / 32-bit',
      imphash: 'd3b07384d113edec49eaa6238ad5ff00',
      sections: [
        { name: '.text', virtualSize: '0x00030000', rawSize: '192 KB', entropy: 7.99, characteristics: 'CODE, EXECUTE, READ', status: 'SUSPICIOUS' },
        { name: '.rdata', virtualSize: '0x00010000', rawSize: '64 KB', entropy: 6.81, characteristics: 'INITIALIZED_DATA, READ', status: 'NORMAL' },
        { name: '.data', virtualSize: '0x00008000', rawSize: '32 KB', entropy: 5.43, characteristics: 'READ_WRITE', status: 'NORMAL' },
        { name: '.rsrc', virtualSize: '0x00320000', rawSize: '3.2 MB', entropy: 7.99, characteristics: 'CONTAINS_EMBEDDED_ZIP', status: 'SUSPICIOUS' }
      ],
      suspiciousStrings: [
        'http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com',
        'tasksche.exe',
        '@WanaDecryptor@.exe',
        'WanaCrypt0r',
        'c.wnry',
        't.wnry',
        'taskhsvc.exe',
        'cmd.exe /c "vssadmin.exe Delete Shadows /All /Quiet"'
      ],
      importedDlls: [
        { dll: 'advapi32.dll', functions: ['CreateServiceA', 'StartServiceA', 'OpenSCManagerA', 'CryptGenKey'] },
        { dll: 'ws2_32.dll', functions: ['WSAStartup', 'connect', 'send', 'recv', 'bind'] },
        { dll: 'wininet.dll', functions: ['InternetOpenA', 'InternetOpenUrlA'] }
      ],
      exports: [],
      antiDebugDetected: false,
      antiVMDetection: false
    },
    dynamicAnalysis: {
      behaviorScore: 99,
      executionTime: '4.1s',
      sandboxOS: 'Windows 7 SP1 x86 (Sandbox Isolated)',
      fileModifications: [
        'Modified 3,810 files with extension .WNCRY',
        'Extracted embedded password-protected payload "c.wnry" using hardcoded key "WNcry@2ol7"',
        'Created C:\\ProgramData\\WanaCrypt0r\\taskse.exe'
      ],
      registryKeys: [
        'HKLM\\SOFTWARE\\WanaCrypt0r\\wd = "C:\\ProgramData\\WanaCrypt0r"',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WanaDecryptor'
      ],
      processTree: [
        { pid: 1820, name: 'mssecsvc2.0_WannaCry.exe', action: 'InternetOpenUrlA (Killswitch Check)', status: 'WARNING', timestamp: '00:00.080' },
        { pid: 1820, name: 'mssecsvc2.0_WannaCry.exe', action: 'SMB Scanner Thread (Port 445 Sweep)', status: 'MALICIOUS', timestamp: '00:00.220' },
        { pid: 2410, name: 'tasksche.exe', action: 'Payload Detonation & Encryption Loop', status: 'MALICIOUS', timestamp: '00:00.650' },
        { pid: 3100, name: '@WanaDecryptor@.exe', action: 'Ransomware GUI Display Window Spawned', status: 'MALICIOUS', timestamp: '00:01.400' }
      ],
      networkBeacons: [
        { ip: '198.51.100.24', domain: 'www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com', port: 80, protocol: 'HTTP', country: 'US', action: 'Killswitch Probe (Simulated Sinkhole)' }
      ],
      mutexes: ['Global\\MsWinZonesCacheCounterMutexA'],
      ransomNoteFound: true,
      ransomNotePath: 'C:\\Users\\Desktop\\@Please_Read_Me@.txt',
      ransomNoteContent: 'Ooops, your files have been encrypted!\n\nWhat Happened to My Computer?\nYour important files are encrypted. Many of your documents, photos, videos, databases and other files are no longer accessible because they have been encrypted. Maybe you are busy looking for a way to recover your files, but do not waste your time.',
      shadowCopiesDeleted: true,
      bootConfigAltered: true
    },
    cryptoAnalysis: {
      encryptionAlgorithm: 'AES-128-CBC + RSA-2048 Hybrid',
      keySize: '128-bit symmetric / 2048-bit asymmetric',
      mode: 'CBC',
      prngFlawDetected: true,
      flawDescription: 'CryptAcquireContext does not clear the RSA prime factors (p and q) from Windows Cryptographic Service Provider (CSP) memory. The primes can be retrieved directly via memory carving if the system has not rebooted.',
      weakIvDetected: false,
      keyScheduleFlaw: false,
      memoryLeakKey: true,
      encryptionSpeed: '180 MB/s',
      targetedExtensions: ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.jpg', '.zip', '.rar', '.sql']
    },
    mlClassification: {
      modelName: 'CyberShield XGBoost + Transformer PE-Classifier v4.8',
      familyProbabilities: [
        { family: 'WannaCry v2.0', probability: 99.8 },
        { family: 'NotPetya', probability: 0.1 },
        { family: 'BadRabbit', probability: 0.1 }
      ],
      topFeatures: [
        { feature: 'Embedded encrypted resource matching WNcry header', weight: 0.44, influence: 'Malicious', description: 'Exact cryptographic header match' },
        { feature: 'TCP port 445 raw SMB socket creation', weight: 0.32, influence: 'Malicious', description: 'EternalBlue exploitation artifact' },
        { feature: 'Killswitch domain lookup pattern', weight: 0.18, influence: 'Malicious', description: 'Hardcoded domain ping before execution' }
      ],
      anomalyScore: 1.0
    },
    mitreTactics: [
      { id: 'T1210', name: 'Exploitation of Remote Services', phase: 'Lateral Movement', technique: 'MS17-010 EternalBlue', description: 'Exploits SMBv1 buffer overflow to spread between machines', detected: true },
      { id: 'T1486', name: 'Data Encrypted for Impact', phase: 'Impact', technique: 'RSA-2048 + AES-128 Hybrid Encryption', description: 'Locks user files with .WNCRY extension', detected: true },
      { id: 'T1490', name: 'Inhibit System Recovery', phase: 'Impact', technique: 'Wipe shadow copies and wbadmin', description: 'Deletes backups', detected: true }
    ],
    iocs: {
      hashes: [
        'MD5: 84c82835a5d21bbcf75a61706d8ab549',
        'SHA256: ed01ebf830043a1b4472515573329ab4f00e0e0189c409d7b9f0414d0ed6ce99'
      ],
      ips: ['198.51.100.24:80'],
      domains: ['www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com'],
      registry: ['HKLM\\SOFTWARE\\WanaCrypt0r'],
      yaraRuleName: 'CyberShield_WannaCry_Rule',
      yaraRuleText: `rule CyberShield_WannaCry_Core {
    meta:
        author = "CyberShield SOC"
        description = "Detects WannaCry ransomware and mssecsvc dropper"
    strings:
        $wncry = "WANACRY!"
        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea"
    condition:
        uint16(0) == 0x5A4D and ($wncry or $killswitch)
}`
    },
    remediation: [
      'Deploy MS17-010 security update immediately across all domain assets.',
      'Disable SMBv1 protocol in Windows Features and block TCP 445 on perimeter firewalls.',
      'Run CyberShield WanaKiwi memory decryptor before restarting affected machines to recover keys.'
    ]
  },
  {
    id: 'SMP-BLK-4402',
    fileName: 'BlackCat_ALPHV_locker.bin',
    fileSize: '1.82 MB',
    fileType: 'PE32+ executable (Rust compiled payload)',
    uploadedAt: '2026-08-20 19:30:11',
    analyzedAt: '2026-08-20 19:30:15',
    md5: 'a8b71239c0182419f091823719283019',
    sha256: '44a8b71239c0182419f091823719283019882731982731982371982371982371',
    sha1: '1928301982371982371982371982371982371982',
    ssdeep: '24576:mALPHV1928301982371982371982371982371:mALPHV19',
    entropy: 7.91,
    verdict: 'MALICIOUS',
    threatLevel: 'CRITICAL',
    confidenceScore: 98.6,
    ransomwareFamily: 'BlackCat (ALPHV)',
    decryptionStatus: 'UNSUPPORTED',
    decryptionMethod: 'Proprietary ChaCha20-Poly1305 + ECC Curve25519 (Requires Private Master Key)',
    decryptionSuccessRate: 0,
    sampleNote: 'Sophisticated Rust-based ransomware with custom command-line access tokens.',
    threatSummary: 'BlackCat (ALPHV) utilizes Rust memory safety and advanced async I/O to perform ultra-fast intermittent file encryption. Requires strict threat actor authentication token to execute.',
    tags: ['BlackCat', 'ALPHV', 'Rust-Malware', 'ChaCha20', 'Zero-Day-Defense'],
    staticAnalysis: {
      isPacked: false,
      compiler: 'Rustc 1.74.0 (LLVM backend)',
      subsystem: 'Windows Console',
      architecture: 'x86_64',
      imphash: '33a92183b9c02e19a827301928301928',
      sections: [
        { name: '.text', virtualSize: '0x00120000', rawSize: '1.1 MB', entropy: 7.88, characteristics: 'CODE, EXECUTE, READ', status: 'SUSPICIOUS' },
        { name: '.rdata', virtualSize: '0x00080000', rawSize: '512 KB', entropy: 6.95, characteristics: 'INITIALIZED_DATA, READ', status: 'NORMAL' },
        { name: '.data', virtualSize: '0x00020000', rawSize: '128 KB', entropy: 5.20, characteristics: 'READ_WRITE', status: 'NORMAL' }
      ],
      suspiciousStrings: [
        '--access-token',
        '--bypass-uac',
        '--drop-drag-and-drop-target',
        'iisreset.exe /stop',
        'net stop "MSSQLSERVER" /y',
        'RECOVER-encrypted-files.txt'
      ],
      importedDlls: [
        { dll: 'ntdll.dll', functions: ['NtCreateFile', 'NtReadFile', 'NtWriteFile'] },
        { dll: 'ws2_32.dll', functions: ['connect', 'send', 'recv'] }
      ],
      exports: [],
      antiDebugDetected: true,
      antiVMDetection: true
    },
    dynamicAnalysis: {
      behaviorScore: 96,
      executionTime: '4.0s',
      sandboxOS: 'Windows 11 x64 Enterprise',
      fileModifications: [
        'Killed database and hypervisor services (SQL, Exchange, Hyper-V)',
        'Encrypted system shares and storage volumes'
      ],
      registryKeys: ['HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog -> Disabled'],
      processTree: [
        { pid: 6100, name: 'BlackCat_ALPHV_locker.bin', action: 'Access token validation routine', status: 'MALICIOUS', timestamp: '00:00.100' },
        { pid: 6100, name: 'BlackCat_ALPHV_locker.bin', action: 'Async Tokio Runtime multi-thread lock initiated', status: 'MALICIOUS', timestamp: '00:00.400' }
      ],
      networkBeacons: [
        { ip: '104.244.72.115', domain: 'alphv-leak-node.top', port: 443, protocol: 'TLS 1.3', country: 'CH', action: 'Telemetry Upload' }
      ],
      mutexes: ['ALPHV_Rust_Global_Instance_Lock'],
      ransomNoteFound: true,
      ransomNotePath: 'C:\\Users\\Public\\RECOVER-files.txt',
      ransomNoteContent: '>>> ALPHV BlackCat Ransomware <<<\nAll your data is encrypted with military-grade ChaCha20 encryption. Key recovery without our private key is mathematically impossible.',
      shadowCopiesDeleted: true,
      bootConfigAltered: true
    },
    cryptoAnalysis: {
      encryptionAlgorithm: 'ChaCha20-Poly1305 + ECC Curve25519',
      keySize: '256-bit symmetric / 256-bit public key',
      mode: 'Authenticated Encryption with Associated Data (AEAD)',
      prngFlawDetected: false,
      flawDescription: 'Cryptographically sound implementation utilizing standard Rust `ring` / `sodiumoxide` cryptographic primitives. No PRNG seeding defect or key schedule flaw detected.',
      weakIvDetected: false,
      keyScheduleFlaw: false,
      memoryLeakKey: false,
      encryptionSpeed: '650 MB/s (High-performance intermittent hashing)',
      targetedExtensions: ['.mdf', '.ldf', '.ndf', '.bak', '.vmdk', '.vhdx', '.db', '.sqlite', '.doc', '.pdf']
    },
    mlClassification: {
      modelName: 'CyberShield XGBoost + Transformer PE-Classifier v4.8',
      familyProbabilities: [
        { family: 'BlackCat (ALPHV)', probability: 98.6 },
        { family: 'LockBit 3.0', probability: 1.0 },
        { family: 'Hive', probability: 0.4 }
      ],
      topFeatures: [
        { feature: 'Rust Tokio async runtime embedded with cryptographic primitives', weight: 0.42, influence: 'Malicious', description: 'Rust ransomware signature' },
        { feature: 'Service termination of MS SQL, Exchange, and Backup daemons', weight: 0.35, influence: 'Malicious', description: 'Pre-encryption service wiper' }
      ],
      anomalyScore: 0.98
    },
    mitreTactics: [
      { id: 'T1486', name: 'Data Encrypted for Impact', phase: 'Impact', technique: 'ChaCha20 Intermittent Encryption', description: 'Intermittent encryption avoids OS detection', detected: true },
      { id: 'T1489', name: 'Service Stop', phase: 'Impact', technique: 'Terminate MSSQL and Backup Services', description: 'Forces open file handles to unlock database files', detected: true }
    ],
    iocs: {
      hashes: ['SHA256: 44a8b71239c0182419f091823719283019882731982731982371982371982371'],
      ips: ['104.244.72.115:443'],
      domains: ['alphv-leak-node.top'],
      registry: ['HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog'],
      yaraRuleName: 'CyberShield_BlackCat_Rust',
      yaraRuleText: `rule CyberShield_BlackCat_ALPHV {
    meta:
        description = "Detects BlackCat ALPHV Rust Ransomware"
    strings:
        $token = "--access-token"
        $rust = "library/std/src/sys/windows"
    condition:
        uint16(0) == 0x5A4D and all of them
}`
    },
    remediation: [
      'Ransomware uses secure asymmetric cryptography. Rely on offline immutable cloud backups.',
      'Revoke compromised Active Directory service accounts and enforce MFA on all VPN gateways.',
      'Engage CyberShield incident response forensics team for deep timeline reconstruction.'
    ]
  },
  {
    id: 'SMP-SAF-1008',
    fileName: 'Quarterly_Financial_Audit_2026.xlsx',
    fileSize: '84.2 KB',
    fileType: 'Microsoft Excel OpenXML Spreadsheet',
    uploadedAt: '2026-08-20 18:12:44',
    analyzedAt: '2026-08-20 18:12:46',
    md5: 'e1d88927182903102938102938102938',
    sha256: 'c827319827319823719823719823719827319823719823719823719827319823',
    sha1: '9827319827319823719823719823719827319823',
    ssdeep: '1536:safe_office_document_spreadsheet:safe_doc',
    entropy: 4.82,
    verdict: 'SAFE',
    threatLevel: 'SAFE',
    confidenceScore: 99.8,
    ransomwareFamily: 'Safe Document / Clean File',
    decryptionStatus: 'NOT_APPLICABLE',
    decryptionMethod: 'N/A - File is not encrypted with ransomware',
    decryptionSuccessRate: 100,
    sampleNote: 'Valid Microsoft OpenXML Spreadsheet with standard XML structure. No VBA macros or embedded OLE exploits.',
    threatSummary: 'The uploaded file has been verified as clean and benign. Static dissection found no malicious macros, DDE links, or anomalous high-entropy payloads.',
    tags: ['Safe', 'Clean', 'Verified-Document', 'No-Macros', 'Non-Malicious'],
    staticAnalysis: {
      isPacked: false,
      compiler: 'Microsoft Office XML Engine',
      subsystem: 'Document Container (ZIP format)',
      architecture: 'Data / Non-executable',
      imphash: '00000000000000000000000000000000',
      sections: [
        { name: '[Content_Types].xml', virtualSize: '2.1 KB', rawSize: '2.1 KB', entropy: 4.65, characteristics: 'XML_DATA', status: 'NORMAL' },
        { name: 'xl/workbook.xml', virtualSize: '14.2 KB', rawSize: '14.2 KB', entropy: 4.89, characteristics: 'XML_SHEET', status: 'NORMAL' },
        { name: 'xl/worksheets/sheet1.xml', virtualSize: '52.0 KB', rawSize: '52.0 KB', entropy: 5.01, characteristics: 'XML_TABLE', status: 'NORMAL' }
      ],
      suspiciousStrings: [],
      importedDlls: [],
      exports: [],
      antiDebugDetected: false,
      antiVMDetection: false
    },
    dynamicAnalysis: {
      behaviorScore: 0,
      executionTime: '2.1s',
      sandboxOS: 'Windows 11 Pro with Microsoft Excel 365 Protected View',
      fileModifications: ['None - File opened in sandbox Excel safely with zero writes to disk.'],
      registryKeys: [],
      processTree: [
        { pid: 8900, name: 'EXCEL.EXE', action: 'Document loaded into memory (Protected Sandbox View)', status: 'NEUTRAL', timestamp: '00:00.300' }
      ],
      networkBeacons: [],
      mutexes: [],
      ransomNoteFound: false,
      shadowCopiesDeleted: false,
      bootConfigAltered: false
    },
    cryptoAnalysis: {
      encryptionAlgorithm: 'None (Unencrypted OpenXML format)',
      keySize: '0-bit',
      mode: 'N/A',
      prngFlawDetected: false,
      flawDescription: 'Clean file. No ransomware encryption routines present.',
      weakIvDetected: false,
      keyScheduleFlaw: false,
      memoryLeakKey: false,
      encryptionSpeed: 'N/A',
      targetedExtensions: []
    },
    mlClassification: {
      modelName: 'CyberShield XGBoost + Transformer PE-Classifier v4.8',
      familyProbabilities: [
        { family: 'Clean / Safe Document', probability: 99.8 },
        { family: 'Malicious Macro Dropper', probability: 0.2 }
      ],
      topFeatures: [
        { feature: 'Entropy score is within normal range (4.82)', weight: 0.50, influence: 'Safe', description: 'Normal document compression entropy' },
        { feature: 'Zero VBA macro streams found in ZIP archive', weight: 0.35, influence: 'Safe', description: 'No code execution vector present' }
      ],
      anomalyScore: 0.01
    },
    mitreTactics: [],
    iocs: {
      hashes: ['SHA256: c827319827319823719823719823719827319823719823719823719827319823'],
      ips: [],
      domains: [],
      registry: [],
      yaraRuleName: 'CyberShield_Clean_Document_Rule',
      yaraRuleText: `// No malicious indicators detected`
    },
    remediation: [
      'File is verified safe for opening and distribution within the corporate network.'
    ]
  }
];

export const PRESET_MALWARE_SAMPLES = [
  {
    name: 'LockBit3.0_payload_x64.exe',
    size: '412.8 KB',
    type: 'PE32+ Executable',
    description: 'High velocity RaaS ransomware with leaked key generator flaw',
    sampleId: 'SMP-LB3-9901'
  },
  {
    name: 'mssecsvc2.0_WannaCry.exe',
    size: '3.49 MB',
    type: 'PE32 Executable / SMB Worm',
    description: 'EternalBlue SMB exploit spreader with WanaKiwi memory prime decryption',
    sampleId: 'SMP-WCR-2017'
  },
  {
    name: 'BlackCat_ALPHV_locker.bin',
    size: '1.82 MB',
    type: 'Rust 64-bit Binary',
    description: 'Advanced multi-threaded intermittent crypto ransomware',
    sampleId: 'SMP-BLK-4402'
  },
  {
    name: 'Quarterly_Financial_Audit_2026.xlsx',
    size: '84.2 KB',
    type: 'Excel OpenXML Spreadsheet',
    description: 'Legitimate business document without macros (Clean baseline test)',
    sampleId: 'SMP-SAF-1008'
  }
];

export const RECENT_THREAT_FEEDS: ThreatFeedItem[] = [
  {
    id: 'TF-2026-081',
    title: 'LockBit 3.0 Group Leverages Microsoft Exchange Zero-Day for Domain Lateral Movement',
    variant: 'LockBit 3.0 (Black)',
    severity: 'CRITICAL',
    date: '2026-08-20',
    cve: 'CVE-2026-38291',
    source: 'CyberShield Global Threat Intel',
    targetIndustries: ['Healthcare', 'Manufacturing', 'Financial Services'],
    summary: 'New campaign observed utilizing automated PowerShell living-off-the-land scripts to drop encrypted LockBit stubs within 15 minutes of initial foothold.',
    indicatorCount: 42
  },
  {
    id: 'TF-2026-080',
    title: 'Akira Ransomware Targets Linux ESXi Virtual Hypervisors via Weak SSH Ciphers',
    variant: 'Akira Linux Locker',
    severity: 'HIGH',
    date: '2026-08-19',
    cve: 'CVE-2025-41902',
    source: 'CISA & CyberShield Alert',
    targetIndustries: ['Cloud Infrastructure', 'Education', 'IT Services'],
    summary: 'Custom ELF 64-bit payload designed specifically to traverse VMware VMFS datastores, power off virtual machines via esxcli, and encrypt .vmdk images.',
    indicatorCount: 28
  },
  {
    id: 'TF-2026-079',
    title: 'Universal Decryptor Released for Phobos Ransomware Variants Generated Before 2026',
    variant: 'Phobos / 8Base',
    severity: 'MEDIUM',
    date: '2026-08-17',
    source: 'No More Ransom Alliance & CyberShield',
    targetIndustries: ['Small & Medium Enterprises', 'Retail'],
    summary: 'Cryptographic flaw discovered in the seed calculation of the offline private key generation algorithm allows free file recovery for victimized organizations.',
    indicatorCount: 15
  },
  {
    id: 'TF-2026-078',
    title: 'Rhysida Ransomware Targets Public Sector with Dual-Encryption Mechanism',
    variant: 'Rhysida v2',
    severity: 'HIGH',
    date: '2026-08-15',
    cve: 'CVE-2026-21804',
    source: 'CyberShield Threat Intelligence',
    targetIndustries: ['Government', 'Public Utilities', 'Defense'],
    summary: 'Utilizes LibTomCrypt library to perform ChaCha20 encryption on user files while wiping volume shadow copies via PowerShell WMI calls.',
    indicatorCount: 34
  }
];

export const MOCK_CHART_DATA = {
  familyDistribution: [
    { name: 'LockBit 3.0', count: 482, color: '#ef4444' },
    { name: 'BlackCat (ALPHV)', count: 295, color: '#f97316' },
    { name: 'WannaCry Variants', count: 184, color: '#eab308' },
    { name: 'Conti / Babuk', count: 142, color: '#06b6d4' },
    { name: 'Akira / Phobos', count: 126, color: '#8b5cf6' },
    { name: 'Safe / Benign', count: 190, color: '#22c55e' }
  ],
  monthlyTrend: [
    { month: 'Mar', samples: 160, detected: 135, decrypted: 42 },
    { month: 'Apr', samples: 210, detected: 180, decrypted: 64 },
    { month: 'May', samples: 245, detected: 210, decrypted: 88 },
    { month: 'Jun', samples: 290, detected: 250, decrypted: 110 },
    { month: 'Jul', samples: 340, detected: 300, decrypted: 138 },
    { month: 'Aug', samples: 184, detected: 152, decrypted: 76 }
  ],
  mitreDistribution: [
    { tactic: 'T1486 Data Encrypted', detections: 894 },
    { tactic: 'T1490 Inhibit Recovery', detections: 780 },
    { tactic: 'T1082 System Info', detections: 640 },
    { tactic: 'T1562 Impair Defenses', detections: 512 },
    { tactic: 'T1071 Web Protocols C2', detections: 488 },
    { tactic: 'T1210 Remote Services', detections: 310 }
  ],
  cryptoAlgos: [
    { algo: 'AES-256-CBC', percentage: 46 },
    { algo: 'ChaCha20-Poly1305', percentage: 28 },
    { algo: 'RSA-4096 Hybrid', percentage: 14 },
    { algo: 'Custom XOR / RC4', percentage: 7 },
    { algo: 'Blowfish / Serpent', percentage: 5 }
  ]
};
