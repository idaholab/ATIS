#file: open_vocabulary.py
#auth: rafer cooley
#desc: variables for open vocabulary listed in STIX V2.1 since they don't appear to be available from the stix2 python library


malware_type_ov = ['adware', 'backdoor', 'bot', 'bootkit', 'ddos', 'downloader', 'dropper', 'exploit-kit', 'keylogger', 'ransomware', 'remote-access-trojan', 'resource-exploitation', 'rogue-security-software', 'rootkit', 'screen-capture', 'spyware', 'trojan', 'unknown', 'virus', 'webshell', 'wiper', 'worm']

malware_capabilities_ov = ['accesses-remote-machines', 'anti-debugging', 'anti-disassembly', 'anti-emulation', 'anti-memory-forensics', 'anti-sandbox', 'anti-vm', 'captures-input-peripherals', 'captures-output-peripherals', 'captures-system-state-data', 'cleans-traces-of-infection', 'commits-fraud', 'communicates-with-c2', 'compromises-data-availability', 'compromises-data-integrity', 'compromises-system-availability', 'controls-local-machine', 'degrades-security-software', 'degrades-system-updates', 'determines-c2-server', 'emails-spam', 'escalates-privileges', 'evades-av', 'exfiltrates-data', 'fingerprints-host', 'hides-artifacts', 'hides-executing-code', 'infects-files', 'infects-remote-machines', 'installs-other-components', 'persists-after-system-reboot', 'prevents-artifact-access', 'prevents-artifact-deletion', 'probes-network-environment', 'self-modifies', 'steals-authentication-credentials', 'violates-system-operational-integrity'
]

report_type_ov = ['attack-pattern', 'campaign', 'identity', 'indicator', 'intrusion-set', 'malware', 'observed-data', 'threat-actor', 'threat-report', 'tool', 'vulnerability']