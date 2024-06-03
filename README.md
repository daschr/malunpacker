<div align="center">
  <h1>malunpacker</h1>
  <em>ICAP service which unpacks password-protected attachments (.iso, .rar, .7z, .zip etc.) of various file types and scans them using YARA. Can be seamlessly integrated into rspamd.</em><br><br>
  <em>Born out of the frustration that Rspamd/ClamAV cannot unpack password-protected mail attachments containing malware.</em>
</div>

[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=fff)](https://hub.docker.com/r/daschr/malunpacker) ![docker build](https://github.com/daschr/malunpacker/actions/workflows/docker-image.yml/badge.svg) 

## Capabilities
- tries to unpack password protected attachments using the mail body as a knowledge base for passwords
- can also use a LLM to extract the password from the mail body
- unpacks
  |mime type|password protection|
  |---|---|
  |application/vnd.rar|yes|
  |application/x-7z-compressed|yes|
  |application/x-bzip|yes|
  |application/x-bzip2|yes|
  |application/x-iso9660-image|n.a.|
  |application/x-rar|yes|
  |application/x-rar-compressed|yes|
  |application/zip|yes|
- scans each dropped sample and attachment using the provided YARA rules; independent of the file type
## Installation (Docker)
1. use the provided [docker-compose.yml](https://github.com/daschr/malunpacker/blob/main/docker-compose.yml) and spawn the container
2. got into the `etc` docker-volume of the container, create a `rules` directory and put your `.yar` rule files into it<br>
   (Note: a good start for rules may be https://yarahq.github.io/)
3. restart the container and check that it's running
4. Rspamd integration
   * go to your Rspamd configuration files and add the following to your `external_services.conf`
     ```
      malunpacker {
        servers = "172.22.1.1:10055";
        # needs to be set explicitly for Rspamd < 1.9.5
        scan_mime_parts = false;
        type = "icap";
        scheme = "respmod";
        x_client_header = true;
        # mime-part regex matching in content-type or filename
        # block all macros
        max_size = 3145728;
        timeout = 60.0;
        retransmits = 1;
        x_client_header = true; # Add X-Client-IP: $IP header
        x_rcpt_header = true; # Add X-Rcpt-To: $SMTP_RCPT header
        x_from_header = true; # Add X-Mail-From: $SMTP_FROM header
      }
     ```
   * adapt your `VIRUS_FOUND` symbol in your `composites.conf` and add the `MALUNPACKER` symbol to it's expression f.e.:
     ```
     VIRUS_FOUND {
       expression = "( CLAM_VIRUS | MALUNPACKER ) & !WHITELIST";
       score = 2000.0;
     }
     ```
5. That's it! You can now test malunpacker by sending some archive containeing malware or some ISO.
## LLM for credential extraction
You may also enable the use of a LLM for credential extraction by specifing the environment variable `USE_ML_FOR_CREDS_EXTRACTION=true` in your docker-compose file.

The service uses [rust-bert](https://github.com/guillaume-be/rust-bert) for the ML part.
