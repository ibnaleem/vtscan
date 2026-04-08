# 🛡️ VTScan — VirusTotal for the Terminal

<p align="center">
    <picture>
        <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/ibnaleem/vtscan/refs/heads/main/assets/vtscan_logo_dark.png">
        <img src="https://raw.githubusercontent.com/ibnaleem/vtscan/refs/heads/main/assets/vtscan_logo.png" alt="vtscan" width="500">
    </picture>
</p>

<p align="center">
  <strong>⚠️ This project is still in beta</strong><br><br>
  <code>go install github.com/ibnaleem/vtscan@latest</code>
</p>

<p align="center">
  <img src="https://github.com/ibnaleem/vtscan/actions/workflows/go.yml/badge.svg?event=push" alt="GitHub Actions Badge">
  <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/ibnaleem/vtscan">
  <img alt="GitHub commit activity" src="https://img.shields.io/github/commit-activity/w/ibnaleem/vtscan">
  <img alt="GitHub contributors" src="https://img.shields.io/github/contributors/ibnaleem/vtscan">
</p>

**`vtscan`** is a command-line tool for scanning files, URLs, and IPs against VirusTotal's malware detection. It makes it easier for developers, sercurity researchers, and pretty much anyone that uses a terminal a lot to quickly get a verdict of a file, IP, URL, and more. It was developed after I grew tired of trying to find a file via the GUI to upload to VirusTotal. Sometimes its on the desktop, often times its in some obscure path that takes us forever to traverse.

## 🚀 Getting Started
After you've ran the install command above, you should obtain an API key from VirusTotal and specify it in your environmental variables as `VT_API_KEY`. Please look up how to setup an environmental variable for your OS.

## 🔍 Searching Files & Hashes
`vtscan` will automatically calculate a SHA256 hash of your file to search VirusTotal's API. You can specify as many files or hashes as you need, and `vtscan` will do the rest for you:
```bash
$ vtscan file malware.exe cryptominer.bat b2660178b77e43b65d9e991332f0c9d59bd555aee9e8879e39a55e7db8d472d0
```
Here, `vtscan` will search for the following:
1. `malware.exe` via SHA256 hash
2. `cryptominer.bat` via SHA256 hash
3. `b266017...` via hash

The hash specified in the argument does not have to be SHA256: it could be either SHA1 or MD5 as well.

## 🔍 Searching IPs
```bash
$ vtscan ip <ip address 1> <ip address 2> <ip address 3>...
```

## 🔍 Searching Domains
```bash
$ vtscan domain <domain 1> <domain 2> <domain 3>...
```

## 🗺️ Roadmap
These are the following API endpoints that are planned for implementation
### IP Addresses
1. [Request an IP address (re)scan](https://docs.virustotal.com/reference/rescan-ip) `POST`
2. [Get comments on an IP address](https://docs.virustotal.com/reference/ip-comments-get) `GET`
3. [Add a comment to an IP address](https://docs.virustotal.com/reference/ip-comments-post) `POST`
4. [Get objects related to an IP address](https://docs.virustotal.com/reference/ip-relationships) `GET`
5. [Get object descriptors related to an IP address](docs.virustotal.com/reference/ip-relationships-ids) `GET`
6. [Get votes on an IP address](https://docs.virustotal.com/reference/ip-votes) `GET`
7. [Add a vote to an IP address](https://docs.virustotal.com/reference/ip-votes-post) `POST`

### Domains & Resolutions
1. [Request an domain (re)scan](https://docs.virustotal.com/reference/domains-rescan) `POST`
2. [Get comments on a domain](https://docs.virustotal.com/reference/domains-comments-get) `GET`
3. [Add a comment to a domain](https://docs.virustotal.com/reference/domains-comments-post) `POST`
4. [Get objects related to a domain](https://docs.virustotal.com/reference/domains-relationships) `GET`
5. [Get object descriptors related to a domain](https://docs.virustotal.com/reference/domains-relationships-ids) `GET`
6. [Get a DNS resolution object](https://docs.virustotal.com/reference/get-resolution-by-id) `GET`
7. [Get votes on a domain](https://docs.virustotal.com/reference/domains-votes-get) `GET`
8. [Add a vote to a domain](https://docs.virustotal.com/reference/domain-votes-post) `POST`
