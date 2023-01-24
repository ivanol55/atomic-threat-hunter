# What is atomic-threat-hunter?
`atomic-threat-hunter` (Security scanner helper tools built around Nuclei) is a **set of tools and scripts** that aims to provide you with a continuous application security posture management toolset based on a **constantly generated**, **lightweight**, **quickly actionable** set of vulnerability reports, streamed directly into our security management platform.

# Why do we need this?
Application security posture management is a **considerable undertaking**. Data needs to be gathered from several sources to identify targets, have those targets properly scanned for vulnerabilities, and all this reporting needs to be **processed**, **aggregated** and **transformed** into easy to recognize, actionable alerts and reports. In our case, to avoid further service costs and vendor lock-in, we run these checks using  by ProjectDiscovery.

# Why create this tool if Nuclei exists?
Nuclei is very good at its job of investigating security violations against a set of standards, for example against the widely used OWASP Top 10, or for common misconfigurations we can target and fix. That said, Nuclei is designed to be launched manually, and its results checked in terminal interfaces. It's really useful to have a security scanner that we can run to check for vulnerabilities in bulk, but a 500 line `json` pasted in an ephimeral terminal is not the **human-centric** way of working. That's where `atomic-threat-hunter` comes in.

# What does atomic-threat-hunter bring to the table?
The aim of this tool is to bring in the human-centric part we miss from ProjectDiscovery's already awesome [Nuclei](https://github.com/projectdiscovery/nuclei):
- **Ease of use**: Configure the tool once with the profiles you need, and leave it running forever to work for you
- **A friendly interface**: read up on what needs to be fixed without the need of a terminal
- **A method to the madness**: keep an order to the reports we generate
- **Information updates**: A point-in-time scan is useless in a constantly evolving environment. So we make it easy to keep the report up to date. Known info deson't mean new alerts.
- **Narrow down on your target**: Is the general scope too heavy on your target? make a faster, more lightweight profile to run simultaneously. Scale as you need.
- **Make it fancy**: Data processing without your intervention. Just go see the new alerts!
- **Portable and reproducible**: docker image, ready to build and test!

# How does this work?
This CLI tool is built entirely as a Go binary, with all its dependencies built inside a Docker image with the provided `Dockerfile`. The image uses the `helper` built binary as an entrypoint, so just build it:
```
docker build -t atomic-threat-hunter
```

modify your desired profile in `config.json`, and run the container with the desired task and profile:
```
docker run --rm \
    -v ./config.json:/atomic-threat-hunter/config.json \
    -v ./scans:/atomic-threat-hunter/scans \
    atomic-threat-hunter:latest scan full example-profile
```

# Where can I send the detected findings?
The standard format provided by Nuclei can be sent to anything that then supports the data processing as an integration. Currently the `datadog` logging platform is supported.
