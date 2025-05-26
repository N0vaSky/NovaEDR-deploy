# Nova EDR

Nova EDR is a comprehensive, lightweight endpoint detection and response solution that combines three powerful open-source security tools managed by a single Windows agent/service. This project is primarily meant so that you can set up your own EDR/SOC capabilties for free, in your lab or organization and monitor the alerts yourself. This will give you the ability to create detection logic to detect adversary behavior, respond, and remediate threats as they arise.

## More Documenation on the Agent itself and it's setup can be found [here](https://share.evernote.com/note/961e1b55-874c-6903-a2cb-d7036500d52c)

## 🏗️ Architecture Overview

Nova EDR integrates three core security components managed by a single C# Windows service:

### 🎯 **Fibratus** - Primary Detection Engine
- **ETW-based threat detection** using Windows kernel events
- **YAML-based detection rules** for customizable threat detection
- **Real-time process monitoring** with kill capabilities
- **Pulls all kernel space ETW providers** File I/O Events, Network Events, Registry Events, Process Events, etc.
- **Host isolation** features for containment
- **Website**: [fibratus.io](https://www.fibratus.io/#/)
- **GitHub**: [rabbitstack/fibratus](https://github.com/rabbitstack/fibratus/tree/master)

### 🔍 **Velociraptor** - Digital Forensics & Incident Response
- **Endpoint visibility** and remote monitoring
- **Artifact collection** and forensic analysis
- **Host isolation** capabilities
- **Remote command execution** for malware cleanup
- **Documentation**: [Velociraptor Docs](https://docs.velociraptor.app/)

### 📊 **Wazuh** - Security Information Management (Optional)
- **Centralized log management** and correlation
- **Alert aggregation** from Fibratus detections
- **Custom rules** for security event processing
- **Documentation**: [Wazuh Documentation](https://documentation.wazuh.com/)

### 🤖 **Nova EDR Agent** - Unified Management Service
- **Automatic installation** and management of all components
- **GitHub-based updates** for detection rules and binaries
- **Service health monitoring** with automatic recovery
- **Centralized configuration** management

## 🚀 Getting Started

### Prerequisites

#### Server Infrastructure Required:
1. **Velociraptor Server** - Deploy following [installation guide](https://socfortress.medium.com/free-incident-response-with-velociraptor-bedd2583415d) (Note: Modify any version numbers in the commands of the guide to match the most current version that you set up. Also, you can generate a Windows MSI for endpoints on the server itself you don't need to compile one like in the guide. Just use the `Server.Utils.CreateMSI` Server Artifact)
2. **Wazuh Server** - Deploy following [installation guide](https://documentation.wazuh.com/current/quickstart.html)
3. **GitHub Repository** - Host detection rules and agent binaries

#### Client Requirements:
- Windows 10/11 or Windows Server 2016+
- Administrator privileges
- Internet connectivity to GitHub repository

### GitHub Repository Structure

Your GitHub repository should contain:
```
your-repo/
├── client-id/
│   ├── Fibratus.msi          # Fibratus installer
│   ├── Velo.msi              # Velociraptor client (configured for your server)
│   ├── Wazuh.ps1             # Wazuh installation script (configured for your server)
│   ├── Custom-Rules.zip      # Fibratus YAML detection rules
|   |   ├── Custom Rules
|   |       ├── Modified Official Rules
|   |       |     ├── modified_official_rules.yml   # If you edit the contents of an offical rule file but stick it with the same name here it will overwrite the official rule that is installed with Fibratus by default.
|   |       ├── custom_rule_file.yml                # These are all your custom detection rules that will be added to Fibratus when it installs.
│   └── Custom-Rules.zip.version  # Version tracking for rules
```
## 🔧 Nova EDR Agent Capabilities

The Nova EDR Agent is a Windows service that provides:

### 🔄 **Automatic Management**
- **Component Installation**: Automatically installs Fibratus, Velociraptor, and Wazuh
- **Rule Updates**: Regularly pulls latest detection rules from GitHub
- **Service Monitoring**: Automatically restarts crashed services
- **Version Control**: Tracks component versions to avoid unnecessary updates

### 📡 **GitHub Integration**
- **Direct Repository Access**: Pulls updates directly from your GitHub repo
- **Configurable Update Intervals**: Set custom check frequencies (default: 60 minutes)
- **Version Tracking**: Only updates when new versions are available
- **Clean Rule Deployment**: Replaces detection rules completely on each update

### 🛡️ **Security Features**
- **Hash Validation**: Verifies integrity of downloaded files
- **Service Recovery**: Automatically restarts failed security services
- **Logging**: Comprehensive logging to Windows Event Log and files

## 🎯 Detection Rule Development

### Creating Custom Fibratus Rules

Fibratus uses YAML-based detection rules that monitor Windows ETW events:

1. **Study existing rules**: Browse the [Fibratus rules directory](https://github.com/rabbitstack/fibratus/tree/master/rules)
2. **Create custom rules**: Write YAML rules targeting specific threats
3. **Add to Custom-Rules.zip**: Package your rules and upload to GitHub
4. **Automatic deployment**: Nova EDR Agent will pull and apply new rules

Example detection rule structure:
```yaml
name: Custom Malware Detection
description: Detects suspicious process behavior
condition: >
  kevt.name = 'CreateProcess' and
  ps.name contains 'malware.exe'
action: kill  # Can kill processes automatically
```
## 📈 Alert Flow & Integration
### Fibratus → Wazuh → Discord Pipeline

Detection: Fibratus generates alerts based on YAML rules
Ingestion: Wazuh receives Fibratus alerts via XML rule configuration
Processing: Wazuh correlates and enriches security events
Notification: Alerts forwarded to Discord for real-time monitoring

### Discord Integration Setup
Follow this comprehensive guide to set up Discord notifications: https://www.learntohomelab.com/homelabseries/EP19_wazuhdiscordalerts/
Result: Real-time EDR alerts delivered to your Discord channel:![image](https://github.com/user-attachments/assets/1d365802-c84a-4179-a1e8-dc9b2653f116)

