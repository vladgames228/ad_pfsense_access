# AD to PfSense Access

**Concept:** AD user logins to a PC, the Domain Controller (DC) catches which PC it was and sends an API request to PfSense that adds the IP address of that PC to a dedicated alias. When any other user logins to the same PC, the DC removes the previous IP from the alias. 

On PfSense, you can set any rules for these aliases (e.g., special level access). To deploy, add the AD user to a dedicated AD group, configure `config.json`, and install the service. 

**Note:** The service must catch AD logs, so it must be installed only on the Domain Controller!

## Installation

1. Install [pfrest.org](https://pfrest.org/INSTALL_AND_CONFIG/) on your PfSense.
2. Create a user with access to the aliases configuration.
3. Generate a **RESTAPI KEY** from that user's account.
4. Download the project to the DC and extract it.
5. Copy the RESTAPI key and paste it into `config.json`.
6. Set the PfSense HTTPS URL in `config.json`.
7. In the **"mapping"** section, set the keys (name of the alias) and values (list of AD groups whose users will be added to that alias).
8. In the **"ip_list"** section, list the PCs on which this logic should work.
9. Install [python.org](https://www.python.org/) on the DC.
10. Run `install.bat` from the project folder. 

The installer will create the `C:/Windows/AD_Pfsense_Access` folder, copy the necessary files, and create a service with the same name.

## Compatibility
* Tested on Windows Server 2022 with AD level 2016.

## Contributing
If you encounter any issues or have a suggestion, please contribute an issue.