# iTop extensions for NGVM

Extensions to install in the tenant's iTop (the CMDB that the `itop` connector reads, LLD detection
§3.5). They add to the data model only; NGVM never writes to the CMDB.

| Extension | What |
| --- | --- |
| `a2vm-iot-device` (1.0.1) | Class `IoTDevice` (under `ConnectableCI`): connected objects with an address — cameras, TVs, media players, energy meters and gateways, sensors, smart home hubs. A device type, a management IP and network interfaces, like a printer. Rights follow those of the other CIs (group `Configuration`). |

The extension keeps the name it had when the product was A2VM (before v0.25.0): iTop knows an
installed module by its name and keeps its objects in its table (`a2vm_iotdevice`); a new name
would be another module, and the devices already recorded would be lost.

## Install (iTop 3.2, in containers)

Copy the folder into `extensions/` of the iTop installation, under its own name (no version in the
folder name), then run the setup in "Upgrade" mode and tick the extension:

```bash
podman cp a2vm-iot-device itop_app:/var/www/html/itop/extensions/a2vm-iot-device
podman exec itop_app chown -R www-data:www-data /var/www/html/itop/extensions/a2vm-iot-device
podman exec itop_app chmod u+w /var/www/html/itop/conf/production/config-itop.php
```

Then `https://<itop>/setup/`, **Upgrade**, tick "NGVM: connected objects (IoTDevice)". The class
appears under Configuration management (search, new CI). Removing the extension later drops the
table `a2vm_iotdevice` and its objects.
