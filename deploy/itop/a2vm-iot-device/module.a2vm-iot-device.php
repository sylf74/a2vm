<?php
// SPDX-License-Identifier: LicenseRef-a2vm-proprietary
// datamodel.a2vm-iot-device.xml has no comment before <itop_design>: iTop reads the first node of
// the file as the root of the delta and would skip the classes silently.
// A2VM: the class IoTDevice, connected objects with an address (cameras, TVs, media players, energy
// meters and gateways, sensors), so that the CMDB lists them and A2VM can check their scan coverage.

SetupWebPage::AddModule(
	__FILE__,
	'a2vm-iot-device/1.0.1',
	[
		'label' => 'A2VM: connected objects (IoTDevice)',
		'category' => 'business',
		'dependencies' => [
			'itop-config-mgmt/3.2.0',
		],
		'mandatory' => false,
		'visible' => true,
		'datamodel' => [],
		'webservice' => [],
		'data.struct' => [],
		'data.sample' => [],
		'doc.manual_setup' => '',
		'doc.more_information' => '',
		'settings' => [],
	]
);
