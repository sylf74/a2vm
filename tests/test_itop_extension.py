# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The iTop extension a2vm-iot-device (deploy/itop): a delta iTop can load, labels for every value."""

from __future__ import annotations

import re
import xml.dom.minidom

from .conftest import ROOT

EXT = ROOT / "deploy" / "itop" / "a2vm-iot-device"


def test_the_root_element_is_the_first_node():
    # iTop reads childNodes[0] of the delta as its root: a comment before <itop_design> makes it skip
    # every class without an error (seen with iTop 3.2.3).
    doc = xml.dom.minidom.parse(str(EXT / "datamodel.a2vm-iot-device.xml"))
    assert doc.childNodes[0].nodeType == doc.ELEMENT_NODE
    assert doc.childNodes[0].tagName == "itop_design"


def test_every_device_type_has_a_label_in_each_language():
    text = (EXT / "datamodel.a2vm-iot-device.xml").read_text()
    field = text[text.index('<field id="device_type"') : text.index("</field>", text.index('<field id="device_type"'))]
    values = set(re.findall(r'<value id="(\w+)">', field))
    assert values and "other" in values
    for lang in ("en", "fr"):
        labels = (EXT / f"{lang}.dict.a2vm-iot-device.php").read_text()
        for value in values:
            assert f"'Class:IoTDevice/Attribute:device_type/Value:{value}'" in labels, (lang, value)
        assert "'Class:IoTDevice'" in labels and "'Class:Model/Attribute:type/Value:IoTDevice'" in labels


def test_module_version_and_dependency():
    module = (EXT / "module.a2vm-iot-device.php").read_text()
    assert re.search(r"'a2vm-iot-device/\d+\.\d+\.\d+'", module)
    assert "'itop-config-mgmt/3.2.0'" in module
