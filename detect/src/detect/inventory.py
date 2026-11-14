# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""`detect inventory`: the declared inventory, findings from the products and versions a client
declared in its profile. The matching itself is `ngvm.declared`, shared with the watch of pillar 1
(LLD vulnerability-detection §1.1, §3.3).
"""

from __future__ import annotations

from ngvm.declared import SOURCE, DeclaredMatcher, declared_observations

InventoryScanner = DeclaredMatcher

__all__ = ["SOURCE", "InventoryScanner", "declared_observations"]
