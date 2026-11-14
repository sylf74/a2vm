# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
terraform {
  required_version = ">= 1.6"
  # The state in GitLab (docs/platform.md §2): tofu init with -backend-config, or a local state
  # with tofu init -backend=false for a test.
  backend "http" {}
}
