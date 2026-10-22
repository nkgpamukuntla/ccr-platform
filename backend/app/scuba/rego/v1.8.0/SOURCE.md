# Vendored from CISA ScubaGear

- Repository: https://github.com/cisagov/ScubaGear
- Tag: v1.8.0 (commit 2d01e711fcb74f615e1fbea6d06556a8dcbff11f)
- Files: PowerShell/ScubaGear/baselines/aad.md (requirement text), PowerShell/ScubaGear/Rego/AADConfig.rego, Rego/Utils/*.rego (the whole folder, as ScubaGear loads it)
- Licence: CC0 1.0 (see LICENSE). Copied unmodified; do not edit. To update, copy a new tag
  into a new folder and compare results against a reference ScubaGear run.
- Evaluated with OPA 1.15.2 (ScubaGear 1.8.0's default), exactly as ScubaGear runs it:
  opa eval data.aad.tests -i <input> -d AADConfig.rego -d Utils -f values
