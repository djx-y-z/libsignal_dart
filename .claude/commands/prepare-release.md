Prepare a new release of this package.

Target version: $ARGUMENTS (if empty, read current version from pubspec.yaml and ask what the new version should be)

## Steps

1. **Read current version** from `pubspec.yaml` (`version:` field)

2. **Determine new version:**
   - If `$ARGUMENTS` is provided, use it as the new version (strip leading `v` if present)
   - If not provided, show the current version and ask the user for the new version

3. **Update `pubspec.yaml`:**
   - Change `version: X.Y.Z` to the new version

4. **Update `CHANGELOG.md`:**
   - Rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD` (use today's date)
   - Add a new empty `[Unreleased]` section above it
   - Update comparison links at the bottom:
     - Add `[Unreleased]: https://github.com/<repo>/compare/vX.Y.Z...HEAD`
     - Add `[X.Y.Z]: https://github.com/<repo>/compare/vPREVIOUS...vX.Y.Z`
     - Read the repo URL and previous version from existing links in the file

5. **Validate:**
   - Run `make publish-dry-run` to verify the package is ready for publishing
   - If it fails, show the errors and stop

6. **Show diff** of all changes made so the user can review before proceeding

7. **Commit:**
   - `git add pubspec.yaml CHANGELOG.md`
   - `git commit -m "chore: prepare release vX.Y.Z"`

8. **Create annotated tag:**
   - `git tag -a vX.Y.Z -m "Release vX.Y.Z"`

9. **Push commit and tag:**
   - `git push origin main`
   - `git push origin vX.Y.Z`
   - This triggers the `publish.yml` CI workflow which publishes to pub.dev
