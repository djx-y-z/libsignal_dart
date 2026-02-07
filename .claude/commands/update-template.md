Update the copier template to the latest version.

Target version: $ARGUMENTS (if empty, check for the latest available version)

## Steps

1. **Read current template version** from `.copier-answers.yml` (`_commit` field)

2. **Determine target version:**
   - If `$ARGUMENTS` is provided, use it as the target version
   - If not provided, run `make check-template-updates` to find the latest available version
   - If already up to date, inform the user and stop

3. **Run copier update:**
   ```bash
   copier update --trust --defaults --vcs-ref=<version>
   ```

4. **Check for conflicts:**
   - Search for `.rej` files: `find . -name "*.rej"`
   - If found, show each `.rej` file and resolve the conflicts
   - Delete `.rej` files after resolving

5. **Verify `.copier-answers.yml`:**
   - Check that `_commit` was updated to the target version
   - If not, update it manually

6. **Run quality checks:**
   ```bash
   make analyze
   make test
   ```
   - If checks fail, investigate and fix the issues

7. **Show summary:**
   - Show `git diff --stat` of all changes
   - Remind the user of next steps:
     ```
     Next steps:
     1. Review the changes
     2. Commit: git add -A && git commit -m "feat: adopt copier template vX.Y.Z"
     ```
