You are executing the MASS Architectural Roadmap. Your plan is at: C:\Users\bradj\.claude\plans\jolly-foraging-clover.md

Read the plan, then check your progress state file at: docs/testing/ralph-progress.json

If the progress file doesn't exist, create it with: {"current_phase": "P0.1", "completed": [], "bugs_filed": [], "iteration": 0}

INCREMENT the iteration counter each time you run.

IMPORTANT: The gh CLI is at "/c/Program Files/GitHub CLI/gh.exe" - use this full path for all gh commands. The repo is r33n3/MASS.

IMPORTANT: The API proxy is nginx at http://localhost (port 80). API routes are at /api/v1/* through the proxy. The health endpoint is at http://localhost:8000/health (direct) - the proxy has its own /health. Use proxy paths (http://localhost/api/v1/*) for all testing except health which should go direct to port 8000.

IMPORTANT: python3 doesn't exist on this Windows system. Use `python` instead.

WORKFLOW:
1. Read the plan file and progress file
2. Pick up from where you left off (current_phase)
3. Execute the current sub-phase:

   PHASE 0 (Validation):
   - Run each test described in the plan via curl/API calls through the proxy
   - For UI tests: verify the endpoints the UI would call work correctly
   - For each test: record PASS or FAIL
   - For each FAIL: create a GitHub Issue via: "/c/Program Files/GitHub CLI/gh.exe" issue create --title "P0: [test name] - [brief description]" --body "Phase: [phase] Test: [test description] Expected: [expected] Actual: [actual error] Layer: [proxy/api/db/worker/ui]" --label "bug,phase-0" --repo r33n3/MASS
   - After filing the issue, ATTEMPT TO FIX the blocking bug immediately
   - After fixing, re-test to verify the fix works
   - Mark the sub-phase complete in progress file
   - Move to next sub-phase

   PHASE 0 EXIT CRITERIA: P0.3 (core scan API pipeline) passes end-to-end. Non-blocking bugs in P0.5/P0.6 should be filed but don't block Phase 1.

   PHASE 1-5: Implement changes described in the plan, test, file issues for problems, commit working code after each sub-phase.

4. Update progress file after completing each sub-phase
5. If you complete ALL phases, output: <promise>ROADMAP COMPLETE</promise>
6. If you hit an unresolvable blocker, file a GitHub issue and skip to next sub-phase

RULES:
- Always read the plan file fresh each iteration (it may have been updated)
- Always read and update the progress file
- Never skip Phase 0 -- it must pass before Phase 1+ begins
- Commit working code frequently (per sub-phase, not per phase)
- File GitHub Issues for ALL bugs/problems found, even cosmetic ones
- Fix blocking bugs before moving forward
- Use labels: bug, enhancement, phase-0 through phase-5
- Test through the proxy (http://localhost/) not direct to API port (except /health)
