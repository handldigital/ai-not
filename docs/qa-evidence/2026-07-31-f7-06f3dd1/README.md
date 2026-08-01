# F7 weekly report visual evidence

Tested PR #18 at the immutable application commit `06f3dd185ffd6fd2024f8d1544844031ef5d5b84` on the live HandL WordPress sandbox.

## Evidence

- `weekly-report-staged-inactive.jpg` shows the unstored weekly preference rendered checked while logging and learn mode are both off. The control and the disclosure agree: the preference is selected by default, delivery is inactive, and the operator can uncheck and save to opt out.
- `weekly-report-first-save-optout.mp4` is a 31.3-second Cap screen recording. It starts from that checked-but-inactive state, enables logging, unchecks the weekly preference, saves once, and returns with the Saved notice, logging checked, and the weekly preference still unchecked.

The post-save WordPress option was independently read after the captured flow and contained `log_enabled: true` and `weekly_report_enabled: false`.

## Media validation

- Screenshot: JPEG, 2560 x 1233, SHA-256 `5b90397e28bf99d0825476fa7ecdc2f6e0579f632e93435e927d1a8b38fca07d`.
- Recording: H.264/AAC MP4, 1920 x 1058, 30 fps, 31.3 seconds, 939 video frames, SHA-256 `ca0fe7378e4105aa9945e0e1d49fd6eaad941f3e2e1b45274df8486846451c7b`.
- Video timestamps are strictly increasing, with zero non-increasing frames and a 0.033333 to 0.033334 second frame interval.
- The first frame, action frames, final frame, and a one-frame-per-second contact sheet were visually inspected.

Cap 0.5.7 left the recording status at `NeedsRemux` even though the complete `display.mp4` existed. The stale metadata path and status were corrected to the existing media, Cap's own project validator then returned `valid: true`, and this MP4 was exported from that validated project.

## Sandbox restore

After capture, the plugin was restored to baseline commit `8f391d6ea2d378b03614a581fb5b756724ad2055`. The database snapshot verified byte-for-byte at SHA-256 `7f53d6bf81dc5a900763dcf958d2f8b37da7347595ac919eb3a1765165fe04ff`, with 142 log rows and zero weekly cron events. The only untracked plugin-worktree file is the pre-existing `deploy.sh`.
