gso-checker fixtures
====================

synthetic/   Small hand-made inputs checked into the repo (process-probe command
             output samples). Most synthetic worlds (release zips, fake live trees,
             baselines, backups) are generated at test time under pytest's tmp_path
             by tests/helpers.py -> build_world(); nothing is ever written to D:\ or E:\.

expected/    Expected values for acceptance tests that read the real corpus:
             a01_stale_files.json    A01 hashes (0.5.4e vs repo overlay ae4f6169)
             a02_historical_aba.json A02 historical A-B-A count (0) on the 7
                                     EUREX-1.5 releases, computed once by hand
                                     with a throwaway script (see the file).

Real corpus (READ ONLY, tests skip cleanly when missing):
  E:\GSO_checker_addendum_A\         addendum A: README.txt, INVENTORY.txt,
                                     releases/releases.json (8 zips, sha256, paths),
                                     snapshots/snapshots.json (53 backup folders),
                                     repo/overlay_ae4f6169.zip (repo overlay),
                                     repo/live_vs_overlay.txt
  E:\GSO_052\, E:\GSO_053\, E:\GSO_054\   the release zips listed in releases.json
  E:\M2TW_backup_2026-11-04_gso054\removed_stallwatch_2026-11-08\eur40StallWatch.nut   (A03)
  D:\SteamLibrary\steamapps\common\Medieval II Total War\mods\Divide_and_Conquer_EUR   live game, never written
