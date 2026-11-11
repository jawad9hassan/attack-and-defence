# Service template

Copy this folder to `services/<your-service-name>/` and follow
`docs/ADDING_A_SERVICE.md` step by step. Nothing in this folder is wired
into the platform — it exists purely as a starting point.

Files:

- `Dockerfile.template` — shows the flagd-sidecar pattern every service
  needs (adjust the base image and the actual service build/run steps).
- `entrypoint.sh.template` — starts flagd in the background, then execs
  the real service.
- `checker_template.py` — copy to
  `platform/checker/checkers/<your-service>_checker.py` and fill in
  `sla_check`; `put_flag` can usually be copied as-is.
- `src/` — put your service's source code here.
