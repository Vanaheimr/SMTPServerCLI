#!/bin/bash
#
# Start the SMTP server with whatever was passed here, e.g.
#
#   ./run.sh --hostname mail.example.org --local-domain example.org
#
# --help lists the switches. Build first (./updateAndBuild.sh): --no-build is
# safe, because the banner prints the commit every assembly was built from,
# so a stale binary says so itself.

set -e
cd "$(dirname "$0")"

dotnet run --no-build --no-restore --project SMTPServerCLI -- "$@"
