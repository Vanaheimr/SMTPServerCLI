#!/bin/bash
#
# Pull this repository and its libraries, and build everything.

set -e

cd "$(dirname "$0")"

git pull
git submodule update --init --recursive
dotnet build SMTPServerCLI.slnx
