#!/bin/bash
# Start both frontend dev server and backend server for development.
set -e

cd "$(dirname "$0")/.."

# Ensure Go binary is built
echo "Building irify-benchmark..."
mkdir -p bin
go build -o bin/irify-benchmark ./cmd/irify-benchmark

echo "Starting dev environment..."
echo "  Frontend: http://localhost:5173"
echo "  Backend:  http://localhost:8081"
echo "  Press Ctrl+C to stop both"
echo ""

# Kill all background processes on exit
trap 'kill 0' EXIT

# Start frontend dev server
cd web && npm run dev &

# Start backend static file server (serve public/data for dev)
./bin/irify-benchmark server --static web/public --port 8081 &

# Wait for all background jobs
wait
