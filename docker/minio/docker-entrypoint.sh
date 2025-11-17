#!/bin/sh
set -e

# Start MinIO server in the background
echo "Starting MinIO server..."
minio server /data --console-address ":9001" &
MINIO_PID=$!

# Wait for MinIO to be ready
echo "Waiting for MinIO to start..."
sleep 5

# Configure mc client
until mc alias set myminio http://localhost:9000 "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" 2>/dev/null; do
    echo "MinIO is not ready yet, waiting..."
    sleep 2
done

echo "MinIO is ready, creating buckets..."

# Create the plugin-storage bucket if it doesn't exist
if ! mc ls myminio/plugin-storage 2>/dev/null; then
    echo "Creating bucket: plugin-storage"
    mc mb myminio/plugin-storage
    echo "Bucket plugin-storage created successfully"
else
    echo "Bucket plugin-storage already exists"
fi

echo "MinIO initialization complete"

# Wait for MinIO process
wait $MINIO_PID
