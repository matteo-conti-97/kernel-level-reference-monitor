#!/bin/bash

# Navigate to directory syscall_table_discover
cd syscall_table_discover || { echo "Failed to enter directory syscall_table_discover"; exit 1; }

# Run make
make clean || { echo "Make command failed"; exit 1; }

cd ..

# Navigate to directory reference-monitor
cd reference-monitor || { echo "Failed to enter directory reference-monitor"; exit 1; }

# Run make
make clean || { echo "Make command failed"; exit 1; }

echo "Cleaned successfully"