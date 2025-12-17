#!/bin/bash

# Script to create a breach folder structure
# Usage: ./setup_breach.sh "Breach Name"

if [ -z "$1" ]; then
    echo "Usage: ./setup_breach.sh \"Breach Name\""
    echo "Example: ./setup_breach.sh \"SQL Injection\""
    exit 1
fi

BREACH_NAME="$1"
# Replace spaces with underscores for folder name
FOLDER_NAME=$(echo "$BREACH_NAME" | tr ' ' '_')

# Create the breach folder
mkdir -p "$FOLDER_NAME/Resources"

# Create empty flag file
touch "$FOLDER_NAME/flag"

# Create a template README in Resources
cat > "$FOLDER_NAME/Resources/README.md" << EOF
# $BREACH_NAME - Documentation

## How I Found It
(Describe how you discovered this vulnerability)

## Exploitation Steps
1. 
2. 
3. 

## Proof
(Add screenshots, request/response captures, etc.)

## How to Fix
(Explain how this vulnerability should be fixed)

## Additional Notes
(Any other relevant information)
EOF

echo "Created breach folder structure for: $BREACH_NAME"
echo "Folder: $FOLDER_NAME/"
echo "  - flag"
echo "  - Resources/"
echo "    - README.md (template)"
echo ""
echo "Next steps:"
echo "1. Find the flag and save it to $FOLDER_NAME/flag"
echo "2. Document your findings in $FOLDER_NAME/Resources/README.md"
echo "3. Add any proof files to $FOLDER_NAME/Resources/"

