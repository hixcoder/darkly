# 1. Create a folder to keep things clean
mkdir -p hidden_loot
cd hidden_loot

# 2. Download every README file from the folder (Recursive)
# -r: Recursive (go into every folder)
# -np: No Parent (don't go back up to index.php)
# -A README: Only download files named "README"
# -e robots=off: Ignore the robots.txt rules
echo "🕷️ Crawling... This will take about 30 seconds..."
wget -q -r -np -e robots=off -A README http://localhost:8080/.hidden/

# 3. Find the needle in the haystack
# We search for lines that DO NOT (-v) contain the boring messages
echo "🔍 Searching for the secret..."
grep -r -v "Demande ton chemin" . | grep -v "Demande à ton voisin" | grep -v "Non ce n'est toujours pas bon" | grep -v "Toujours pas tu vas craquer" | grep -v "Tu veux de l'aide" | grep "README"