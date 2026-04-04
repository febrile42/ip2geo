# This cleans up after a develop->Main PR merge
# Avoids GH telling us we're commits ahead/behind
git fetch origin
git checkout develop
git pull --rebase origin main
git push --force-with-lease origin develop