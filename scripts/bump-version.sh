#!/usr/bin/env bash
# Auto-bump version and commit (used in release pipeline)
# Usage: ./scripts/bump-version.sh [major|minor|patch]

set -euo pipefail

BUMP_TYPE="${1:-patch}"

echo "📦 Bumping version ($BUMP_TYPE)..."

npm version "$BUMP_TYPE" --no-git-tag-version

NEW_VERSION=$(jq -r '.version' package.json)

echo "✅ Version bumped to $NEW_VERSION"
echo ""
echo "📝 Next steps (manual):"
echo "  1. git add package.json package-lock.json"
echo "  2. git commit -m 'chore(release): v$NEW_VERSION'"
echo "  3. git tag v$NEW_VERSION"
echo "  4. git push origin master && git push origin v$NEW_VERSION"
echo "  5. gh release create v$NEW_VERSION --notes '...'"
