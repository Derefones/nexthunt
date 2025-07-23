#!/bin/bash
# Remove broken, duplicate, or unused files and fix repository structure

set -euo pipefail

print_status() { echo -e "\033[0;34m[*]\033[0m $1"; }
print_success() { echo -e "\033[0;32m[✓]\033[0m $1"; }
print_warning() { echo -e "\033[1;33m[!]\033[0m $1"; }

print_status "Cleaning up repository structure..."

# Files to remove (broken, duplicate, or superseded)
files_to_remove=(
    "comprehensive-test.sh"           # Duplicate of complete-test-suite.sh
    "fix-service-ports.sh"           # Creates port conflicts, logic moved to add-service.sh
    "service-template.sh"            # Superseded by unified add-service.sh
    "add-crawler-config.json"        # Unused config file
    "test-web-crawler.sh"            # Part of removed example
    "test-framework.sh"              # Duplicate functionality in validation-script.sh
)

# Remove broken/duplicate files
removed_count=0
for file in "${files_to_remove[@]}"; do
    if [[ -f "$file" ]]; then
        rm -f "$file"
        print_success "Removed duplicate/broken file: $file"
        ((removed_count++))
    fi
done

# Remove any temporary test directories
for dir in nexthunt-test-*; do
    if [[ -d "$dir" ]]; then
        rm -rf "$dir"
        print_success "Removed temporary directory: $dir"
        ((removed_count++))
    fi
done

# Remove broken template files
if [[ -d "templates" ]]; then
    find templates -name "*.bak" -o -name "*~" -o -name "web-crawler.*" | while read -r file; do
        if [[ -f "$file" ]]; then
            rm -f "$file"
            print_success "Removed broken template: $file"
            ((removed_count++))
        fi
    done
fi

# Clean up backup files
find . -maxdepth 1 -name "*.bak" -o -name "*~" -o -name ".#*" | while read -r file; do
    if [[ -f "$file" ]]; then
        rm -f "$file"
        print_success "Removed backup file: $file"
        ((removed_count++))
    fi
done

# Fix script permissions
print_status "Fixing script permissions..."
find . -name "*.sh" -type f -exec chmod +x {} \; 2>/dev/null || true

# Remove empty directories
print_status "Removing empty directories..."
find . -type d -empty -not -path "./.git/*" -delete 2>/dev/null || true

# Consolidate documentation
if [[ -f "README.md" ]] && [[ -f "quick-start-guide.md" ]]; then
    print_status "Documentation files found - consider consolidating"
fi

# Report cleanup results
echo
if [[ $removed_count -gt 0 ]]; then
    print_success "Cleanup completed - removed $removed_count items"
else
    print_success "Repository is already clean"
fi

print_status "Repository structure optimized"
echo
echo "Active core files:"
echo "├── nexthunt-setup.sh          # Main setup script"
echo "├── add-service.sh             # Service creation (unified)"
echo "├── validation-script.sh       # Core validation functions"
echo "├── complete-test-suite.sh     # Comprehensive testing"
echo "├── quickstart.sh              # Quick setup and demo"
echo "├── production-deployment.sh   # Production deployment"
echo "├── service-config.json        # Service configuration"
echo "├── plugin-system.txt          # Plugin system documentation"
echo "└── quick-start-guide.md       # User documentation"
echo
echo "Removed/consolidated:"
for file in "${files_to_remove[@]}"; do
    echo "  ✗ $file"
done
