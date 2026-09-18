#!/usr/bin/env fish

# Script to copy iOS libraries to Xcode project
# Usage: ./setup_ios_lib.fish

set -l SCRIPT_DIR (dirname (status --current-filename))
set -l IOS_LIB_DIR "(status dirname)/../../native/hqc/lib/src/ios_output"
set -l TARGET_DIR "$SCRIPT_DIR"

echo "Setting up iOS libraries for Xcode project..."
echo "Source: $IOS_LIB_DIR"
echo "Target: $TARGET_DIR"

# Check if source files exist
if not test -f "$IOS_LIB_DIR/libhqc_wrap_ios_device.a"
    echo "Error: libhqc_wrap_ios_device.a not found at $IOS_LIB_DIR"
    echo "Please run the build script first:"
    echo "  cd native/hqc/lib/src && ./build_ios_lib.fish"
    exit 1
end

if not test -f "$IOS_LIB_DIR/libhqc_wrap_ios_simulator.a"
    echo "Error: libhqc_wrap_ios_simulator.a not found at $IOS_LIB_DIR"
    exit 1
end

# Copy libraries
echo ""
echo "Copying iOS libraries..."
cp "$IOS_LIB_DIR/libhqc_wrap_ios_device.a" "$TARGET_DIR/"
cp "$IOS_LIB_DIR/libhqc_wrap_ios_simulator.a" "$TARGET_DIR/"

if test $status -eq 0
    echo "✓ Libraries copied successfully"
    echo ""
    echo "Next steps in Xcode:"
    echo "1. Open DissQus.xcodeproj"
    echo "2. Right-click project → Add Files to DissQus..."
    echo "3. Select libhqc_wrap_ios_device.a and libhqc_wrap_ios_simulator.a"
    echo "4. In Build Phases → Link Binary With Libraries:"
    echo "   - Set libhqc_wrap.dylib Platform Filter to 'macOS'"
    echo "   - Set libhqc_wrap_ios_device.a Platform Filter to 'iOS'"
    echo "   - Set libhqc_wrap_ios_simulator.a Platform Filter to 'iOS Simulator'"
else
    echo "Error: Failed to copy libraries"
    exit 1
end


