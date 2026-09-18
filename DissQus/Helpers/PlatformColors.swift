//
//  PlatformColors.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import SwiftUI

#if os(macOS) || targetEnvironment(macCatalyst)
import AppKit
typealias ColorType = NSColor
#elseif os(iOS)
import UIKit
typealias ColorType = UIColor
#endif

extension Color {
    /// Cross-platform control background color
    static var controlBackground: Color {
        #if os(macOS) || targetEnvironment(macCatalyst)
        return Color(NSColor.controlBackgroundColor)
        #elseif os(iOS)
        return Color(UIColor.systemBackground)
        #endif
    }
    
    /// Cross-platform window background color
    static var windowBackground: Color {
        #if os(macOS) || targetEnvironment(macCatalyst)
        return Color(NSColor.windowBackgroundColor)
        #elseif os(iOS)
        return Color(UIColor.systemBackground)
        #endif
    }
}

