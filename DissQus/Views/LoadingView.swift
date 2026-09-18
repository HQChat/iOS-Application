//
//  LoadingView.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import SwiftUI

struct LoadingView: View {
    let message: String

    init(message: String = "Loading...") {
        self.message = message
    }

    var body: some View {
        VStack(spacing: 18) {
            HQLogoMark(size: 48)
                .modifier(BlinkModifier())

            Text(message)
                .font(HQFont.ui(14, weight: .medium))
                .foregroundColor(HQColor.textSecond)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .hqScreenBackground()
    }
}
