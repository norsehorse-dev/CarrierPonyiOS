// InAppStrings.swift
// CarrierPony iOS
//
// Catalog lookups for strings built in code (row previews, time labels, day
// separators), in the in-app language. SwiftUI Text(LocalizedStringKey)
// follows the .environment(\.locale) RootView sets from cp.lang, but a plain
// String returned from a helper is shown verbatim, so these stayed English in
// every language. Pass the view's environment locale.

import Foundation

enum InAppStrings {

    /// The catalog value for `key` in `locale`'s language, falling back to the
    /// key itself (the English source).
    static func string(_ key: String, locale: Locale) -> String {
        let code = locale.language.languageCode?.identifier ?? "en"
        guard code != "en",
              let path = Bundle.main.path(forResource: code, ofType: "lproj"),
              let bundle = Bundle(path: path) else { return key }
        return bundle.localizedString(forKey: key, value: key, table: nil)
    }

    /// A catalog format string with one integer argument (e.g. "%lld members").
    static func format(_ key: String, _ value: Int, locale: Locale) -> String {
        String(format: string(key, locale: locale), locale: locale, value)
    }
}
