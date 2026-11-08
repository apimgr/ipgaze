# Translating IPGaze

This guide describes how to contribute translations for the web interface and
command line client. English is the source locale. Translators should edit a
target locale file and never change `en.json` as part of a translation update.

## Current languages

IPGaze embeds eight locale files in both binaries: English (`en`), Spanish
(`es`), French (`fr`), German (`de`), Italian (`it`), Chinese (`zh`), Arabic
(`ar`), and Japanese (`ja`). Arabic uses a right-to-left layout. The language
selector and CLI help derive their supported-language list from the same
registry as these embedded files.

## Contribute or update a translation

1. Copy `src/common/i18n/locales/en.json` as the starting point for a new
   language, or edit the existing locale file for an update.
2. Keep every key and its nesting unchanged. Translate values only, including
   all user-visible interface, help, and error text.
3. Set the `meta` fields: `language` (lowercase BCP 47 code), `name` (English
   language name), `native_name`, `direction` (`ltr` or `rtl`), and `version`.
   Add `translators` only when contributors have agreed to be credited.
4. Preserve every `{placeholder}` exactly, including its spelling and braces.
   Its position in a translated sentence may change.
5. Translate all plural forms required by the language's CLDR categories.
   Arabic uses `zero`, `one`, `two`, `few`, `many`, and `other`; English uses
   `one` and `other`. Preserve the plural key structure from the source file.
6. Keep product names, protocol names, config keys, file names, URLs, and
   literal option values such as `dark` and `auto` unchanged.
7. Submit the locale file and, for a new language, the registry and default
   language configuration changes together. Update the README language list
   and this page's language count in the same change.

AI-assisted and machine translations are welcome as best-effort contributions;
they do not need to wait for native-speaker review before merging. Human
reviewers are welcome to correct wording at any time. Keep a consistent,
neutral register and follow the language's punctuation and typography rules.
Use complete sentences instead of relying on adjacent fragments.

## Validation and review

Run the project's test gate with `make test`. It validates the embedded locale
set, JSON syntax, native names, translation keys, plural metadata, and the
documented supported-language list. Build both server and CLI binaries after
changing the locale registry; the locale files are embedded into each binary.

Review the interface at 320, 768, and 1280 CSS pixels. Check long translated
strings for clipping and overflow, and check right-to-left layouts in Arabic.
Keep the same key order and two-space JSON indentation as `en.json`.

## Translation glossary

| Term | Guidance |
|------|----------|
| IPGaze | Keep the product name unchanged |
| API, JSON, Tor, I2P | Keep protocol and technology names unchanged |
| token | Translate consistently as an authentication credential |
| rotate | Use the term for replacing a credential, not turning something |
| revoke | Use the term for invalidating a credential or permission |
| lookup | Use one consistent term for querying an IP address |

Add translator credits to the locale's `meta.translators` only with the
contributors' consent.
