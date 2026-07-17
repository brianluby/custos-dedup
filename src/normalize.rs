use std::borrow::Cow;

pub(crate) fn text(value: &str) -> Cow<'_, str> {
    let trimmed = value.trim();
    let already_normalized = !trimmed.is_empty()
        && !trimmed.contains("  ")
        && trimmed.chars().all(|character| {
            (character.is_alphanumeric() || character == ' ')
                && character.to_lowercase().eq([character])
        });

    if already_normalized {
        return Cow::Borrowed(trimmed);
    }

    let mut normalized = String::with_capacity(trimmed.len());
    let mut needs_separator = false;
    for character in trimmed.chars().flat_map(char::to_lowercase) {
        if character.is_alphanumeric() {
            if needs_separator && !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.push(character);
            needs_separator = false;
        } else {
            needs_separator = true;
        }
    }
    Cow::Owned(normalized)
}

pub(crate) fn similarity(left: &str, right: &str) -> f64 {
    let left = text(left);
    let right = text(right);
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }
    rapidfuzz::fuzz::ratio(left.chars(), right.chars())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_collapses_case_punctuation_and_whitespace() {
        assert_eq!(
            text("  OpenSSL: Buffer   Overflow! "),
            "openssl buffer overflow"
        );
    }

    #[test]
    fn text_keeps_unicode_letters() {
        assert_eq!(text("CAFÉ déjà-vu"), "café déjà vu");
    }

    #[test]
    fn text_lowercases_titlecase_characters_on_the_fast_path() {
        assert_eq!(text("ǅeta widget"), "ǆeta widget");
        assert_eq!(text("ǅeta widget"), text("ǅeta-widget"));
    }

    #[test]
    fn similarity_is_zero_when_either_side_is_empty() {
        assert_eq!(similarity("", "finding"), 0.0);
    }
}
