use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use cpe::component::Component;
use cpe::cpe::{Cpe, CpeType, Language};
use cpe::uri::Uri;
use packageurl::PackageUrl;

const CPE23_PREFIX: &str = "cpe:2.3:";
const CPE23_COMPONENT_COUNT: usize = 11;
const CPE22_MAX_COMPONENT_COUNT: usize = 7;
const PURL_IDENTITY_PREFIX: &str = "subject:purl:v1:";
const CPE_IDENTITY_PREFIX: &str = "subject:cpe:v1:";

const PART: usize = 0;
const VENDOR: usize = 1;
const PRODUCT: usize = 2;
const VERSION: usize = 3;
const UPDATE: usize = 4;
const EDITION: usize = 5;
const LANGUAGE: usize = 6;
const SW_EDITION: usize = 7;
const TARGET_SW: usize = 8;
const TARGET_HW: usize = 9;
const OTHER: usize = 10;

/// An error while parsing or normalizing a structured subject identifier.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// A Package URL failed its underlying syntax or type-specific validation.
    #[error("invalid Package URL: {reason}")]
    InvalidPurl {
        /// A dependency-independent explanation of the parse failure.
        reason: String,
    },
    /// A percent sign was not followed by exactly two hexadecimal digits.
    #[error("invalid percent escape in Package URL at byte {position}")]
    InvalidPercentEscape {
        /// The byte offset of the invalid percent sign.
        position: usize,
    },
    /// A Package URL contained an explicit but empty version.
    #[error("Package URL version must not be empty")]
    EmptyPurlVersion,
    /// A Package URL qualifier was not a non-empty `key=value` pair.
    #[error("invalid Package URL qualifier `{qualifier}`; expected `key=value`")]
    InvalidPurlQualifier {
        /// The invalid raw qualifier pair.
        qualifier: String,
    },
    /// A Package URL qualifier had an empty value.
    #[error("Package URL qualifier `{key}` must not have an empty value")]
    EmptyPurlQualifierValue {
        /// The qualifier key.
        key: String,
    },
    /// A Package URL repeated a qualifier key after case normalization.
    #[error("duplicate Package URL qualifier `{key}`")]
    DuplicatePurlQualifier {
        /// The normalized duplicate key.
        key: String,
    },
    /// The input was not a supported CPE binding.
    #[error("unsupported CPE binding; expected `cpe:2.3:`, `cpe:/`, `x-cpe:/`, or `p-cpe:/`")]
    UnsupportedCpeBinding,
    /// A CPE 2.3 formatted string did not contain exactly eleven components.
    #[error("CPE 2.3 formatted string must contain {expected} components, found {actual}")]
    CpeComponentCount {
        /// The required component count.
        expected: usize,
        /// The observed component count.
        actual: usize,
    },
    /// A legacy CPE URI contained fields the dependency would silently ignore.
    #[error("legacy CPE URI supports at most {maximum} components, found {actual}")]
    LegacyCpeComponentCount {
        /// The largest supported legacy component count.
        maximum: usize,
        /// The observed component count.
        actual: usize,
    },
    /// A CPE component ended with an incomplete backslash escape.
    #[error("invalid escape in CPE component {component} at byte {position}")]
    InvalidCpeEscape {
        /// The zero-based component index.
        component: usize,
        /// The byte offset within that component.
        position: usize,
    },
    /// A CPE component was empty or contained a forbidden control character.
    #[error("invalid CPE component {component}: {reason}")]
    InvalidCpeValue {
        /// The zero-based component index.
        component: usize,
        /// A stable explanation of the failed invariant.
        reason: &'static str,
    },
    /// The CPE part was not application, operating system, hardware, ANY, or NA.
    #[error("invalid CPE part `{value}`")]
    InvalidCpePart {
        /// The invalid decoded part.
        value: String,
    },
    /// A legacy CPE URI failed strict dependency parsing.
    #[error("invalid legacy CPE URI: {reason}")]
    InvalidLegacyCpe {
        /// A dependency-independent explanation of the parse failure.
        reason: String,
    },
    /// The input was neither a Package URL nor a supported CPE name.
    #[error(
        "unsupported subject identifier; expected a `pkg:` Package URL or supported CPE binding"
    )]
    UnsupportedSubjectId,
}

/// A canonical Package URL suitable for equality, ordering, and stable keys.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedPurl {
    canonical: String,
    full_identity: String,
    coordinate: String,
    ty: String,
    namespace: Option<String>,
    name: String,
    version: Option<String>,
    qualifiers: Box<[(String, String)]>,
    subpath: Option<String>,
}

impl NormalizedPurl {
    /// Parses a Package URL and returns its canonical representation.
    ///
    /// In addition to the `packageurl` parser, this rejects malformed percent
    /// escapes and ambiguous qualifiers that the dependency would otherwise
    /// discard or overwrite.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] when the Package URL is invalid or lossy.
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        prevalidate_purl(value)?;
        let parsed =
            value
                .parse::<PackageUrl<'static>>()
                .map_err(|error| IdentityError::InvalidPurl {
                    reason: error.to_string(),
                })?;

        let canonical = parsed.to_string();
        let full_identity = format!("{PURL_IDENTITY_PREFIX}{canonical}");

        let mut coordinate_value = parsed.clone();
        coordinate_value.without_version();
        coordinate_value.clear_qualifiers();
        coordinate_value.without_subpath();
        let coordinate = coordinate_value.to_string();

        let mut qualifiers = parsed
            .qualifiers()
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<Vec<_>>();
        qualifiers.sort_unstable();

        Ok(Self {
            canonical,
            full_identity,
            coordinate,
            ty: parsed.ty().to_owned(),
            namespace: parsed.namespace().map(str::to_owned),
            name: parsed.name().to_owned(),
            version: parsed.version().map(str::to_owned),
            qualifiers: qualifiers.into_boxed_slice(),
            subpath: parsed.subpath().map(str::to_owned),
        })
    }

    /// Returns the canonical Package URL string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Returns the canonical Package URL type.
    #[must_use]
    pub fn ty(&self) -> &str {
        &self.ty
    }

    /// Returns the optional canonical namespace.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Returns the package name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional package version.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Iterates over canonical qualifier keys and decoded values in sorted order.
    pub fn qualifiers(&self) -> impl ExactSizeIterator<Item = (&str, &str)> + '_ {
        self.qualifiers
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    /// Returns the optional package subpath.
    #[must_use]
    pub fn subpath(&self) -> Option<&str> {
        self.subpath.as_deref()
    }

    pub(crate) fn full_identity(&self) -> &str {
        &self.full_identity
    }

    /// Returns the canonical package coordinate without version, qualifiers, or subpath.
    #[must_use]
    pub fn coordinate(&self) -> &str {
        &self.coordinate
    }

    pub(crate) fn subject_name(&self) -> &str {
        &self.name
    }
}

impl FromStr for NormalizedPurl {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl AsRef<str> for NormalizedPurl {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for NormalizedPurl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A canonical, binding-independent CPE name.
///
/// Output always uses the common CPE 2.3 formatted-string binding, including
/// all eleven components. Legacy `cpe:/` inputs are decoded semantically and
/// never formatted through the `cpe` dependency's non-round-trippable display.
/// Component accessors return decoded text; [`Self::as_str`], equality, and
/// hashing preserve the distinction between wildcards and quoted literals.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedCpe {
    canonical: String,
    full_identity: String,
    coordinate: String,
    fields: Box<[CpeField; CPE23_COMPONENT_COUNT]>,
}

impl NormalizedCpe {
    /// Parses a CPE 2.3 formatted string or legacy CPE 2.2 URI.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] for unsupported bindings, malformed escaping,
    /// invalid component counts, invalid parts, or invalid legacy URI values.
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        let fields = if let Some(body) = value.strip_prefix(CPE23_PREFIX) {
            parse_formatted_cpe(body)?
        } else if legacy_cpe_body(value).is_some() {
            parse_legacy_cpe(value)?
        } else {
            return Err(IdentityError::UnsupportedCpeBinding);
        };
        Self::from_fields(fields)
    }

    fn from_fields(mut fields: [CpeField; CPE23_COMPONENT_COUNT]) -> Result<Self, IdentityError> {
        validate_part(&fields[PART])?;
        validate_language(&fields[LANGUAGE])?;
        for field in &mut fields {
            field.make_ascii_lowercase();
        }
        let canonical = format_cpe(&fields);
        let full_identity = format!("{CPE_IDENTITY_PREFIX}{canonical}");

        let mut coordinate_fields = std::array::from_fn(|_| CpeField::Any);
        coordinate_fields[PART] = fields[PART].clone();
        coordinate_fields[VENDOR] = fields[VENDOR].clone();
        coordinate_fields[PRODUCT] = fields[PRODUCT].clone();
        let coordinate = format_cpe(&coordinate_fields);

        Ok(Self {
            canonical,
            full_identity,
            coordinate,
            fields: Box::new(fields),
        })
    }

    /// Returns the canonical CPE 2.3 formatted string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Returns the part component (`a`, `o`, `h`, `*`, or `-`).
    #[must_use]
    pub fn part(&self) -> &str {
        self.fields[PART].as_str()
    }

    /// Returns the vendor component.
    #[must_use]
    pub fn vendor(&self) -> &str {
        self.fields[VENDOR].as_str()
    }

    /// Returns the product component.
    #[must_use]
    pub fn product(&self) -> &str {
        self.fields[PRODUCT].as_str()
    }

    /// Returns the decoded version component, including `*` or `-` logical values.
    ///
    /// A wildcard `*` and a quoted literal `\*` both appear as `*` through
    /// this accessor. Their distinct semantics remain visible in [`Self::as_str`]
    /// and participate in equality and hashing.
    #[must_use]
    pub fn version_component(&self) -> &str {
        self.fields[VERSION].as_str()
    }

    /// Returns a concrete version, or `None` for ANY and NA.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.fields[VERSION].concrete()
    }

    /// Returns the update component.
    #[must_use]
    pub fn update(&self) -> &str {
        self.fields[UPDATE].as_str()
    }

    /// Returns the edition component.
    #[must_use]
    pub fn edition(&self) -> &str {
        self.fields[EDITION].as_str()
    }

    /// Returns the language component.
    #[must_use]
    pub fn language(&self) -> &str {
        self.fields[LANGUAGE].as_str()
    }

    /// Returns the software-edition component.
    #[must_use]
    pub fn sw_edition(&self) -> &str {
        self.fields[SW_EDITION].as_str()
    }

    /// Returns the target-software component.
    #[must_use]
    pub fn target_sw(&self) -> &str {
        self.fields[TARGET_SW].as_str()
    }

    /// Returns the target-hardware component.
    #[must_use]
    pub fn target_hw(&self) -> &str {
        self.fields[TARGET_HW].as_str()
    }

    /// Returns the other component.
    #[must_use]
    pub fn other(&self) -> &str {
        self.fields[OTHER].as_str()
    }

    pub(crate) fn full_identity(&self) -> &str {
        &self.full_identity
    }

    /// Returns the canonical CPE coordinate containing part, vendor, and product.
    #[must_use]
    pub fn coordinate(&self) -> &str {
        &self.coordinate
    }

    pub(crate) fn subject_name(&self) -> &str {
        self.fields[PRODUCT].concrete().unwrap_or("")
    }
}

impl FromStr for NormalizedCpe {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl AsRef<str> for NormalizedCpe {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for NormalizedCpe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A normalized structured identifier for a finding subject.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SubjectId {
    /// A Package URL identifier.
    Purl(NormalizedPurl),
    /// A CPE identifier.
    Cpe(NormalizedCpe),
}

impl SubjectId {
    /// Parses a Package URL or supported CPE binding based on its prefix.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] when the prefix is unsupported or the selected
    /// identifier parser rejects the value.
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        if value.starts_with("pkg:") {
            NormalizedPurl::parse(value).map(Self::Purl)
        } else if value.starts_with(CPE23_PREFIX) || legacy_cpe_body(value).is_some() {
            NormalizedCpe::parse(value).map(Self::Cpe)
        } else {
            Err(IdentityError::UnsupportedSubjectId)
        }
    }

    /// Returns the canonical identifier without its internal key-domain prefix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Purl(value) => value.as_str(),
            Self::Cpe(value) => value.as_str(),
        }
    }

    /// Returns the Package URL when this is a PURL identifier.
    #[must_use]
    pub fn as_purl(&self) -> Option<&NormalizedPurl> {
        match self {
            Self::Purl(value) => Some(value),
            Self::Cpe(_) => None,
        }
    }

    /// Returns the CPE when this is a CPE identifier.
    #[must_use]
    pub fn as_cpe(&self) -> Option<&NormalizedCpe> {
        match self {
            Self::Cpe(value) => Some(value),
            Self::Purl(_) => None,
        }
    }

    pub(crate) fn kind_tag(&self) -> &'static str {
        match self {
            Self::Purl(_) => "purl",
            Self::Cpe(_) => "cpe",
        }
    }

    pub(crate) fn full_identity(&self) -> &str {
        match self {
            Self::Purl(value) => value.full_identity(),
            Self::Cpe(value) => value.full_identity(),
        }
    }

    /// Returns the versionless package or product coordinate used for blocking.
    #[must_use]
    pub fn coordinate(&self) -> &str {
        match self {
            Self::Purl(value) => value.coordinate(),
            Self::Cpe(value) => value.coordinate(),
        }
    }

    pub(crate) fn version(&self) -> Option<&str> {
        match self {
            Self::Purl(value) => value.version(),
            Self::Cpe(value) => value.version(),
        }
    }

    pub(crate) fn subject_name(&self) -> &str {
        match self {
            Self::Purl(value) => value.subject_name(),
            Self::Cpe(value) => value.subject_name(),
        }
    }

    /// Returns whether two identifiers can describe the same structured subject
    /// without any of their concrete details contradicting each other.
    pub(crate) fn details_compatible(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Purl(left), Self::Purl(right)) => {
                left.coordinate == right.coordinate
                    && optional_detail_compatible(left.version(), right.version())
                    && optional_detail_compatible(left.subpath(), right.subpath())
                    && left.qualifiers.iter().all(|(left_key, left_value)| {
                        right
                            .qualifiers
                            .iter()
                            .find(|(right_key, _)| right_key == left_key)
                            .is_none_or(|(_, right_value)| right_value == left_value)
                    })
            }
            (Self::Cpe(left), Self::Cpe(right)) => {
                left.coordinate == right.coordinate
                    && left.fields[VERSION..]
                        .iter()
                        .zip(&right.fields[VERSION..])
                        .all(|(left, right)| {
                            matches!(left, CpeField::Any)
                                || matches!(right, CpeField::Any)
                                || left == right
                        })
            }
            (Self::Purl(_), Self::Cpe(_)) | (Self::Cpe(_), Self::Purl(_)) => false,
        }
    }
}

fn optional_detail_compatible(left: Option<&str>, right: Option<&str>) -> bool {
    left.zip(right).is_none_or(|(left, right)| left == right)
}

impl From<NormalizedPurl> for SubjectId {
    fn from(value: NormalizedPurl) -> Self {
        Self::Purl(value)
    }
}

impl From<NormalizedCpe> for SubjectId {
    fn from(value: NormalizedCpe) -> Self {
        Self::Cpe(value)
    }
}

impl FromStr for SubjectId {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl AsRef<str> for SubjectId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SubjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum CpeField {
    Any,
    NotApplicable,
    Value(CpeValue),
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct CpeValue {
    decoded: String,
    atoms: Box<[CpeAtom]>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum CpeAtom {
    Literal(char),
    WildcardOne,
    WildcardMany,
}

impl CpeField {
    fn as_str(&self) -> &str {
        match self {
            Self::Any => "*",
            Self::NotApplicable => "-",
            Self::Value(value) => &value.decoded,
        }
    }

    fn concrete(&self) -> Option<&str> {
        match self {
            Self::Value(value) => Some(&value.decoded),
            Self::Any | Self::NotApplicable => None,
        }
    }

    fn push_formatted(&self, output: &mut String) {
        match self {
            Self::Any => output.push('*'),
            Self::NotApplicable => output.push('-'),
            Self::Value(value) => value.push_formatted(output),
        }
    }

    fn make_ascii_lowercase(&mut self) {
        if let Self::Value(value) = self {
            value.make_ascii_lowercase();
        }
    }
}

impl CpeValue {
    fn from_formatted(raw: &str, component: usize) -> Result<Self, IdentityError> {
        let mut atoms = Vec::with_capacity(raw.len());
        let mut characters = raw.char_indices();
        while let Some((position, character)) = characters.next() {
            match character {
                '\\' => {
                    let (_, quoted) = characters.next().ok_or(IdentityError::InvalidCpeEscape {
                        component,
                        position,
                    })?;
                    if !is_quoted_character(quoted) {
                        return Err(IdentityError::InvalidCpeValue {
                            component,
                            reason: "only backslash, wildcard, and punctuation characters may be quoted",
                        });
                    }
                    atoms.push(CpeAtom::Literal(quoted));
                }
                '?' => atoms.push(CpeAtom::WildcardOne),
                '*' => atoms.push(CpeAtom::WildcardMany),
                character if is_cpe_unreserved(character) => {
                    atoms.push(CpeAtom::Literal(character));
                }
                _ => {
                    return Err(IdentityError::InvalidCpeValue {
                        component,
                        reason: "non-alphanumeric punctuation must be quoted",
                    });
                }
            }
        }

        validate_wildcards(&atoms, component)?;
        Ok(Self::from_atoms(atoms))
    }

    fn from_legacy_encoded(
        raw: &str,
        decoded: &str,
        component: usize,
    ) -> Result<Self, IdentityError> {
        let mut atoms = Vec::with_capacity(raw.len());
        let mut index = 0;
        while index < raw.len() {
            if raw.as_bytes()[index] == b'%' {
                let encoded = raw.as_bytes().get(index + 1..index + 3).ok_or_else(|| {
                    IdentityError::InvalidLegacyCpe {
                        reason: format!(
                            "component {component} contains an incomplete percent encoding"
                        ),
                    }
                })?;
                let byte =
                    decode_hex_pair(encoded).ok_or_else(|| IdentityError::InvalidLegacyCpe {
                        reason: format!(
                            "component {component} contains an invalid percent encoding"
                        ),
                    })?;
                match byte {
                    0x01 => atoms.push(CpeAtom::WildcardOne),
                    0x02 => atoms.push(CpeAtom::WildcardMany),
                    byte if byte.is_ascii() => {
                        push_legacy_literal(&mut atoms, char::from(byte), component)?;
                    }
                    _ => {
                        return Err(IdentityError::InvalidLegacyCpe {
                            reason: format!(
                                "component {component} contains a non-ASCII percent encoding"
                            ),
                        });
                    }
                }
                index += 3;
            } else {
                let character =
                    raw[index..]
                        .chars()
                        .next()
                        .ok_or_else(|| IdentityError::InvalidLegacyCpe {
                            reason: format!("component {component} could not be decoded"),
                        })?;
                push_legacy_literal(&mut atoms, character, component)?;
                index += character.len_utf8();
            }
        }

        validate_wildcards(&atoms, component)?;
        let value = Self::from_atoms(atoms);
        if value.decoded != decoded {
            return Err(IdentityError::InvalidLegacyCpe {
                reason: format!(
                    "component {component} raw encoding disagrees with the validated legacy value"
                ),
            });
        }
        if value.atoms.as_ref() == [CpeAtom::Literal('-')] {
            return Err(IdentityError::InvalidLegacyCpe {
                reason: format!(
                    "component {component} is a literal hyphen that cannot be represented without colliding with CPE NA"
                ),
            });
        }
        Ok(value)
    }

    fn from_unreserved(value: &'static str) -> Self {
        Self::from_atoms(value.chars().map(CpeAtom::Literal).collect())
    }

    fn from_atoms(atoms: Vec<CpeAtom>) -> Self {
        let decoded = atoms
            .iter()
            .map(|atom| match atom {
                CpeAtom::Literal(character) => *character,
                CpeAtom::WildcardOne => '?',
                CpeAtom::WildcardMany => '*',
            })
            .collect();
        Self {
            decoded,
            atoms: atoms.into_boxed_slice(),
        }
    }

    fn push_formatted(&self, output: &mut String) {
        for atom in &self.atoms {
            match atom {
                CpeAtom::Literal(character) => {
                    if !is_cpe_unreserved(*character) {
                        output.push('\\');
                    }
                    output.push(*character);
                }
                CpeAtom::WildcardOne => output.push('?'),
                CpeAtom::WildcardMany => output.push('*'),
            }
        }
    }

    fn make_ascii_lowercase(&mut self) {
        self.decoded.make_ascii_lowercase();
        for atom in &mut self.atoms {
            if let CpeAtom::Literal(character) = atom {
                *character = character.to_ascii_lowercase();
            }
        }
    }
}

fn decode_hex_pair(pair: &[u8]) -> Option<u8> {
    let [high, low] = pair else {
        return None;
    };
    Some(decode_hex_digit(*high)? << 4 | decode_hex_digit(*low)?)
}

fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn push_legacy_literal(
    atoms: &mut Vec<CpeAtom>,
    character: char,
    component: usize,
) -> Result<(), IdentityError> {
    if is_cpe_unreserved(character) || is_quoted_character(character) {
        atoms.push(CpeAtom::Literal(character));
        Ok(())
    } else {
        Err(IdentityError::InvalidLegacyCpe {
            reason: format!(
                "component {component} contains character {character:?} that cannot be represented by the CPE 2.3 formatted binding"
            ),
        })
    }
}

fn prevalidate_purl(value: &str) -> Result<(), IdentityError> {
    validate_percent_escapes(value)?;

    let question_positions = value
        .match_indices('?')
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let fragment_positions = value
        .match_indices('#')
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if question_positions.len() > 1 || fragment_positions.len() > 1 {
        return Err(IdentityError::InvalidPurl {
            reason: "query and fragment delimiters may occur at most once".to_owned(),
        });
    }

    let question = question_positions.first().copied();
    let fragment = fragment_positions.first().copied();
    if question
        .zip(fragment)
        .is_some_and(|(query, subpath)| query > subpath)
    {
        return Err(IdentityError::InvalidPurl {
            reason: "qualifiers must precede the subpath".to_owned(),
        });
    }

    let identity_end = question.or(fragment).unwrap_or(value.len());
    if value[..identity_end]
        .rfind('@')
        .is_some_and(|index| index + 1 == identity_end)
    {
        return Err(IdentityError::EmptyPurlVersion);
    }

    if let Some(question) = question {
        let query_end = fragment.unwrap_or(value.len());
        validate_purl_qualifiers(&value[question + 1..query_end])?;
    }
    Ok(())
}

fn validate_percent_escapes(value: &str) -> Result<(), IdentityError> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(IdentityError::InvalidPercentEscape { position: index });
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn validate_purl_qualifiers(query: &str) -> Result<(), IdentityError> {
    let mut keys = HashSet::new();
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(IdentityError::InvalidPurlQualifier {
                qualifier: pair.to_owned(),
            });
        };
        if key.is_empty() {
            return Err(IdentityError::InvalidPurlQualifier {
                qualifier: pair.to_owned(),
            });
        }
        if value.is_empty() {
            return Err(IdentityError::EmptyPurlQualifierValue {
                key: key.to_owned(),
            });
        }
        let normalized = key.to_ascii_lowercase();
        if !keys.insert(normalized.clone()) {
            return Err(IdentityError::DuplicatePurlQualifier { key: normalized });
        }
    }
    Ok(())
}

fn parse_formatted_cpe(body: &str) -> Result<[CpeField; CPE23_COMPONENT_COUNT], IdentityError> {
    let raw_fields = split_formatted_cpe(body)?;
    if raw_fields.len() != CPE23_COMPONENT_COUNT {
        return Err(IdentityError::CpeComponentCount {
            expected: CPE23_COMPONENT_COUNT,
            actual: raw_fields.len(),
        });
    }

    let fields = raw_fields
        .iter()
        .enumerate()
        .map(|(index, field)| parse_formatted_field(field, index))
        .collect::<Result<Vec<_>, _>>()?;
    fields
        .try_into()
        .map_err(|fields: Vec<CpeField>| IdentityError::CpeComponentCount {
            expected: CPE23_COMPONENT_COUNT,
            actual: fields.len(),
        })
}

fn split_formatted_cpe(body: &str) -> Result<Vec<String>, IdentityError> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    let mut escape_position = 0;

    for character in body.chars() {
        if escaped {
            current.push('\\');
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
            escape_position = current.len();
        } else if character == ':' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
    }

    if escaped {
        return Err(IdentityError::InvalidCpeEscape {
            component: fields.len(),
            position: escape_position,
        });
    }
    fields.push(current);
    Ok(fields)
}

fn parse_formatted_field(raw: &str, component: usize) -> Result<CpeField, IdentityError> {
    match raw {
        "*" => return Ok(CpeField::Any),
        "-" => return Ok(CpeField::NotApplicable),
        "" => {
            return Err(IdentityError::InvalidCpeValue {
                component,
                reason: "formatted components must not be empty",
            });
        }
        _ => {}
    }

    CpeValue::from_formatted(raw, component).map(CpeField::Value)
}

fn parse_legacy_cpe(value: &str) -> Result<[CpeField; CPE23_COMPONENT_COUNT], IdentityError> {
    let body = legacy_cpe_body(value).ok_or(IdentityError::UnsupportedCpeBinding)?;
    let raw_components = body.split(':').collect::<Vec<_>>();
    let actual = raw_components.len();
    if actual > CPE22_MAX_COMPONENT_COUNT {
        return Err(IdentityError::LegacyCpeComponentCount {
            maximum: CPE22_MAX_COMPONENT_COUNT,
            actual,
        });
    }

    let uri = Uri::parse(value).map_err(|error| IdentityError::InvalidLegacyCpe {
        reason: error.to_string(),
    })?;
    let raw_fields = legacy_raw_fields(&raw_components)?;

    Ok([
        legacy_part(uri.part()),
        legacy_component(uri.vendor(), raw_fields[VENDOR], VENDOR)?,
        legacy_component(uri.product(), raw_fields[PRODUCT], PRODUCT)?,
        legacy_component(uri.version(), raw_fields[VERSION], VERSION)?,
        legacy_component(uri.update(), raw_fields[UPDATE], UPDATE)?,
        legacy_component(uri.edition(), raw_fields[EDITION], EDITION)?,
        legacy_language(uri.language(), raw_fields[LANGUAGE])?,
        legacy_component(uri.sw_edition(), raw_fields[SW_EDITION], SW_EDITION)?,
        legacy_component(uri.target_sw(), raw_fields[TARGET_SW], TARGET_SW)?,
        legacy_component(uri.target_hw(), raw_fields[TARGET_HW], TARGET_HW)?,
        legacy_component(uri.other(), raw_fields[OTHER], OTHER)?,
    ])
}

fn legacy_raw_fields<'a>(
    components: &[&'a str],
) -> Result<[&'a str; CPE23_COMPONENT_COUNT], IdentityError> {
    let mut fields = [""; CPE23_COMPONENT_COUNT];
    for (index, field) in fields.iter_mut().enumerate().take(UPDATE + 1) {
        *field = components.get(index).copied().unwrap_or_default();
    }

    let edition = components.get(EDITION).copied().unwrap_or_default();
    if edition.starts_with('~') {
        let packed = edition.split('~').collect::<Vec<_>>();
        if packed.len() != 6 || !packed[0].is_empty() {
            return Err(IdentityError::InvalidLegacyCpe {
                reason: "validated packed edition did not contain five fields".to_owned(),
            });
        }
        fields[EDITION] = packed[1];
        fields[SW_EDITION] = packed[2];
        fields[TARGET_SW] = packed[3];
        fields[TARGET_HW] = packed[4];
        fields[OTHER] = packed[5];
    } else {
        fields[EDITION] = edition;
    }
    fields[LANGUAGE] = components.get(LANGUAGE).copied().unwrap_or_default();
    Ok(fields)
}

fn legacy_cpe_body(value: &str) -> Option<&str> {
    value
        .strip_prefix("cpe:/")
        .or_else(|| value.strip_prefix("x-cpe:/"))
        .or_else(|| value.strip_prefix("p-cpe:/"))
}

fn legacy_part(value: CpeType) -> CpeField {
    match value {
        CpeType::Application => CpeField::Value(CpeValue::from_unreserved("a")),
        CpeType::OperatingSystem => CpeField::Value(CpeValue::from_unreserved("o")),
        CpeType::Hardware => CpeField::Value(CpeValue::from_unreserved("h")),
        CpeType::Any | CpeType::Empty => CpeField::Any,
    }
}

fn legacy_component(
    value: Component<'_>,
    raw: &str,
    component: usize,
) -> Result<CpeField, IdentityError> {
    match value {
        Component::Any => Ok(CpeField::Any),
        Component::NotApplicable => Ok(CpeField::NotApplicable),
        Component::Value(value) => {
            CpeValue::from_legacy_encoded(raw, &value, component).map(CpeField::Value)
        }
    }
}

fn legacy_language(value: &Language, raw: &str) -> Result<CpeField, IdentityError> {
    match value {
        Language::Any => Ok(CpeField::Any),
        Language::Language(value) => {
            let decoded = value.to_string();
            CpeValue::from_legacy_encoded(raw, &decoded, LANGUAGE).map(CpeField::Value)
        }
    }
}

fn validate_part(value: &CpeField) -> Result<(), IdentityError> {
    match value {
        CpeField::Any | CpeField::NotApplicable => Ok(()),
        CpeField::Value(value) if matches!(value.decoded.as_str(), "a" | "o" | "h") => Ok(()),
        CpeField::Value(value) => Err(IdentityError::InvalidCpePart {
            value: value.decoded.clone(),
        }),
    }
}

fn validate_language(value: &CpeField) -> Result<(), IdentityError> {
    let CpeField::Value(value) = value else {
        return Ok(());
    };

    let mut subtags = value.decoded.split('-');
    let language = subtags.next().unwrap_or_default();
    let region = subtags.next();
    let valid_language =
        matches!(language.len(), 2 | 3) && language.bytes().all(|byte| byte.is_ascii_alphabetic());
    let valid_region = region.is_none_or(|region| {
        (region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_alphabetic()))
            || (region.len() == 3 && region.bytes().all(|byte| byte.is_ascii_digit()))
    });

    if valid_language && valid_region && subtags.next().is_none() {
        Ok(())
    } else {
        Err(IdentityError::InvalidCpeValue {
            component: LANGUAGE,
            reason: "language must be a two- or three-letter tag with an optional region",
        })
    }
}

fn validate_wildcards(atoms: &[CpeAtom], component: usize) -> Result<(), IdentityError> {
    let first_literal = atoms
        .iter()
        .position(|atom| matches!(atom, CpeAtom::Literal(_)))
        .ok_or(IdentityError::InvalidCpeValue {
            component,
            reason: "a non-logical value must contain at least one literal character",
        })?;
    let last_literal = atoms
        .iter()
        .rposition(|atom| matches!(atom, CpeAtom::Literal(_)))
        .ok_or(IdentityError::InvalidCpeValue {
            component,
            reason: "a non-logical value must contain at least one literal character",
        })?;

    if atoms[first_literal..=last_literal]
        .iter()
        .any(|atom| !matches!(atom, CpeAtom::Literal(_)))
    {
        return Err(IdentityError::InvalidCpeValue {
            component,
            reason: "wildcards may appear only at the beginning or end of a value",
        });
    }

    validate_wildcard_edge(&atoms[..first_literal], component)?;
    validate_wildcard_edge(&atoms[last_literal + 1..], component)
}

fn validate_wildcard_edge(atoms: &[CpeAtom], component: usize) -> Result<(), IdentityError> {
    if atoms.is_empty()
        || atoms
            .iter()
            .all(|atom| matches!(atom, CpeAtom::WildcardOne))
        || (atoms.len() == 1 && matches!(atoms[0], CpeAtom::WildcardMany))
    {
        Ok(())
    } else {
        Err(IdentityError::InvalidCpeValue {
            component,
            reason: "each wildcard edge must be either question marks or one asterisk",
        })
    }
}

fn is_cpe_unreserved(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_')
}

fn is_cpe_punctuation(character: char) -> bool {
    matches!(
        character,
        '!' | '"'
            | '#'
            | '$'
            | '%'
            | '&'
            | '\''
            | '('
            | ')'
            | '+'
            | ','
            | '/'
            | ':'
            | ';'
            | '<'
            | '='
            | '>'
            | '@'
            | '['
            | ']'
            | '^'
            | '`'
            | '{'
            | '|'
            | '}'
            | '~'
    )
}

fn is_quoted_character(character: char) -> bool {
    character == '\\' || matches!(character, '*' | '?') || is_cpe_punctuation(character)
}

fn format_cpe(fields: &[CpeField; CPE23_COMPONENT_COUNT]) -> String {
    let mut output = String::with_capacity(
        CPE23_PREFIX.len()
            + fields
                .iter()
                .map(|field| field.as_str().len() + 1)
                .sum::<usize>(),
    );
    output.push_str(CPE23_PREFIX);
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            output.push(':');
        }
        field.push_formatted(&mut output);
    }
    output
}

#[cfg(feature = "serde")]
macro_rules! serde_string {
    ($type:ty) => {
        impl serde::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = <String as serde::Deserialize>::deserialize(deserializer)?;
                Self::parse(&value).map_err(serde::de::Error::custom)
            }
        }
    };
}

#[cfg(feature = "serde")]
serde_string!(NormalizedPurl);
#[cfg(feature = "serde")]
serde_string!(NormalizedCpe);
#[cfg(feature = "serde")]
serde_string!(SubjectId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purl_canonicalizes_type_namespaces_names_and_qualifiers() {
        let purl = NormalizedPurl::parse("pkg:GITHUB/Package-URL/Purl-Spec@1?Z=two&a=one").unwrap();

        assert_eq!(
            purl.as_str(),
            "pkg:github/package-url/purl-spec@1?a=one&z=two"
        );
    }

    #[test]
    fn purl_exposes_sorted_components_and_versionless_coordinate() {
        let purl = NormalizedPurl::parse(
            "pkg:deb/debian/xz-utils@5.6.1?distro=bookworm&arch=amd64#src/lib",
        )
        .unwrap();

        assert_eq!(purl.ty(), "deb");
        assert_eq!(purl.namespace(), Some("debian"));
        assert_eq!(purl.name(), "xz-utils");
        assert_eq!(purl.version(), Some("5.6.1"));
        assert_eq!(purl.subpath(), Some("src/lib"));
        assert_eq!(
            purl.qualifiers().collect::<Vec<_>>(),
            [("arch", "amd64"), ("distro", "bookworm")]
        );
        assert_eq!(purl.coordinate(), "pkg:deb/debian/xz-utils");
    }

    #[test]
    fn purl_rejects_malformed_percent_escape() {
        let error = NormalizedPurl::parse("pkg:generic/widget%ZZ@1").unwrap_err();

        assert_eq!(error, IdentityError::InvalidPercentEscape { position: 18 });
    }

    #[test]
    fn purl_rejects_empty_version() {
        assert_eq!(
            NormalizedPurl::parse("pkg:generic/widget@").unwrap_err(),
            IdentityError::EmptyPurlVersion
        );
    }

    #[test]
    fn purl_rejects_empty_qualifier_value() {
        assert_eq!(
            NormalizedPurl::parse("pkg:generic/widget?arch=").unwrap_err(),
            IdentityError::EmptyPurlQualifierValue {
                key: "arch".to_owned()
            }
        );
    }

    #[test]
    fn purl_rejects_bare_qualifier() {
        assert_eq!(
            NormalizedPurl::parse("pkg:generic/widget?arch").unwrap_err(),
            IdentityError::InvalidPurlQualifier {
                qualifier: "arch".to_owned()
            }
        );
    }

    #[test]
    fn purl_rejects_duplicate_qualifiers_after_case_normalization() {
        assert_eq!(
            NormalizedPurl::parse("pkg:generic/widget?Arch=x86&arch=arm64").unwrap_err(),
            IdentityError::DuplicatePurlQualifier {
                key: "arch".to_owned()
            }
        );
    }

    #[test]
    fn purl_normalization_is_idempotent() {
        let first = NormalizedPurl::parse("pkg:PYPI/Django_package@1%2bdev").unwrap();
        let second = NormalizedPurl::parse(first.as_str()).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn formatted_cpe_round_trips_all_components() {
        let input = "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:en-us:*:windows:x64:*";
        let cpe = NormalizedCpe::parse(input).unwrap();

        assert_eq!(cpe.as_str(), input);
        assert_eq!(cpe.part(), "a");
        assert_eq!(cpe.vendor(), "microsoft");
        assert_eq!(cpe.product(), "internet_explorer");
        assert_eq!(cpe.version(), Some("8.0.6001"));
        assert_eq!(cpe.update(), "beta");
        assert_eq!(cpe.language(), "en-us");
        assert_eq!(cpe.target_sw(), "windows");
        assert_eq!(cpe.target_hw(), "x64");
    }

    #[test]
    fn formatted_cpe_handles_escaped_colons_and_backslashes() {
        let input = r"cpe:2.3:a:acme:widget\:pro\\edition:1.0:*:*:*:*:*:*:*";
        let cpe = NormalizedCpe::parse(input).unwrap();

        assert_eq!(cpe.product(), r"widget:pro\edition");
        assert_eq!(cpe.as_str(), input);
    }

    #[test]
    fn formatted_cpe_uses_backslash_parity_for_delimiters() {
        let input = r"cpe:2.3:a:foo\\:bar:1:*:*:*:*:*:*:*";
        let cpe = NormalizedCpe::parse(input).unwrap();

        assert_eq!(cpe.vendor(), "foo\\");
        assert_eq!(cpe.product(), "bar");
        assert_eq!(cpe.as_str(), input);
    }

    #[test]
    fn formatted_cpe_rejects_redundant_escapes() {
        let error = NormalizedCpe::parse(r"cpe:2.3:a:acme:wid\get:1.0:*:*:*:*:*:*:*").unwrap_err();

        assert!(matches!(
            error,
            IdentityError::InvalidCpeValue {
                component: PRODUCT,
                ..
            }
        ));
    }

    #[test]
    fn formatted_cpe_preserves_wildcard_and_literal_star_semantics() {
        let wildcard = NormalizedCpe::parse(r"cpe:2.3:a:acme:widget:8.*:sp?:*:*:*:*:*:*").unwrap();
        let literal = NormalizedCpe::parse(r"cpe:2.3:a:acme:widget:8.\*:sp?:*:*:*:*:*:*").unwrap();

        assert_eq!(wildcard.version(), Some("8.*"));
        assert_eq!(literal.version(), Some("8.*"));
        assert_eq!(
            wildcard.as_str(),
            r"cpe:2.3:a:acme:widget:8.*:sp?:*:*:*:*:*:*"
        );
        assert_eq!(
            literal.as_str(),
            r"cpe:2.3:a:acme:widget:8.\*:sp?:*:*:*:*:*:*"
        );
        assert_ne!(wildcard, literal);
    }

    #[test]
    fn formatted_cpe_rejects_embedded_wildcards() {
        let error =
            NormalizedCpe::parse("cpe:2.3:a:acme:widget:8.*.1570:*:*:*:*:*:*:*").unwrap_err();

        assert!(matches!(
            error,
            IdentityError::InvalidCpeValue {
                component: VERSION,
                ..
            }
        ));
    }

    #[test]
    fn formatted_cpe_enforces_wildcard_edge_grammar() {
        let cpe = NormalizedCpe::parse("cpe:2.3:a:acme:widget:??8.0??:*:*:*:*:*:*:*").unwrap();
        let mixed = NormalizedCpe::parse("cpe:2.3:a:acme:widget:?*8.0:*:*:*:*:*:*:*").unwrap_err();
        let repeated_star =
            NormalizedCpe::parse("cpe:2.3:a:acme:widget:8.0**:*:*:*:*:*:*:*").unwrap_err();

        assert_eq!(cpe.as_str(), "cpe:2.3:a:acme:widget:??8.0??:*:*:*:*:*:*:*");
        assert!(matches!(
            mixed,
            IdentityError::InvalidCpeValue {
                component: VERSION,
                ..
            }
        ));
        assert!(matches!(
            repeated_star,
            IdentityError::InvalidCpeValue {
                component: VERSION,
                ..
            }
        ));
    }

    #[test]
    fn formatted_cpe_rejects_bare_question_mark_but_preserves_quoted_literal() {
        let bare = NormalizedCpe::parse("cpe:2.3:a:acme:widget:?:*:*:*:*:*:*:*").unwrap_err();
        let literal =
            NormalizedCpe::parse(r"cpe:2.3:a:micr\?osoft:widget:1:*:*:*:*:*:*:*").unwrap();

        assert!(matches!(
            bare,
            IdentityError::InvalidCpeValue {
                component: VERSION,
                ..
            }
        ));
        assert_eq!(literal.vendor(), "micr?osoft");
        assert_eq!(
            literal.as_str(),
            r"cpe:2.3:a:micr\?osoft:widget:1:*:*:*:*:*:*:*"
        );
    }

    #[test]
    fn formatted_cpe_requires_punctuation_to_be_quoted() {
        let unquoted =
            NormalizedCpe::parse("cpe:2.3:a:acme:big$money_2010:1.0:*:*:*:*:*:*:*").unwrap_err();
        let quoted =
            NormalizedCpe::parse(r"cpe:2.3:a:acme:big\$money_2010:1.0:*:*:*:*:*:*:*").unwrap();

        assert!(matches!(
            unquoted,
            IdentityError::InvalidCpeValue {
                component: PRODUCT,
                ..
            }
        ));
        assert_eq!(quoted.product(), "big$money_2010");
        assert_eq!(
            quoted.as_str(),
            r"cpe:2.3:a:acme:big\$money_2010:1.0:*:*:*:*:*:*:*"
        );
    }

    #[test]
    fn formatted_cpe_accepts_nistir_7695_examples() {
        let examples = [
            "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*",
            "cpe:2.3:a:hp:insight:7.4.0.1570:-:*:*:online:win2003:x64:*",
            "cpe:2.3:a:hp:openview_network_manager:7.51:*:*:*:*:linux:*:*",
            r"cpe:2.3:a:foo\\bar:big\$money_2010:*:*:*:*:special:ipod_touch:80gb:*",
        ];

        for example in examples {
            let cpe = NormalizedCpe::parse(example).unwrap();
            assert_eq!(cpe.as_str(), example);
        }
    }

    #[test]
    fn formatted_cpe_validates_language_tags() {
        let alpha_region =
            NormalizedCpe::parse("cpe:2.3:a:acme:widget:1.0:*:*:en-US:*:*:*:*").unwrap();
        let numeric_region =
            NormalizedCpe::parse("cpe:2.3:a:acme:widget:1.0:*:*:eng-419:*:*:*:*").unwrap();
        let invalid =
            NormalizedCpe::parse("cpe:2.3:a:acme:widget:1.0:*:*:english:*:*:*:*").unwrap_err();

        assert_eq!(alpha_region.language(), "en-us");
        assert_eq!(numeric_region.language(), "eng-419");
        assert!(matches!(
            invalid,
            IdentityError::InvalidCpeValue {
                component: LANGUAGE,
                ..
            }
        ));
    }

    #[test]
    fn formatted_cpe_rejects_wrong_component_count() {
        let error = NormalizedCpe::parse("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*").unwrap_err();

        assert_eq!(
            error,
            IdentityError::CpeComponentCount {
                expected: 11,
                actual: 10
            }
        );
    }

    #[test]
    fn formatted_cpe_rejects_trailing_escape() {
        let error = NormalizedCpe::parse("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:\\").unwrap_err();

        assert!(matches!(error, IdentityError::InvalidCpeEscape { .. }));
    }

    #[test]
    fn formatted_cpe_rejects_invalid_part() {
        assert_eq!(
            NormalizedCpe::parse("cpe:2.3:x:acme:widget:1.0:*:*:*:*:*:*:*").unwrap_err(),
            IdentityError::InvalidCpePart {
                value: "x".to_owned()
            }
        );
    }

    #[test]
    fn cpe_coordinate_preserves_only_type_vendor_and_product() {
        let cpe =
            NormalizedCpe::parse("cpe:2.3:a:acme:widget:1.0:update:edition:en:pro:linux:x64:other")
                .unwrap();

        assert_eq!(cpe.coordinate(), "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*");
    }

    #[test]
    fn legacy_cpe_normalizes_to_common_formatted_binding() {
        let cpe = NormalizedCpe::parse("cpe:/a:microsoft:internet_explorer:8.0.6001:beta").unwrap();

        assert_eq!(
            cpe.as_str(),
            "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*"
        );
    }

    #[test]
    fn legacy_cpe_distinguishes_wildcard_and_literal_encodings() {
        let wildcard =
            NormalizedCpe::parse("cpe:/a:microsoft:internet_explorer:8.%02:sp%01").unwrap();
        let literal =
            NormalizedCpe::parse("cpe:/a:microsoft:internet_explorer:8.%2a:sp%3f").unwrap();

        assert_eq!(
            wildcard.as_str(),
            "cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*"
        );
        assert_eq!(
            literal.as_str(),
            r"cpe:2.3:a:microsoft:internet_explorer:8.\*:sp\?:*:*:*:*:*:*"
        );
        assert_eq!(wildcard.version(), Some("8.*"));
        assert_eq!(literal.version(), Some("8.*"));
        assert_eq!(wildcard.update(), "sp?");
        assert_eq!(literal.update(), "sp?");
        assert_ne!(wildcard, literal);
        assert_eq!(wildcard, NormalizedCpe::parse(wildcard.as_str()).unwrap());
        assert_eq!(literal, NormalizedCpe::parse(literal.as_str()).unwrap());
    }

    #[test]
    fn legacy_packed_edition_expands_to_cpe23_fields() {
        let cpe = NormalizedCpe::parse(
            "cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win2003~x64~",
        )
        .unwrap();

        assert_eq!(
            cpe.as_str(),
            "cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win2003:x64:*"
        );
    }

    #[test]
    fn legacy_packed_edition_preserves_wildcard_and_literal_encodings() {
        let cpe = NormalizedCpe::parse("cpe:/a:hp:insight:7.4:-:~ed%02~pro%01~win%2a~x64%3f~other")
            .unwrap();

        assert_eq!(cpe.edition(), "ed*");
        assert_eq!(cpe.sw_edition(), "pro?");
        assert_eq!(cpe.target_sw(), "win*");
        assert_eq!(cpe.target_hw(), "x64?");
        assert_eq!(
            cpe.as_str(),
            r"cpe:2.3:a:hp:insight:7.4:-:ed*:*:pro?:win\*:x64\?:other"
        );
    }

    #[test]
    fn legacy_vendor_prefix_is_removed_by_normalization() {
        let plain = NormalizedCpe::parse("cpe:/a:acme:widget:1.0").unwrap();
        let prefixed = NormalizedCpe::parse("x-cpe:/a:acme:widget:1.0").unwrap();

        assert_eq!(plain, prefixed);
    }

    #[test]
    fn legacy_cpe_rejects_fields_the_dependency_would_ignore() {
        let error =
            NormalizedCpe::parse("cpe:/a:acme:widget:1.0:update:edition:en:ignored").unwrap_err();

        assert_eq!(
            error,
            IdentityError::LegacyCpeComponentCount {
                maximum: 7,
                actual: 8
            }
        );
    }

    #[test]
    fn legacy_and_formatted_bindings_have_equal_semantics() {
        let legacy = NormalizedCpe::parse("cpe:/a:acme:widget:1.0").unwrap();
        let formatted = NormalizedCpe::parse("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*").unwrap();

        assert_eq!(legacy, formatted);
    }

    #[test]
    fn formatted_and_legacy_cpe_values_compare_case_insensitively() {
        let legacy = NormalizedCpe::parse("cpe:/a:microsoft:internet_explorer:8.0:beta").unwrap();
        let formatted =
            NormalizedCpe::parse("cpe:2.3:a:MICROSOFT:Internet_Explorer:8.0:BETA:*:*:*:*:*:*")
                .unwrap();

        assert_eq!(legacy, formatted);
        assert_eq!(
            formatted.as_str(),
            "cpe:2.3:a:microsoft:internet_explorer:8.0:beta:*:*:*:*:*:*"
        );
    }

    #[test]
    fn cpe_normalization_is_idempotent() {
        let first = NormalizedCpe::parse("cpe:/a:acme:widget:1.0").unwrap();
        let second = NormalizedCpe::parse(first.as_str()).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn subject_id_dispatches_and_domain_separates_identifiers() {
        let purl = SubjectId::parse("pkg:generic/widget@1").unwrap();
        let cpe = SubjectId::parse("cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*").unwrap();

        assert_eq!(purl.kind_tag(), "purl");
        assert_eq!(cpe.kind_tag(), "cpe");
        assert!(purl.full_identity().starts_with(PURL_IDENTITY_PREFIX));
        assert!(cpe.full_identity().starts_with(CPE_IDENTITY_PREFIX));
        assert_ne!(purl.full_identity(), cpe.full_identity());
    }

    #[test]
    fn subject_id_exposes_engine_helpers() {
        let subject = SubjectId::parse("pkg:npm/%40scope/widget@2.0.0").unwrap();

        assert_eq!(subject.coordinate(), "pkg:npm/%40scope/widget");
        assert_eq!(subject.version(), Some("2.0.0"));
        assert_eq!(subject.subject_name(), "widget");
    }

    #[test]
    fn purl_detail_compatibility_rejects_only_overlapping_conflicts() {
        let unspecified = SubjectId::parse("pkg:generic/widget").unwrap();
        let version_one = SubjectId::parse("pkg:generic/widget@1").unwrap();
        let version_two = SubjectId::parse("pkg:generic/widget@2").unwrap();
        let arch = SubjectId::parse("pkg:generic/widget?arch=x86_64").unwrap();
        let arch_with_distro =
            SubjectId::parse("pkg:generic/widget?arch=x86_64&distro=bookworm").unwrap();
        let other_arch = SubjectId::parse("pkg:generic/widget?arch=aarch64").unwrap();
        let distro = SubjectId::parse("pkg:generic/widget?distro=bookworm").unwrap();
        let source = SubjectId::parse("pkg:generic/widget#src/lib").unwrap();
        let binary = SubjectId::parse("pkg:generic/widget#bin/widget").unwrap();
        let other_coordinate = SubjectId::parse("pkg:generic/other@1").unwrap();

        assert!(unspecified.details_compatible(&version_one));
        assert!(version_one.details_compatible(&unspecified));
        assert!(!version_one.details_compatible(&version_two));
        assert!(arch.details_compatible(&arch_with_distro));
        assert!(arch.details_compatible(&distro));
        assert!(!arch.details_compatible(&other_arch));
        assert!(unspecified.details_compatible(&source));
        assert!(!source.details_compatible(&binary));
        assert!(!version_one.details_compatible(&other_coordinate));
    }

    #[test]
    fn cpe_detail_compatibility_is_conservative_about_concrete_values() {
        let any = SubjectId::parse("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*").unwrap();
        let version_one = SubjectId::parse("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*").unwrap();
        let version_one_again =
            SubjectId::parse("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*").unwrap();
        let version_two = SubjectId::parse("cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*").unwrap();
        let not_applicable = SubjectId::parse("cpe:2.3:a:acme:widget:-:*:*:*:*:*:*:*").unwrap();
        let wildcard = SubjectId::parse("cpe:2.3:a:acme:widget:1.*:*:*:*:*:*:*:*").unwrap();
        let wildcard_again = SubjectId::parse("cpe:2.3:a:acme:widget:1.*:*:*:*:*:*:*:*").unwrap();
        let literal_star = SubjectId::parse(r"cpe:2.3:a:acme:widget:1.\*:*:*:*:*:*:*:*").unwrap();
        let other_coordinate = SubjectId::parse("cpe:2.3:a:acme:gadget:1.0:*:*:*:*:*:*:*").unwrap();

        assert!(any.details_compatible(&version_one));
        assert!(version_one.details_compatible(&any));
        assert!(version_one.details_compatible(&version_one_again));
        assert!(!version_one.details_compatible(&version_two));
        assert!(any.details_compatible(&not_applicable));
        assert!(!not_applicable.details_compatible(&version_one));
        assert!(wildcard.details_compatible(&wildcard_again));
        assert!(!wildcard.details_compatible(&version_one));
        assert!(!wildcard.details_compatible(&literal_star));
        assert!(!version_one.details_compatible(&other_coordinate));
    }

    #[test]
    fn subject_detail_compatibility_requires_the_same_identifier_kind() {
        let purl = SubjectId::parse("pkg:generic/widget@1").unwrap();
        let cpe = SubjectId::parse("cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*").unwrap();

        assert!(!purl.details_compatible(&cpe));
        assert!(!cpe.details_compatible(&purl));
    }

    #[test]
    fn subject_id_rejects_unknown_prefix() {
        assert_eq!(
            SubjectId::parse("docker:acme/widget").unwrap_err(),
            IdentityError::UnsupportedSubjectId
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_uses_canonical_strings() {
        let purl = NormalizedPurl::parse("pkg:PYPI/Django_package@1").unwrap();
        let json = serde_json::to_string(&purl).unwrap();
        let decoded: NormalizedPurl = serde_json::from_str(&json).unwrap();

        assert_eq!(json, r#""pkg:pypi/django-package@1""#);
        assert_eq!(decoded, purl);
    }

    #[test]
    fn cpe_parse_rejects_unsupported_binding() {
        assert_eq!(
            NormalizedCpe::parse("not-a-cpe").unwrap_err(),
            IdentityError::UnsupportedCpeBinding
        );
    }

    #[test]
    fn purl_parse_rejects_non_pkg_scheme() {
        assert!(matches!(
            NormalizedPurl::parse("not-a-purl"),
            Err(IdentityError::InvalidPurl { .. })
        ));
    }

    #[test]
    fn normalized_purl_display_matches_as_str() {
        let purl = NormalizedPurl::parse("pkg:generic/widget@1").unwrap();
        assert_eq!(purl.to_string(), purl.as_str());
    }

    #[test]
    fn normalized_cpe_display_matches_as_str() {
        let cpe = NormalizedCpe::parse("cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.to_string(), cpe.as_str());
    }

    #[test]
    fn subject_id_display_and_as_ref_agree_with_as_str() {
        let subject = SubjectId::parse("pkg:generic/widget@1").unwrap();
        assert_eq!(subject.to_string(), subject.as_str());
        assert_eq!(subject.as_ref(), subject.as_str());
    }

    #[test]
    fn subject_id_from_conversions_preserve_identity() {
        let purl = NormalizedPurl::parse("pkg:generic/widget@1").unwrap();
        let subject: SubjectId = purl.clone().into();
        assert_eq!(subject.as_purl(), Some(&purl));

        let cpe = NormalizedCpe::parse("cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*").unwrap();
        let subject2: SubjectId = cpe.clone().into();
        assert_eq!(subject2.as_cpe(), Some(&cpe));
    }
}
