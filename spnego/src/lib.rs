#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_qualifications
)]

extern crate alloc;

use der::{
    asn1::{BitString, ContextSpecific, OctetStringRef},
    Choice, DecodeValue, Encode, EncodeValue, Enumerated, FixedTag, Length, Reader, Sequence, Tag,
    TagMode, TagNumber, Writer,
};
use spki::ObjectIdentifier;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GssToken<'a> {
    pub tag: ObjectIdentifier,
    pub object: alloc::vec::Vec<NegotiationToken<'a>>,
}

impl<'a> GssToken<'a> {
    fn context_specific_object(
        &self,
    ) -> der::Result<Option<ContextSpecific<alloc::vec::Vec<NegotiationToken<'a>>>>> {
        Ok(Some(ContextSpecific {
            tag_number: TagNumber::N0,
            tag_mode: TagMode::Implicit,
            value: self.object.clone(), // TODO
        }))
    }
}

impl FixedTag for GssToken<'_> {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(0),
    };
}

impl<'a> DecodeValue<'a> for GssToken<'a> {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            Ok(Self {
                tag: reader.decode()?,
                object: reader
                    .context_specific(TagNumber::N0, TagMode::Implicit)?
                    .unwrap(),
            })
        })
    }
}

impl EncodeValue for GssToken<'_> {
    fn value_len(&self) -> der::Result<Length> {
        self.tag.encoded_len()? + self.object.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.tag.encode(writer)?;
        self.context_specific_object()?.encode(writer)?;

        Ok(())
    }
}

pub type MechType = ObjectIdentifier;

pub type MechTypeList = alloc::vec::Vec<ObjectIdentifier>;

pub type ContextFlags = BitString;

#[derive(Clone, Debug, PartialEq, Eq, Choice)]
pub enum NegotiationToken<'a> {
    // #[asn1(context_specific = "0", optional = "false", tag_mode = "IMPLICIT")]
    NegTokenInit(NegTokenInit2<'a>),
    // #[asn1(context_specific = "1", optional = "false", tag_mode = "IMPLICIT")]
    NegTokenArg(NegTokenTarg<'a>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Sequence)]
pub struct NegHints<'a> {
    #[asn1(
        context_specific = "0",
        optional = "true",
        tag_mode = "EXPLICIT",
        constructed = "false"
    )]
    pub name: Option<OctetStringRef<'a>>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub address: Option<OctetStringRef<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct NegTokenInit<'a> {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    pub mech_types: Option<MechTypeList>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub req_flags: Option<ContextFlags>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "IMPLICIT")]
    pub mech_token: Option<OctetStringRef<'a>>,

    #[asn1(context_specific = "3", optional = "true", tag_mode = "IMPLICIT")]
    pub mech_list_mic: Option<OctetStringRef<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct NegTokenInit2<'a> {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub mech_types: Option<MechTypeList>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub req_flags: Option<ContextFlags>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub mech_token: Option<OctetStringRef<'a>>,

    #[asn1(context_specific = "3", optional = "true", tag_mode = "EXPLICIT")]
    pub neg_hints: Option<NegHints<'a>>,

    #[asn1(context_specific = "4", optional = "true", tag_mode = "EXPLICIT")]
    pub mech_list_mic: Option<OctetStringRef<'a>>,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "ENUMERATED")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum NegResult {
    AcceptCompleted = 0,
    AcceptIncomplete = 1,
    Reject = 2,
}

/// Tag mode explicit
#[derive(Clone, Copy, Debug, Eq, PartialEq, Sequence)]
pub struct NegTokenTarg<'a> {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub neg_result: Option<NegResult>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub supported_mech: Option<MechType>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub response_token: Option<OctetStringRef<'a>>,

    #[asn1(context_specific = "3", optional = "true", tag_mode = "EXPLICIT")]
    pub mech_list_mic: Option<OctetStringRef<'a>>,
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use hex_literal::hex;
    use spki::ObjectIdentifier;

    use super::*;

    use der::Decode;

    #[test]
    fn encode() {
        let mech_type_bytes = hex!("060a2b06010401823702020a");
        let mech_type = MechType::from_der(&mech_type_bytes).unwrap();
        assert_eq!(
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10"),
            mech_type
        );

        let neg_token_targ_bytes = hex!("308199a0030a0101a10c060a2b06010401823702020aa281830481804e544c4d53535000020000000a000a003800000005028a6234805409a0e0e1f900000000000000003e003e0042000000060100000000000f530041004d004200410002000a00530041004d004200410001000a00530041004d00420041000400000003000a00730061006d00620061000700080036739dbd327fd90100000000");
        let neg_token_targ = NegTokenTarg::from_der(&neg_token_targ_bytes).unwrap();
        assert_eq!(
            NegResult::AcceptIncomplete,
            neg_token_targ.neg_result.unwrap()
        );
        assert_eq!(
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10"),
            neg_token_targ.supported_mech.unwrap()
        );

        let neg_token_init_bytes = hex!("303ca00e300c060a2b06010401823702020aa22a04284e544c4d535350000100000005028862000000000000000000000000000000000601b01d0000000f");
        let neg_token = NegTokenInit2::from_der(&neg_token_init_bytes).unwrap();
        assert_eq!(1, neg_token.mech_types.unwrap().len());
        // assert_eq!(OctetStringRef::new(b"not_defined_in_RFC4178@please_ignore").unwrap(), neg_token.neg_hints.unwrap().name.unwrap());

        let gss_bytes = hex!("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d535350000100000005028862000000000000000000000000000000000601b01d0000000f");
        let gss = GssToken::from_der(&gss_bytes).unwrap();
        assert_eq!(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.2"), gss.tag);
    }

    #[test]
    fn decode() {
        let sample_mech_token = hex!(
            "4e544c4d535350000100000005028862000000000000000000000000000000000601b01d0000000f"
        );
        let reference = hex!("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d535350000100000005028862000000000000000000000000000000000601b01d0000000f");

        let gss_token = GssToken {
            tag: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.2"),
            object: vec![NegotiationToken::NegTokenInit(NegTokenInit2 {
                mech_types: Some(vec![ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10")]),
                req_flags: None,
                mech_token: Some(OctetStringRef::new(&sample_mech_token).unwrap()),
                neg_hints: None,
                mech_list_mic: None,
            })],
        };

        let mut buf = vec::Vec::new();
        let v = gss_token.encode_to_vec(&mut buf).unwrap();
        assert_eq!(&reference[..], &buf);

        // let mech_type_bytes = hex!("060a2b06010401823702020a");
        // let mech_type = MechType::from_der(&mech_type_bytes).unwrap();
        // assert_eq!(
        //     ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10"),
        //     mech_type
        // );

        // let neg_token_targ_bytes = hex!("308199a0030a0101a10c060a2b06010401823702020aa281830481804e544c4d53535000020000000a000a003800000005028a6234805409a0e0e1f900000000000000003e003e0042000000060100000000000f530041004d004200410002000a00530041004d004200410001000a00530041004d00420041000400000003000a00730061006d00620061000700080036739dbd327fd90100000000");
        // let neg_token_targ = NegTokenTarg::from_der(&neg_token_targ_bytes).unwrap();
        // assert_eq!(
        //     NegResult::AcceptIncomplete,
        //     neg_token_targ.neg_result.unwrap()
        // );
        // assert_eq!(
        //     ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10"),
        //     neg_token_targ.supported_mech.unwrap()
        // );

        // let neg_token_init_bytes = hex!("303ca00e300c060a2b06010401823702020aa22a04284e544c4d535350000100000005028862000000000000000000000000000000000601b01d0000000f");
        // let neg_token = NegTokenInit2::from_der(&neg_token_init_bytes).unwrap();
        // assert_eq!(1, neg_token.mech_types.unwrap().len());
        // // assert_eq!(OctetStringRef::new(b"not_defined_in_RFC4178@please_ignore").unwrap(), neg_token.neg_hints.unwrap().name.unwrap());

        // let gss_bytes = hex!("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d535350000100000005028862000000000000000000000000000000000601b01d0000000f");
        // let gss = GssToken::from_der(&gss_bytes).unwrap();
        // assert_eq!(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.2"), gss.tag);
    }
}
