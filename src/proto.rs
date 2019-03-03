use lexpr;

use serde::de::{
    self, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess, VariantAccess,
    Visitor,
};
use serde::{forward_to_deserialize_any, Deserialize};

// use serde::de::error::{Error, Result};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum Operation {
    Equal(String),
    PrefixOf(String),
    OfPrefix(String),
    Regex(String),
    In(Vec<String>),
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum MatchCondition {
    HeaderExists { header: String },
    WillHaveBody,
    HeaderMatch { header: String, op: Operation },
    MethodMatch(Operation),
    UrlMatch(Operation),
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum MatchExpression {
    Condition(MatchCondition),
    And(Vec<Box<MatchExpression>>),
    Or(Vec<Box<MatchExpression>>),
}

pub struct FnCallDeserializer<'a, 'de> {
    fn_name: &'a str,
    args: &'a [&'de lexpr::Value],
}

impl<'a, 'de:'a> FnCallDeserializer<'a, 'de> {
    fn new(n: &'a str, args: &'a [&'de lexpr::Value]) -> FnCallDeserializer<'a, 'de> {
        FnCallDeserializer {
            fn_name: n,
            args: args,
        }
    }
}

impl<'de, 'a> de::Deserializer<'de> for &'a mut FnCallDeserializer<'a, 'de> {
    //   = note: `Error` from trait: `type Error;`
    type Error = ExprError;

    fn deserialize_any<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

pub struct Deserializer<'de> {
    input: &'de lexpr::Value,
}

impl<'de> Deserializer<'de> {
    fn new(v: &'de lexpr::Value) -> Deserializer<'de> {
        Deserializer { input: v }
    }

    fn atomize(&self, a: &lexpr::Value) -> Result<String, ()> {
        match a {
            lexpr::Value::Atom(a) => Ok(format!("{:?}", a)),
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug)]
pub enum ExprError {
    Error(String),
    ExpectedString,
    ExpectedSexpr,
}

impl std::fmt::Display for ExprError {
    fn fmt(&self, fmtr: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmtr, "Error")
    }
}

impl serde::de::Error for ExprError {
    fn custom<T>(t: T) -> ExprError
    where
        T: std::fmt::Display,
    {
        ExprError::Error(format!("{}", t))
    }
}

impl std::error::Error for ExprError {}

impl<'de, 'a> de::Deserializer<'de> for &'a mut Deserializer<'de> {
    //   = note: `Error` from trait: `type Error;`
    type Error = ExprError;

    fn deserialize_any<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_byte_buf<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_bytes<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_bool<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_char<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_f32<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_f64<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_i16<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_i32<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_i64<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_i8<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_identifier<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_ignored_any<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_map<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_newtype_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_option<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_seq<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_string<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_str<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_enum<V>(
        self,
        key: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        println!("{}", key);
        println!("{:?}", variants);
        println!("{:?}", self.input);
        match self.input {
            lexpr::Value::List(l) => {
                let vname = l
                    .get(0)
                    .ok_or(ExprError::ExpectedString)
                    .and_then(|f| self.atomize(f).map_err(|_| ExprError::ExpectedString))
                    .and_then(|a| Ok(String::from(a)))?;
                let vals = l.iter().skip(1).collect::<Vec<&lexpr::Value>>();
                let mut fd = FnCallDeserializer::new(&vname, vals.as_slice());
                visitor.visit_enum(Enum::new(fd))
//
 //                Err(ExprError::ExpectedSexpr)
//                
            }
            _ => Err(ExprError::ExpectedSexpr),
        }

        // unimplemented!()
    }

    fn deserialize_struct<V>(
        self,
        key: &'static str,
        value: &'static [&'static str],
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_tuple<V>(
        self,
        len: usize,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_tuple_struct<V>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_u16<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_u32<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_u64<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_u8<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_unit<V>(
        self,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
    fn deserialize_unit_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> std::result::Result<
        <V as serde::de::Visitor<'de>>::Value,
        <Self as serde::Deserializer<'de>>::Error,
    >
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
}

struct Enum<'a, 'de: 'a> {
    de: FnCallDeserializer<'a, 'de>,
}

impl<'a, 'de> Enum<'a, 'de> {
    fn new(de: FnCallDeserializer<'a, 'de>) -> Self {
        Enum { de }
    }
}

// `EnumAccess` is provided to the `Visitor` to give it the ability to determine
// which variant of the enum is supposed to be deserialized.
//
// Note that all enum deserialization methods in Serde refer exclusively to the
// "externally tagged" enum representation.
impl<'de, 'a> EnumAccess<'de> for Enum<'a, 'de> {
    type Error = ExprError;
    type Variant = Self;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let val = { let q = seed.deserialize(&mut self.de)?; q };
        Ok((val, self))
    }
}
// `VariantAccess` is provided to the `Visitor` to give it the ability to see
// the content of the single variant that it decided to deserialize.
impl<'de, 'a> VariantAccess<'de> for Enum<'a, 'de> {
    type Error = ExprError;

    // If the `Visitor` expected this variant to be a unit variant, the input
    // should have been the plain string case handled in `deserialize_enum`.
    fn unit_variant(self) -> Result<(), Self::Error> {
        Err(ExprError::ExpectedString)
    }

    // Newtype variants are represented in JSON as `{ NAME: VALUE }` so
    // deserialize the value here.
    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        seed.deserialize(&mut self.de)
    }

    // Tuple variants are represented in JSON as `{ NAME: [DATA...] }` so
    // deserialize the sequence of data here.
    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        de::Deserializer::deserialize_seq(&mut self.de, visitor)
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }` so
    // deserialize the inner map here.
    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        de::Deserializer::deserialize_map(&mut self.de, visitor)
    }
}

#[test]
fn test1() {
    let x = "(and )";
    let r = lexpr::from_str(x).unwrap();
    println!("{:?}", r);

    let x = "(and :a :b)";
    let r = lexpr::from_str(x).unwrap();
    println!("{:?}", r);

    let x = "(and (a  ) (b ))";
    let r = lexpr::from_str(x).unwrap();
    println!("{:?}", r);

    let mut deser = Deserializer::new(&r);
    let m = MatchExpression::deserialize(&mut deser).unwrap();
}
