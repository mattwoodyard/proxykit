use lexpr::{from_str, Atom, Value};

use serde::de::{
    self, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess, VariantAccess,
    Visitor,
};
use serde::{forward_to_deserialize_any, Deserialize};

// use serde::de::error::{Error, Result};

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Operation {
    Equal(String),
    PrefixOf(String),
    OfPrefix(String),
    Regex(String),
    In(Vec<String>),
}

impl Operation {
    fn interpret(input: &Value) -> Result<Operation, ExprError> {
        match input {
            Value::List(l) => {
                let f = l.get(0).ok_or(ExprError::ExpectedNonEmpty)?;
                let mut remain = l.iter().skip(1);

                let fnname = match f {
                    Value::Atom(Atom::Symbol(s)) => Ok(s),
                    _ => Err(ExprError::ExpectedString(String::from("Some function"))),
                }?;

                match fnname.as_str() {
                    "=" => {
                        let arg = remain
                            .next()
                            .ok_or(ExprError::ExpectedArgument(String::from("Got none")))?;
                        Ok(Operation::Equal(arg.to_string()))
                    }
                    x => Err(ExprError::FnNotImplemented(x.to_string())),
                }
            }
            _ => Err(ExprError::ExpectedList),
        }
    }
}

struct FnResolver<'a> {
    input: &'a Value,
}

impl<'a> FnResolver<'a> {
    fn new(i: &'a Value) -> FnResolver<'a> {
        FnResolver { input: i }
    }

    fn fn_name(&self) -> Result<&'a str, ExprError> {
        match self.input {
            Value::List(l) => l
                .get(0)
                .ok_or(ExprError::ExpectedNonEmpty)
                .and_then(|v| match v {
                    Value::Atom(Atom::Symbol(s)) => Ok(s.as_str()),
                    _ => Err(ExprError::ExpectedString(String::from("Some function"))),
                }),
            _ => Err(ExprError::ExpectedList),
        }
    }

    fn get_arg(&self, idx: usize) -> Result<&'a Value, ExprError> {
        match self.input {
            Value::List(l) => l.get(idx + 1).ok_or(ExprError::ExpectedNonEmpty),
            _ => Err(ExprError::ExpectedList),
        }
    }

    fn get_arg_str(&self, idx: usize) -> Result<&'a str, ExprError> {
        match self.input {
            Value::List(l) => {
                l.get(idx + 1)
                    .ok_or(ExprError::ExpectedNonEmpty)
                    .and_then(|v| match v {
                        Value::Atom(Atom::Symbol(s)) => Ok(s.as_str()),
                        _ => Err(ExprError::ExpectedString(String::from("Some function"))),
                    })
            }
            _ => Err(ExprError::ExpectedList),
        }
    }

    fn args(&self) -> Result<impl Iterator<Item = &'a Value>, ExprError> {
        match self.input {
            Value::List(l) => Ok(l.iter().skip(1)),
            _ => Err(ExprError::ExpectedList),
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum MatchCondition {
    HeaderExists { header: String },
    WillHaveBody,
    HeaderMatch { header: String, op: Operation },
    MethodMatch(Operation),
    UrlMatch(Operation),
}

impl MatchCondition {
    fn interpret(input: &Value) -> Result<MatchCondition, ExprError> {
        let resolver = FnResolver::new(input);
        let fname = resolver.fn_name()?;
        match fname {
            "header-exists" => resolver
                .get_arg_str(0)
                .map(|a| MatchCondition::HeaderExists {
                    header: String::from(a),
                }),
            "has-body" => Ok(MatchCondition::WillHaveBody),
            "header-matches" | "header" => resolver
                .get_arg_str(0)
                .and_then(|a| {
                    resolver
                        .get_arg(1)
                        .and_then(Operation::interpret)
                        .map(|i| (a, i))
                })
                .map(|(a, b)| MatchCondition::HeaderMatch {
                    header: String::from(a),
                    op: b,
                }),
            // "method-matches" =>  {}
            // "url-matches" => {}
            // "status-matches" => {}
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum MatchExpression {
    Condition(MatchCondition),
    And(Vec<Box<MatchExpression>>),
    Or(Vec<Box<MatchExpression>>),
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum ExprError {
    ExpectedList,
    ExpectedString(String),
    ExpectedNonEmpty,
    ExpectedArgument(String),
    FnNotImplemented(String),
}

impl MatchExpression {
    fn interpret(input: &lexpr::Value) -> Result<MatchExpression, ExprError> {
        let resolver = FnResolver::new(input);
        let fname = resolver.fn_name()?;
        match fname {
            "and" => {
                let rt = resolver.args().and_then(|args| {
                    args.map(MatchExpression::interpret)
                        .collect::<Result<Vec<MatchExpression>, ExprError>>()
                })?;
                Ok(MatchExpression::And(
                    rt.into_iter().map(|i| Box::new(i)).collect(),
                ))
            }
            "or" => {
                let rt = resolver.args().and_then(|args| {
                    args.map(MatchExpression::interpret)
                        .collect::<Result<Vec<MatchExpression>, ExprError>>()
                })?;
                Ok(MatchExpression::Or(
                    rt.into_iter().map(|i| Box::new(i)).collect(),
                ))
            }
            _ => MatchCondition::interpret(input).map(|c| MatchExpression::Condition(c)),
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum TriggerDefinition {
    Request,
    Response,
    RequestAndResponse,
    RequestAsync,
    ResponseAsync,
    RequestAndResponseAsync,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum TriggerTarget {
    Url(String),
    Internal(String),
    Lua(String),
    Ebpf(String),
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Trigger {
    pub style: TriggerDefinition,
    pub target: TriggerTarget,
    pub condition: MatchExpression,
}


impl Trigger {

//    fn evaluate(&self) -> TriggerAction {

  //  }


}



#[test]
fn basic_tests() {
    let x = "(= \"string with spaces\")";
    let r = lexpr::from_str(x).unwrap();
    let res = Operation::interpret(&r).unwrap();
    assert_eq!(
        res,
        Operation::Equal(String::from("\"string with spaces\""))
    );

    let x = "(!= \"string with spaces\")";
    let r = lexpr::from_str(x).unwrap();
    let res = Operation::interpret(&r);
    assert_eq!(res, Err(ExprError::FnNotImplemented(String::from("!="))));

    let x = "(header-exists content-type)";
    let r = lexpr::from_str(x).unwrap();
    let res = MatchCondition::interpret(&r).unwrap();
    assert_eq!(
        res,
        MatchCondition::HeaderExists {
            header: String::from("content-type")
        }
    );

    let x = "(header-matches content-type (= application/json))";
    let r = lexpr::from_str(x).unwrap();
    let res = MatchCondition::interpret(&r).unwrap();
    println!("{:?}", res);

    let x = "(and (header content-type (= application/json)) (header-exists host))";
    let r = lexpr::from_str(x).unwrap();
    let res = MatchExpression::interpret(&r).unwrap();
    println!("{:?}", res);
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
}
