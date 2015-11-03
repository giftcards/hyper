use std::any::Any;
use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};
use header::{Header, HeaderFormat};
use header::parsing;
use std::iter::Iterator;
use std::ascii::AsciiExt;
use std::collections::HashMap;
use header::HttpDate;
use std::str::FromStr;
use std::error::Error;

/// `Content-Disposition` header, defined in [RFC7235](https://tools.ietf.org/html/rfc7235#section-4.2)
///
/// The `Authorization` header field allows a user agent to authenticate
/// itself with an origin server -- usually, but not necessarily, after
/// receiving a 401 (Unauthorized) response.  Its value consists of
/// credentials containing the authentication information of the user
/// agent for the realm of the resource being requested.
///
/// # ABNF
/// ```plain
/// Authorization = credentials
/// ```
///
/// # Example values
/// * `Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==`
/// * `Bearer fpKL54jvWmEGVoRdCNjG`
///
/// # Examples
/// ```
/// use hyper::header::{Headers, Authorization};
///
/// let mut headers = Headers::new();
/// headers.set(Authorization("let me in".to_owned()));
/// ```
/// ```
/// use hyper::header::{Headers, Authorization, Basic};
///
/// let mut headers = Headers::new();
/// headers.set(
///    Authorization(
///        Basic {
///            username: "Aladdin".to_owned(),
///            password: Some("open sesame".to_owned())
///        }
///    )
/// );
/// ```
/// ```
/// use hyper::header::{Headers, Authorization, Bearer};
///
/// let mut headers = Headers::new();
/// headers.set(
///    Authorization(
///        Bearer {
///            token: "QWxhZGRpbjpvcGVuIHNlc2FtZQ".to_owned()
///        }
///    )
/// );
/// ```
#[derive(Clone, PartialEq, Debug)]
pub struct ContentDisposition<D: Disposition>(pub D);

impl<D: Disposition> Deref for ContentDisposition<D> {
    type Target = D;

    fn deref<'a>(&'a self) -> &'a D {
        &self.0
    }
}

impl<D: Disposition> DerefMut for ContentDisposition<D> {
    fn deref_mut<'a>(&'a mut self) -> &'a mut D {
        &mut self.0
    }
}

impl<D: Disposition + Any> Header for ContentDisposition<D> where D::T: 'static {
    fn header_name() -> &'static str {
        "Content-Disposition"
    }

    fn parse_header(raw: &[Vec<u8>]) -> ::Result<ContentDisposition<D>> {
		parsing::from_one_raw_str(raw).and_then(|header: String| {
			let mut params = header.split(';').map(str::trim);
			return if let Some(expected_disposition) = D::disposition() {
				let disposition = match params.next() {
					Some(s) => s.to_ascii_lowercase(),
					None => return Err(::Error::Header),
				};
				if disposition == expected_disposition {
					match <D as Disposition>::from_params(parse_str_to_hash_map("").unwrap()).map(ContentDisposition) {
						Ok(h) => Ok(h),
						Err(_) => Err(::Error::Header)
					}
				} else {
					Err(::Error::Header)
				}
			} else {
				match <D as Disposition>::from_params(parse_str_to_hash_map("").unwrap()).map(ContentDisposition) {
					Ok(h) => Ok(h),
					Err(_) => Err(::Error::Header)
				}
			}
		})
    }
}

impl<D: Disposition + Any> HeaderFormat for ContentDisposition<D> where D::T: 'static + Display {
    fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let params = self.0.to_params().unwrap();

		if let Some(disposition) = D::disposition() {
			try!(write!(f, "{}", disposition));

			if params.len() != 0 {
				try!(f.write_str("; "));
			}
		};

//		let mut iter = params.iter().peekable();
//
//		while let Some(param) = iter.next() {
//			try!(Display::fmt(param, f));
//
//			if iter.peek().is_some() {
//				try!(f.write_str("; "));
//			}
//		}
		Ok(())
    }
}

type DispositionResult<T> = Result<T, DispositionError>;

/// An content disposition to be used in the header.
pub trait Disposition: fmt::Debug + Clone + Send + Sync {
	type T: Display;
    /// An optional Disposition name.
    ///
    /// Will be replaced with an associated constant once available.
    fn disposition() -> Option<&'static str>;
    /// Format the Disposition data into a header value.
    fn to_params(&self) -> DispositionResult<HashMap<String, String>>;

	fn from_params(params: HashMap<String, String>) -> DispositionResult<Self>;
}

#[derive(Debug)]
pub enum DispositionError {
	MissingParam(String),
	InvalidParam(String)
}

impl fmt::Display for DispositionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.description())
    }
}

impl Error for DispositionError {
    fn description(&self) -> &str {
        match *self {
//            MissingParam(String) => "Invalid HTTP version specified",
//            InvalidParam(String) => "Invalid Method specified"
			_ => "hello"
        }
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl Disposition for HashMap<String, String> {
    type T = String;

	fn disposition() -> Option<&'static str> {
        None
    }

	fn from_params(params: HashMap<String, String>) -> DispositionResult<Self> {
		Ok(params)
	}

    fn to_params(&self) -> DispositionResult<HashMap<String, String>> {
        Ok(self.clone())
    }
}

/// Credential holder for Basic Authentication
#[derive(Clone, PartialEq, Debug)]
pub struct Inline;

impl Disposition for Inline {
	type T = String;

    fn disposition() -> Option<&'static str> {
        Some("inline")
    }

    fn to_params(&self) -> DispositionResult<HashMap<String, String>> {
		Ok(HashMap::new())
    }

	fn from_params(_: HashMap<String, String>) -> DispositionResult<Self> {
		Ok(Inline)
	}
}

/// Credential holder for Basic Authentication
#[derive(Clone, PartialEq, Debug)]
pub struct Attachment {
	pub filename: String,
	pub filename_fallback: Option<String>,
	pub creation_date: Option<HttpDate>,
	pub modification_date: Option<HttpDate>,
	pub read_date: Option<HttpDate>,
	pub size: Option<usize>,
}

impl Disposition for Attachment {
	type T = String;

    fn disposition() -> Option<&'static str> {
        Some("attachment")
    }

    fn to_params(&self) -> DispositionResult<HashMap<String, String>> {
		Ok(HashMap::new())
    }

	fn from_params(params: HashMap<String, String>) -> DispositionResult<Self> {
		let filename = if params.get("filename*").is_some() {
			params.get("filename*").map(|s| (*s).to_owned()).unwrap()
		} else {
			try!(params.get("filename").map(|s| (*s).to_owned()).ok_or(DispositionError::MissingParam(String::from("filename or filename*"))))
		};
		let filename_fallback = if params.get("filename*").is_some() {
			params.get("filename").map(|s| (*s).to_owned())
		} else {
			None
		};
		let creation_date = if params.get("creation_date").is_some() {
			Some(try!(HttpDate::from_str(params.get("creation_date").unwrap()).map_err(|_| DispositionError::InvalidParam(String::from("creation_date")))))
		} else {
			None
		};
		let modification_date = if params.get("modification_date").is_some() {
			Some(try!(HttpDate::from_str(params.get("modification_date").unwrap()).map_err(|_| DispositionError::InvalidParam(String::from("modification_date")))))
		} else {
			None
		};
		let read_date = if params.get("read_date").is_some() {
			Some(try!(HttpDate::from_str(params.get("read_date").unwrap()).map_err(|_| DispositionError::InvalidParam(String::from("read_date")))))
		} else {
			None
		};
		let size = if params.get("size").is_some() {
			Some(try!(params.get("size").unwrap().parse().map_err(|_| DispositionError::InvalidParam(String::from("size")))))
		} else {
			None
		};
		
		Ok(Attachment {
			filename: filename,
			filename_fallback: filename_fallback,
			creation_date: creation_date,
			modification_date: modification_date,
			read_date: read_date,
			size: size
		})
	}
}

pub fn parse_str_to_hash_map(params: &str) -> Result<HashMap<String, String>, &str> {

	let mut map = HashMap::new();
	
	let mut iterator = params.chars().peekable();
	let tspecial = " ()<>@,;:\\\"/[]?=";
	let modes = [
	  "before_key",
	  "in_key",
	  "after_key",
	  "before_value",
	  "in_value",
	  "in_quoted_value",
	  "after_value"
    ];
	let mut mode = modes[0];
	let mut key = String::new();
	let mut value = String::new();

	while let Some(char) = iterator.next() {
		println!("{}", char);
		if !char.is_ascii() {
			return Err("none ascii chars sent.");
		}
		
		if char == ' ' {
			if mode == modes[1] {
				mode = modes[2];
			}
			
			if mode == modes[4] {
				mode = modes[6];
				map.insert(key.clone(), value.clone());
			}
			
			if mode != modes[5] {
				continue;
			}
		}
		
		if char == '=' {
			if mode == modes[0] {
				return Err("no key present.");
			}
			
			if mode == modes[1] || mode == modes[2] {
				mode = modes[3];
				continue;
			}
		}
		
		if char == ';' && (mode == modes[6] || mode == modes[4]) {
			if mode == modes[4] {
				map.insert(key.clone(), value.clone());				
			}
			mode = modes[0];
			key = String::new();
			value = String::new();
			continue;
		}
		
		if char == '"' {
			if mode == modes[3] {
				mode = modes[5];
				continue;
			}
			
			if mode == modes[5] && !value.ends_with('\\') {
				mode = modes[6];
				map.insert(key.clone(), value.clone());
				continue;
			}
		}
		
		if mode == modes[0] {
			mode = modes[1];
		}
		
		if mode == modes[3] {
			mode = modes[4];
		}
		
		if mode != modes[5] && (char.is_control() || tspecial.find(char).is_some()) {
			return Err("invalid characters found");
		}
		
		if mode == modes[1] {
			key.push(char);
		}
		
		if mode == modes[4] || mode == modes[5] {
			value.push(char);
		}
	}

	Ok(map)
}

#[cfg(test)]
mod tests {
    use super::{ContentDisposition, Inline};
    use super::super::super::{Headers, Header};
    use super::parse_str_to_hash_map;
	use std::collections::HashMap;

//    #[test]
//    fn test_raw_disposition() {
//        let mut headers = Headers::new();
//        headers.set(ContentDisposition("raw".to_owned()));
//        assert_eq!(headers.to_string(), "Content-Disposition: raw\r\n".to_owned());
//    }
//
//    #[test]
//    fn test_raw_disposition_parse() {
//        let header: ContentDisposition<String> = Header::parse_header(
//            &[b"raw".to_vec()]).unwrap();
//        assert_eq!(header.0, "raw".to_owned());
//    }

    #[test]
    fn test_inline_disposition() {
        let mut headers = Headers::new();
        headers.set(ContentDisposition(Inline));
        assert_eq!(
            headers.to_string(),
            "Content-Disposition: inline\r\n".to_owned());
    }

    #[test]
    fn test_inline_disposition_parse() {
        let _: ContentDisposition<Inline> = Header::parse_header(
            &[b"inline".to_vec()]).unwrap();
    }
    
    #[test]
    fn test_parse_str_to_hash_map() {
    	let params = "hello=goodbye;seeya=\"later dude\"";
    	let mut hash_map = HashMap::new();
    	hash_map.insert("hello".to_owned(), "goodbye".to_owned());
    	hash_map.insert("seeya".to_owned(), "later dude".to_owned());
    	assert_eq!(
    		Ok(hash_map),
    		parse_str_to_hash_map(params)
		);
    	assert_eq!(
    		Err("no key present."),
    		parse_str_to_hash_map("=hello")
		);
    	assert_eq!(
    		Err("no key present."),
    		parse_str_to_hash_map("=\"hello\"")
		);
    }
    
}

bench_header!(raw, ContentDisposition<String>, { vec![b"raw".to_vec()] });
bench_header!(inline, ContentDisposition<Inline>, { vec![b"inline".to_vec()] });
