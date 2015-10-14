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
					match <D as Disposition>::from_params(params.skip(1).collect()).map(ContentDisposition) {
						Ok(h) => Ok(h),
						Err(_) => Err(::Error::Header)
					}
				} else {
					Err(::Error::Header)
				}
			} else {
				match <D as Disposition>::from_params(params.collect()).map(ContentDisposition) {
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

		let mut iter = params.iter().peekable();

		while let Some(param) = iter.next() {
			try!(Display::fmt(param, f));

			if iter.peek().is_some() {
				try!(f.write_str("; "));
			}
		}
		Ok(())
    }
}

/// An content disposition to be used in the header.
pub trait Disposition: fmt::Debug + Clone + Send + Sync {
	type T: Display;
    /// An optional Disposition name.
    ///
    /// Will be replaced with an associated constant once available.
    fn disposition() -> Option<&'static str>;
    /// Format the Disposition data into a header value.
    fn to_params(&self) -> ::Result<Vec<Self::T>>;

	fn from_params(params: Vec<&str>) -> ::Result<Self>;
}

impl Disposition for Vec<String> {
    type T = String;

	fn disposition() -> Option<&'static str> {
        None
    }

	fn from_params(params: Vec<&str>) -> ::Result<Self> {
		Ok(params.iter().map(|s| String::from(*s)).collect())
	}

    fn to_params(&self) -> ::Result<Vec<String>> {
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

    fn to_params(&self) -> ::Result<Vec<String>> {
		Ok(Vec::new())
    }

	fn from_params(_: Vec<&str>) -> ::Result<Self> {
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

    fn to_params(&self) -> ::Result<Vec<String>> {
		Ok(Vec::new())
    }

	fn from_params(params: Vec<&str>) -> ::Result<Self> {
		let hash_map = parse_param_vec_to_hash_map(params);
		let filename = if hash_map.get("filename*").is_some() {
			hash_map.get("filename*").map(|s| String::from(*s)).unwrap()
		} else {
			try!(hash_map.get("filename").map(|s| String::from(*s)).ok_or(::Error::Header))
		};
		let filename_fallback = if hash_map.get("filename*").is_some() {
			hash_map.get("filename").map(|s| String::from(*s))
		} else {
			None
		};
		let creation_date = if hash_map.get("creation_date").is_some() {
			Some(try!(HttpDate::from_str(hash_map.get("creation_date").unwrap()).map_err(|_| ::Error::Header)))
		} else {
			None
		};
		let modification_date = if hash_map.get("modification_date").is_some() {
			Some(try!(HttpDate::from_str(hash_map.get("modification_date").unwrap()).map_err(|_| ::Error::Header)))
		} else {
			None
		};
		let read_date = if hash_map.get("read_date").is_some() {
			Some(try!(HttpDate::from_str(hash_map.get("read_date").unwrap()).map_err(|_| ::Error::Header)))
		} else {
			None
		};
		let size = if hash_map.get("size").is_some() {
			Some(try!(hash_map.get("size").unwrap().parse().map_err(|_| ::Error::Header)))
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

fn parse_param_vec_to_hash_map(params: Vec<&str>) -> HashMap<&str, &str> {

	let mut map = HashMap::new();

	for param in &params {
		let mut split_str_iter = param.split("=");
		let key = split_str_iter.next().unwrap();
		let value = split_str_iter.next().unwrap();

		map.insert(key, value);
	}

	map
}

#[cfg(test)]
mod tests {
    use super::{ContentDisposition, Inline};
    use super::super::super::{Headers, Header};

    #[test]
    fn test_raw_disposition() {
        let mut headers = Headers::new();
        headers.set(ContentDisposition(vec!["raw".to_owned()]));
        assert_eq!(headers.to_string(), "Content-Disposition: raw\r\n".to_owned());
    }

    #[test]
    fn test_raw_disposition_parse() {
        let header: ContentDisposition<Vec<String>> = Header::parse_header(
            &[b"raw".to_vec()]).unwrap();
        assert_eq!(header.0, vec!["raw".to_owned()]);
    }

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
}

bench_header!(raw, ContentDisposition<String>, { vec![b"raw".to_vec()] });
bench_header!(inline, ContentDisposition<Inline>, { vec![b"inline".to_vec()] });
