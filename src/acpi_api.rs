use std::str::from_utf8;

use icaparse::{Request, SectionType, EMPTY_HEADER};

macro_rules! str {
    ($s:literal) => {
        String::from($s)
    };
}

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net,
};

trait AsString {
    fn as_string(&self) -> String;
}

impl AsString for SectionType {
    fn as_string(&self) -> String {
        match self {
            SectionType::NullBody => str!("NullBody"),
            SectionType::RequestHeader => str!("RequestHeader"),
            Self::RequestBody => str!("RequestBody"),
            Self::ResponseHeader => str!("ResponseHeader"),
            Self::ResponseBody => str!("ResponseBody"),
            Self::OptionsBody => str!("OptionsBody"),
        }
    }
}

trait ReadToVec {
    type Error;

    async fn read_to_vec(&mut self, vec: &mut Vec<u8>, length: usize) -> Result<(), Self::Error>;
}

impl<T: AsyncRead + AsyncReadExt + Unpin> ReadToVec for T {
    type Error = std::io::Error;

    async fn read_to_vec(
        self: &mut T,
        vec: &mut Vec<u8>,
        length: usize,
    ) -> Result<(), Self::Error> {
        let mut buf = [0u8; 512];
        let mut read_bytes = 0usize;

        while read_bytes != length {
            let tbr = 512.min(length - read_bytes);

            let r = self.read(&mut buf[..tbr]).await?;
            vec.extend_from_slice(&buf[..r]);
            read_bytes += r;
        }
        Ok(())
    }
}

pub struct ICAPWorker {
    con: net::TcpStream,
}

pub enum ICAPError {
    SocketError(tokio::io::ErrorKind),
    IoError(std::io::Error),
    ParsingError(icaparse::Error),
}

impl From<icaparse::Error> for ICAPError {
    fn from(value: icaparse::Error) -> Self {
        ICAPError::ParsingError(value)
    }
}

impl From<tokio::io::ErrorKind> for ICAPError {
    fn from(value: tokio::io::ErrorKind) -> Self {
        ICAPError::SocketError(value)
    }
}

impl From<std::io::Error> for ICAPError {
    fn from(value: std::io::Error) -> Self {
        ICAPError::IoError(value)
    }
}

impl ICAPWorker {
    pub fn new(con: net::TcpStream) -> Self {
        ICAPWorker { con }
    }

    pub async fn process_msg(&mut self) -> Result<(), ICAPError> {
        let mut recv_buf = [0u8; 512];

        let mut buf: Vec<u8> = Vec::new();

        loop {
            let nbytes = match self.con.read(&mut recv_buf).await {
                Ok(0) => {
                    return Err(tokio::io::ErrorKind::BrokenPipe.into());
                }
                Ok(nbytes) => nbytes,
                Err(e) if e.kind() == tokio::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    return Err(e.kind().into());
                }
            };

            let mut header = [EMPTY_HEADER; 16];
            let mut req = Request::new(&mut header);

            buf.extend_from_slice(&recv_buf[..nbytes]);

            if req.parse(&buf.as_slice())?.is_complete() {
                if req.method.is_none() {
                    let resp: String = ICAPResponse::with_code_reason(204, "no mod needed").into();

                    self.con.write_all(resp.as_bytes()).await?;
                    break;
                }

                match req.method.unwrap() {
                    "OPTIONS" => {
                        let resp: String =
                            ICAPResponse::new(200, Some("ok"), &[("Methods", "RESPMOD")]).into();

                        self.con.write_all(resp.as_bytes()).await?;
                    }
                    "RESPMOD" => {
                        if let Some(mail) = self.get_mail(&req).await {
                            match from_utf8(&mail) {
                                Ok(m) => {
                                    println!("mail:\n{}", m);
                                }
                                Err(e) => {
                                    println!("Error decoding mail: {:?}", e);
                                }
                            }
                        }

                        let resp: String =
                            ICAPResponse::with_code_reason(204, "no mod needed").into();

                        self.con.write_all(resp.as_bytes()).await?;
                    }
                    _ => {
                        let resp: String =
                            ICAPResponse::with_code_reason(204, "no mod needed").into();

                        self.con.write_all(resp.as_bytes()).await?;
                    }
                }
                break;
            }
        }

        Ok(())
    }

    fn get_mail_length(req: &Request) -> Option<usize> {
        if req.encapsulated_sections.is_none() {
            return None;
        }

        let header: &str = match req
            .encapsulated_sections
            .as_ref()
            .unwrap()
            .get(&SectionType::ResponseHeader)
            .map(|h| from_utf8(h))
        {
            Some(Ok(h)) => h,
            _ => {
                return None;
            }
        };

        for line in header.split("\r\n") {
            if let Some((field, val)) = line.split_once(":") {
                if field.to_lowercase() == "content-length" {
                    if let Ok(length) = val.trim().parse::<usize>() {
                        return Some(length);
                    }
                }
            }
        }

        None
    }

    async fn get_mail<'a, 'b>(&'a mut self, req: &Request<'b, 'b>) -> Option<Vec<u8>> {
        let mail_length = match Self::get_mail_length(&req) {
            Some(l) => l,
            None => {
                return None;
            }
        };

        // println!("\nsections: {:?}", req.encapsulated_sections);
        if let Some(sections) = req.encapsulated_sections.as_ref() {
            for (sec, sectval) in sections.iter() {
                println!("sec: {}", sec.as_string());
                match from_utf8(&sectval) {
                    Ok(b) => println!("{}", b),
                    Err(e) => println!("Error dec: {:?}\n{:?}", e, sectval),
                }
            }
        }

        let mut mail: Vec<u8> = Vec::new();

        if let Some(part_body) = req
            .encapsulated_sections
            .as_ref()
            .unwrap()
            .get(&SectionType::ResponseBody)
        {
            mail.extend_from_slice(&part_body);
        }

        let diff_length = mail_length - mail.len();

        if self.con.read_to_vec(&mut mail, diff_length).await.is_ok() {
            return Some(mail);
        }

        None
    }
}

struct ICAPResponse {
    pub code: u16,
    pub reason: Option<String>,
    pub headers: Option<Vec<(String, String)>>,
}

impl ICAPResponse {
    fn new(code: u16, reason: Option<&str>, headers: &[(&str, &str)]) -> Self {
        let headers = {
            let mut h: Vec<(String, String)> = Vec::new();

            for e in headers {
                h.push((e.0.to_string(), e.1.to_string()));
            }

            h
        };

        ICAPResponse {
            code,
            reason: reason.map(|s| s.to_string()),
            headers: Some(headers),
        }
    }

    fn with_code(code: u16) -> Self {
        ICAPResponse {
            code,
            reason: None,
            headers: None,
        }
    }

    fn with_code_reason(code: u16, reason: &str) -> Self {
        ICAPResponse {
            code,
            reason: Some(reason.to_string()),
            headers: None,
        }
    }
}

impl From<ICAPResponse> for String {
    fn from(r: ICAPResponse) -> Self {
        let mut s = String::new();

        s.push_str(&format!(
            "ICAP/1.0 {} {}\r\n",
            r.code,
            r.reason.unwrap_or_default()
        ));

        if let Some(headers) = r.headers {
            for (name, val) in headers {
                s.push_str(&name);
                s.push_str(": ");
                s.push_str(&val);
                s.push_str("\r\n");
            }
        }

        s.push_str("\r\n");

        s
    }
}