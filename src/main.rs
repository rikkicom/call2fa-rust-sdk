use reqwest::StatusCode;
use reqwest::blocking::Client as BlockingClient;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Custom Error type for the client, covering various failure scenarios.
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("The login parameter is empty")]
    EmptyLogin,
    #[error("The password parameter is empty")]
    EmptyPassword,
    #[error("The phone number parameter is empty")]
    EmptyPhoneNumber,
    #[error("The pool ID parameter is empty")]
    EmptyPoolId,
    #[error("The code parameter is empty")]
    EmptyCode,
    #[error("The lang parameter is empty")]
    EmptyLang,
    #[error("The call ID parameter is empty")]
    EmptyId,
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("API returned an unexpected status code: {0}")]
    UnexpectedStatusCode(StatusCode),
    #[error("Failed to deserialize JSON response: {0}")]
    DeserializationFailed(String),
    #[error("JWT not found in authentication response")]
    JwtNotFound,
}

/// Represents the client for the Rikkicom `Call2FA` API.
#[derive(Debug)]
pub struct Client {
    #[allow(clippy::struct_field_names)]
    http_client: BlockingClient,
    base_uri: String,
    version: String,
    jwt: String,
}

// Structs for API request bodies
#[derive(Serialize)]
struct AuthRequest<'a> {
    login: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct CallRequest<'a> {
    phone_number: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    callback_url: &'a str,
}

#[derive(Serialize)]
struct CallWithCodeRequest<'a> {
    phone_number: &'a str,
    code: &'a str,
    lang: &'a str,
}

#[derive(Serialize)]
struct PoolCallRequest<'a> {
    phone_number: &'a str,
}

// Struct for the authentication response
#[derive(Deserialize)]
struct AuthResponse {
    jwt: String,
}

impl Client {
    /// Creates a new client instance and authenticates with the API.
    ///
    /// # Arguments
    ///
    /// * `login` - The customer's API login.
    /// * `password` - The customer's API password.
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Client` instance or a `ClientError`.
    ///
    /// # Errors
    ///
    /// Will return `Err` if parameters are empty
    pub fn new(login: &str, password: &str) -> Result<Self, ClientError> {
        if login.is_empty() {
            return Err(ClientError::EmptyLogin);
        }
        if password.is_empty() {
            return Err(ClientError::EmptyPassword);
        }

        let http_client = BlockingClient::new();
        let base_uri = "https://api-call2fa.rikkicom.io".to_string();
        let version = "v1".to_string();

        let jwt = Self::receive_jwt(&http_client, &base_uri, &version, login, password)?;

        Ok(Self {
            http_client,
            base_uri,
            version,
            jwt,
        })
    }

    /// Fetches the JSON Web Token from the API.
    ///
    /// # Errors
    ///
    /// Will return `Err` if status code is not 200.
    fn receive_jwt(
        http_client: &BlockingClient,
        base_uri: &str,
        version: &str,
        login: &str,
        password: &str,
    ) -> Result<String, ClientError> {
        let uri = format!("{base_uri}/{version}/auth/");
        let auth_data = AuthRequest { login, password };

        let response = http_client.post(&uri).json(&auth_data).send()?;

        if response.status() == StatusCode::OK {
            let auth_response: AuthResponse = response
                .json()
                .map_err(|e| ClientError::DeserializationFailed(e.to_string()))?;
            Ok(auth_response.jwt)
        } else {
            Err(ClientError::UnexpectedStatusCode(response.status()))
        }
    }

    /// Initiates a new call.
    ///
    /// # Errors
    ///
    /// Will return `Err` if status code is not 200.
    pub fn call(
        &self,
        phone_number: &str,
        callback_url: &str,
    ) -> Result<serde_json::Value, ClientError> {
        if phone_number.is_empty() {
            return Err(ClientError::EmptyPhoneNumber);
        }

        let uri = self.make_full_uri("call");
        let call_data = CallRequest {
            phone_number,
            callback_url,
        };

        let response = self
            .http_client
            .post(&uri)
            .bearer_auth(&self.jwt)
            .json(&call_data)
            .send()?;

        if response.status() == StatusCode::CREATED {
            Ok(response.json()?)
        } else {
            Err(ClientError::UnexpectedStatusCode(response.status()))
        }
    }

    /// Initiates a new call via the last digits mode.
    ///
    /// # Errors
    ///
    /// Will return `Err` if parameters are empty or status code is not 200.
    pub fn call_via_last_digits(
        &self,
        phone_number: &str,
        pool_id: &str,
        use_six_digits: bool,
    ) -> Result<serde_json::Value, ClientError> {
        if phone_number.is_empty() {
            return Err(ClientError::EmptyPhoneNumber);
        }
        if pool_id.is_empty() {
            return Err(ClientError::EmptyPoolId);
        }

        let method = if use_six_digits {
            format!("pool/{pool_id}/call/six-digits")
        } else {
            format!("pool/{pool_id}/call")
        };
        let uri = self.make_full_uri(&method);
        let call_data = PoolCallRequest { phone_number };

        let response = self
            .http_client
            .post(&uri)
            .bearer_auth(&self.jwt)
            .json(&call_data)
            .send()?;

        if response.status() == StatusCode::CREATED {
            Ok(response.json()?)
        } else {
            Err(ClientError::UnexpectedStatusCode(response.status()))
        }
    }

    /// Initiates a new call with a verification code.
    ///
    /// # Errors
    ///
    /// Will return `Err` if parameters are empty or status code is not 200.
    pub fn call_with_code(
        &self,
        phone_number: &str,
        code: &str,
        lang: &str,
    ) -> Result<serde_json::Value, ClientError> {
        if phone_number.is_empty() {
            return Err(ClientError::EmptyPhoneNumber);
        }
        if code.is_empty() {
            return Err(ClientError::EmptyCode);
        }
        if lang.is_empty() {
            return Err(ClientError::EmptyLang);
        }

        let uri = self.make_full_uri("code/call");
        let call_data = CallWithCodeRequest {
            phone_number,
            code,
            lang,
        };

        let response = self
            .http_client
            .post(&uri)
            .bearer_auth(&self.jwt)
            .json(&call_data)
            .send()?;

        if response.status() == StatusCode::CREATED {
            Ok(response.json()?)
        } else {
            Err(ClientError::UnexpectedStatusCode(response.status()))
        }
    }

    /// Gets information about a call by its identifier.
    /// # Errors
    ///
    /// Will return `Err` if `id` is empty or status code is not 200.
    pub fn info(&self, id: &str) -> Result<serde_json::Value, ClientError> {
        if id.is_empty() {
            return Err(ClientError::EmptyId);
        }

        let uri = self.make_full_uri(&format!("call/{id}"));

        let response = self.http_client.get(&uri).bearer_auth(&self.jwt).send()?;

        if response.status() == StatusCode::OK {
            Ok(response.json()?)
        } else {
            Err(ClientError::UnexpectedStatusCode(response.status()))
        }
    }

    /// Creates a full URI to the specified API method.
    fn make_full_uri(&self, method: &str) -> String {
        format!("{}/{}/{}/", self.base_uri, self.version, method)
    }

    /// Returns the current API version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Sets a different API version.
    pub fn set_version(&mut self, version: String) {
        self.version = version;
    }
}

/// This function contains the core logic and can return a Result.
fn run(login: &str, password: &str, call_to: &str, callback_url: &str) -> Result<(), ClientError> {
    // Create the Call2FA client. The `?` operator will propagate any error from `Client::new`.
    let client = Client::new(login, password)?;
    println!("Client created successfully.");

    // Make a call. The `?` operator will propagate any error from `client.call`.
    let response = client.call(call_to, callback_url)?;
    println!("Call initiated successfully.");

    // Print the successful response. `serde_json::to_string_pretty` is used for nice formatting.
    match serde_json::to_string_pretty(&response) {
        Ok(json_string) => println!("Response:\n{json_string}"),
        Err(_) => println!("Could not format response JSON. Raw: {response:?}"),
    }

    // Result looks like the following:
    // {
    //   "call_id": "95831458"
    // }

    Ok(())
}

fn main() {
    // Initialize the logger. This allows reqwest to print debug information.
    // You can control the log level via the RUST_LOG environment variable.
    // For example: `RUST_LOG=debug cargo run`
    env_logger::init();

    // API credentials - replace with your actual login and password.
    let login = "***";
    let password = "***";

    // Configuration for this call
    let call_to = "+380631010121";
    let callback_url = "https://httpbin.org/post";

    println!("Attempting to create Call2FA client and make a call...");

    // The `main` function in Rust cannot directly return a Result,
    // so we handle the Result from the `run` function.
    if let Err(e) = run(login, password, call_to, callback_url) {
        eprintln!("Something went wrong:");
        eprintln!("{e}");
        std::process::exit(1);
    }
}
