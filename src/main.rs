use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, Error};
use actix_web::http::header;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use chrono::{Duration, Utc};
use clap::Parser;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::future::{ready, Ready};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(author, version, about = "Dynamic Password Generator (UTC-based)")]
struct Args {
    #[arg(long, default_value_t = 80)]
    port: u16,
    
    #[arg(long)]
    password: Option<String>,
    
    #[arg(long, default_value_t = false)]
    secure_cookie: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct SaltEntry {
    name: String,
    salt: String,
}

#[derive(Deserialize, Debug)]
struct GenerateRequest {
    salt: String,
    offset: Option<i64>,
    time: Option<String>,
}

#[derive(Serialize, Debug)]
struct GenerateResponse {
    success: bool,
    password: Option<String>,
    time_seed: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, Debug)]
struct SaltsResponse {
    salts: Vec<SaltEntry>,
}

#[derive(Deserialize, Debug)]
struct SaltOperationRequest {
    name: String,
    salt: Option<String>,
}

#[derive(Serialize, Debug)]
struct SaltOperationResponse {
    success: bool,
    message: Option<String>,
    salts: Option<Vec<SaltEntry>>,
}

const CONFIG_DIR: &str = "config";
const SALTS_FILE: &str = "salts.json";

const SESSION_TIMEOUT_SECONDS: i64 = 600;

struct AppState {
    salts: Arc<Mutex<Vec<SaltEntry>>>,
    config_path: String,
    password: Option<String>,
    sessions: Arc<Mutex<std::collections::HashMap<String, i64>>>,
    secure_cookie: bool,
}

fn save_salts(salts: &[SaltEntry], config_path: &str) -> std::io::Result<()> {
    let file_path = Path::new(config_path).join(SALTS_FILE);
    let json_data = serde_json::to_string_pretty(salts)?;
    let mut file = File::create(&file_path)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
}

fn load_salts(config_path: &str) -> Vec<SaltEntry> {
    let file_path = Path::new(config_path).join(SALTS_FILE);
    if file_path.exists() {
        match File::open(&file_path) {
            Ok(mut file) => {
                let mut content = String::new();
                if file.read_to_string(&mut content).is_ok() {
                    if let Ok(salts) = serde_json::from_str(&content) {
                        return salts;
                    }
                }
            }
            Err(_) => {}
        }
    }
    vec![]
}

#[derive(Deserialize, Debug)]
struct LoginRequest {
    password: String,
}

#[derive(Serialize, Debug)]
struct LoginResponse {
    success: bool,
    message: Option<String>,
}

pub struct AuthMiddleware;

impl<S: 'static> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Transform = AuthService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthService { service }))
    }
}

pub struct AuthService<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for AuthService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();
        if path == "/login" || path == "/api/login" || path.starts_with("/static/") {
            let fut = self.service.call(req);
            return Box::pin(async move { fut.await });
        }

        let data = req.app_data::<web::Data<AppState>>();
        let (allow_access, _refresh_session) = if let Some(data) = data {
            if data.password.is_none() {
                (true, false)
            } else {
                if let Some(cookie) = req.cookie("session_id") {
                    let session_id = cookie.value().to_string();
                    let now = Utc::now().timestamp();
                    let mut sessions = data.sessions.lock().unwrap();
                    if let Some(&timestamp) = sessions.get(&session_id) {
                        if now - timestamp < SESSION_TIMEOUT_SECONDS {
                            sessions.insert(session_id, now);
                            (true, true)
                        } else {
                            sessions.remove(&session_id);
                            (false, false)
                        }
                    } else {
                        (false, false)
                    }
                } else {
                    (false, false)
                }
            }
        } else {
            (false, false)
        };

        if allow_access {
            let fut = self.service.call(req);
            Box::pin(async move { fut.await })
        } else {
            if path.starts_with("/api/") {
                Box::pin(async move {
                    Ok(req.into_response(
                        HttpResponse::Unauthorized()
                            .content_type("application/json")
                            .body(r#"{"success":false,"error":"Unauthorized"}"#),
                    ))
                })
            } else {
                Box::pin(async move {
                    Ok(req.into_response(
                        HttpResponse::Found()
                            .append_header((header::LOCATION, "/login"))
                            .finish(),
                    ))
                })
            }
        }
    }
}

fn calculate_dynamic_password(hour_seed: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hour_seed.as_bytes());
    hasher.update(salt.as_bytes());
    let result = hasher.finalize();

    let charset = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut password = String::new();
    for i in 0..8 {
        let idx = (result[i] as usize) % charset.len();
        password.push(charset.chars().nth(idx).unwrap());
    }
    password
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/index.html"))
}

#[get("/login")]
async fn login_page() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/login.html"))
}

#[post("/api/login")]
async fn login(data: web::Data<AppState>, req: web::Json<LoginRequest>) -> impl Responder {
    let password = req.password.trim();
    
    if let Some(auth_password) = &data.password {
        if password == auth_password {
            let session_id = Uuid::new_v4().to_string();
            let now = Utc::now().timestamp();
            data.sessions.lock().unwrap().insert(session_id.clone(), now);
            
            HttpResponse::Ok()
                .cookie(
                    actix_web::cookie::Cookie::build("session_id", session_id)
                        .http_only(true)
                        .secure(data.secure_cookie)
                        .path("/")
                        .finish()
                )
                .content_type("application/json")
                .json(LoginResponse {
                    success: true,
                    message: Some("Login successful".to_string()),
                })
        } else {
            HttpResponse::Unauthorized()
                .content_type("application/json")
                .json(LoginResponse {
                    success: false,
                    message: Some("Invalid password".to_string()),
                })
        }
    } else {
        HttpResponse::Ok()
            .content_type("application/json")
            .json(LoginResponse {
                success: true,
                message: Some("No password set".to_string()),
            })
    }
}

#[get("/api/salts")]
async fn get_salts(data: web::Data<AppState>) -> impl Responder {
    let salts = data.salts.lock().unwrap().clone();
    HttpResponse::Ok()
        .content_type("application/json")
        .json(SaltsResponse { salts })
}

#[post("/api/salts/add")]
async fn add_salt(data: web::Data<AppState>, req: web::Json<SaltOperationRequest>) -> impl Responder {
    let name = req.name.trim();
    let salt = req.salt.as_deref().unwrap_or("").trim();
    
    if name.is_empty() {
        return HttpResponse::BadRequest()
            .content_type("application/json")
            .json(SaltOperationResponse {
                success: false,
                message: Some("Name cannot be empty".to_string()),
                salts: None,
            });
    }
    
    if salt.is_empty() {
        return HttpResponse::BadRequest()
            .content_type("application/json")
            .json(SaltOperationResponse {
                success: false,
                message: Some("Salt cannot be empty".to_string()),
                salts: None,
            });
    }

    let config_path = data.config_path.clone();
    let mut salts = load_salts(&config_path);
    
    let is_update = salts.iter().any(|s| s.name == name);
    
    if is_update {
        for s in salts.iter_mut() {
            if s.name == name {
                s.salt = salt.to_string();
                break;
            }
        }
    } else {
        salts.push(SaltEntry {
            name: name.to_string(),
            salt: salt.to_string(),
        });
    }
    
    if let Err(e) = save_salts(&salts, &config_path) {
        eprintln!("Failed to save salts: {}", e);
    }
    
    let mut memory_salts = data.salts.lock().unwrap();
    *memory_salts = salts.clone();
    
    let message = if is_update {
        "Salt updated successfully".to_string()
    } else {
        "Salt added successfully".to_string()
    };
    
    HttpResponse::Ok()
        .content_type("application/json")
        .json(SaltOperationResponse {
            success: true,
            message: Some(message),
            salts: Some(salts),
        })
}

#[post("/api/salts/remove")]
async fn remove_salt(data: web::Data<AppState>, req: web::Json<SaltOperationRequest>) -> impl Responder {
    let name = req.name.trim();
    if name.is_empty() {
        return HttpResponse::BadRequest()
            .content_type("application/json")
            .json(SaltOperationResponse {
                success: false,
                message: Some("Name cannot be empty".to_string()),
                salts: None,
            });
    }

    let config_path = data.config_path.clone();
    let mut salts = load_salts(&config_path);
    let original_len = salts.len();
    
    salts.retain(|s| s.name != name);
    
    if salts.len() == original_len {
        return HttpResponse::BadRequest()
            .content_type("application/json")
            .json(SaltOperationResponse {
                success: false,
                message: Some("Salt not found".to_string()),
                salts: None,
            });
    }
    
    if let Err(e) = save_salts(&salts, &config_path) {
        eprintln!("Failed to save salts: {}", e);
    }

    let mut memory_salts = data.salts.lock().unwrap();
    *memory_salts = salts.clone();
    
    HttpResponse::Ok()
        .content_type("application/json")
        .json(SaltOperationResponse {
            success: true,
            message: Some("Salt removed successfully".to_string()),
            salts: Some(salts),
        })
}

#[post("/api/salts/refresh")]
async fn refresh_salts(data: web::Data<AppState>) -> impl Responder {
    let config_path = data.config_path.clone();
    let new_salts = load_salts(&config_path);
    
    let mut salts = data.salts.lock().unwrap();
    *salts = new_salts.clone();
    
    HttpResponse::Ok()
        .content_type("application/json")
        .json(SaltOperationResponse {
            success: true,
            message: Some("Salts refreshed successfully".to_string()),
            salts: Some(new_salts),
        })
}

#[post("/api/generate")]
async fn generate_password(
    req: web::Json<GenerateRequest>,
) -> impl Responder {
    let salt = req.salt.trim();
    if salt.is_empty() {
        return HttpResponse::BadRequest()
            .content_type("application/json")
            .json(GenerateResponse {
                success: false,
                password: None,
                time_seed: None,
                error: Some("Salt is required".to_string()),
            });
    }

    if req.offset.is_some() && req.time.is_some() {
        return HttpResponse::BadRequest()
            .content_type("application/json")
            .json(GenerateResponse {
                success: false,
                password: None,
                time_seed: None,
                error: Some("Offset and time cannot be specified simultaneously".to_string()),
            });
    }

    let hour_seed = match &req.time {
        Some(t) => {
            if t.len() != 10 {
                return HttpResponse::BadRequest()
                    .content_type("application/json")
                    .json(GenerateResponse {
                        success: false,
                        password: None,
                        time_seed: None,
                        error: Some(format!(
                            "Time format invalid! Expected YYYYMMDDHH (10 digits), actual length: {}",
                            t.len()
                        )),
                    });
            }
            t.clone()
        }
        None => {
            let offset = req.offset.unwrap_or(0);
            let target_time = Utc::now() + Duration::hours(offset);
            target_time.format("%Y%m%d%H").to_string()
        }
    };

    let password = calculate_dynamic_password(&hour_seed, salt);

    HttpResponse::Ok()
        .content_type("application/json")
        .json(GenerateResponse {
            success: true,
            password: Some(password),
            time_seed: Some(hour_seed),
            error: None,
        })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    println!("Server starting on port {}...", args.port);
    if args.password.is_some() {
        println!("Password protection enabled.");
    }

    fs::create_dir_all(CONFIG_DIR)?;
    let config_path = CONFIG_DIR.to_string();
    let file_path = Path::new(&config_path).join(SALTS_FILE);
    let initial_salts = load_salts(&config_path);
    
    if !file_path.exists() {
        save_salts(&initial_salts, &config_path)?;
    }
    
    let salts = Arc::new(Mutex::new(initial_salts));    

    let sessions = Arc::new(Mutex::new(std::collections::HashMap::new()));

    let sessions_clone = sessions.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let now = Utc::now().timestamp();
            let mut sessions = sessions_clone.lock().unwrap();
            sessions.retain(|_, &mut timestamp| now - timestamp < SESSION_TIMEOUT_SECONDS);
        }
    });

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                salts: salts.clone(),
                config_path: config_path.clone(),
                password: args.password.clone(),
                sessions: sessions.clone(),
                secure_cookie: args.secure_cookie,
            }))
            .wrap(AuthMiddleware)
            .service(login_page)
            .service(login)
            .service(index)
            .service(get_salts)
            .service(add_salt)
            .service(remove_salt)
            .service(refresh_salts)
            .service(generate_password)
    })
    .bind(("0.0.0.0", args.port))?
    .run()
    .await
}