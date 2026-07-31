use crate::detectors::web::detect_web;
use crate::detectors::database::detect_database;
use crate::detectors::mail::detect_mail;
use crate::detectors::ssh_ftp::detect_ssh_ftp;

pub fn parse_service_version(banner: &str, port: u16) -> String {
    if banner.is_empty() {
        return "unknown".to_string();
    }

    if let Some(version) = detect_web(banner, port) {
        return version;
    }

    if let Some(version) = detect_database(banner, port) {
        return version;
    }

    if let Some(version) = detect_mail(banner, port) {
        return version;
    }

    if let Some(version) = detect_ssh_ftp(banner, port) {
        return version;
    }

    "unknown".to_string()
}