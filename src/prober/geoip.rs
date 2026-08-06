use maxminddb::geoip2;
use maxminddb::Reader;
use std::net::IpAddr;

pub struct GeoIPInfo {
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub isp: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
}

impl GeoIPInfo {
    pub fn lookup(ip: &str, db_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut info = GeoIPInfo {
            country: None,
            city: None,
            latitude: None,
            longitude: None,
            isp: None,
            asn: None,
            asn_org: None,
        };

        let reader = Reader::open_readfile(db_path)?;
        let ip_addr: IpAddr = ip.parse()?;

        if let Ok(city) = reader.lookup::<geoip2::City>(ip_addr) {
            if let Some(country) = city.country {
                if let Some(names) = country.names {
                    if let Some(name) = names.get("en") {
                        info.country = Some(name.to_string());
                    }
                }
            }

            if let Some(city_data) = city.city {
                if let Some(names) = city_data.names {
                    if let Some(name) = names.get("en") {
                        info.city = Some(name.to_string());
                    }
                }
            }

            if let Some(location) = city.location {
                info.latitude = location.latitude;
                info.longitude = location.longitude;
            }
        }

        if let Ok(asn) = reader.lookup::<geoip2::Asn>(ip_addr) {
            info.asn = asn.autonomous_system_number;
            info.asn_org = asn.autonomous_system_organization.map(|s| s.to_string());
        }

        Ok(info)
    }

    pub fn lookup_simple(_ip: &str) -> Self {
        GeoIPInfo {
            country: None,
            city: None,
            latitude: None,
            longitude: None,
            isp: None,
            asn: None,
            asn_org: None,
        }
    }
}