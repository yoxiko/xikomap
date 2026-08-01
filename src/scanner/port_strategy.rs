use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortStrategy {
    Top10,
    Top100,
    Top1000,
    Web,
    Database,
    Custom(Vec<u16>),
}

impl PortStrategy {
    pub fn get_ports(&self) -> Vec<u16> {
        match self {
            PortStrategy::Top10 => vec![21, 22, 23, 25, 53, 80, 110, 143, 443, 3389],
            PortStrategy::Top100 => get_top_100(),
            PortStrategy::Top1000 => get_top_1000(),
            PortStrategy::Web => vec![80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9090],
            PortStrategy::Database => vec![1433, 1521, 3306, 5432, 5984, 6379, 27017, 27018, 28017, 9042],
            PortStrategy::Custom(ports) => ports.clone(),
        }
    }

    pub fn from_str(strategy: &str, custom_ports: Option<&str>) -> Self {
        match strategy.to_lowercase().as_str() {
            "top10" => PortStrategy::Top10,
            "top100" => PortStrategy::Top100,
            "top1000" => PortStrategy::Top1000,
            "web" => PortStrategy::Web,
            "database" => PortStrategy::Database,
            "custom" => {
                if let Some(ports_str) = custom_ports {
                    let ports = parse_port_ranges(ports_str);
                    PortStrategy::Custom(ports)
                } else {
                    PortStrategy::Top100
                }
            }
            _ => PortStrategy::Top100,
        }
    }
}

fn parse_port_ranges(ranges: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in ranges.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() == 2 {
                if let (Ok(start), Ok(end)) = (bounds[0].parse::<u16>(), bounds[1].parse::<u16>()) {
                    for i in start..=end {
                        ports.push(i);
                    }
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

fn get_top_100() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 1723, 2049, 3306,
        3389, 5432, 5900, 5984, 6379, 8080, 8443, 8888, 9090, 27017, 13, 17, 19, 37, 42, 49, 50, 67, 68, 69,
        70, 79, 88, 102, 113, 119, 123, 137, 138, 161, 162, 175, 177, 179, 199, 211, 254, 264, 280, 311, 340,
        366, 389, 406, 407, 427, 464, 465, 497, 500, 512, 513, 514, 515, 520, 521, 540, 548, 554, 563, 587,
        593, 623, 625, 626, 631, 636, 646, 648, 666, 683, 691, 695, 749, 750, 751, 752, 754, 765, 780, 783,
        787, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 999, 1000,
        1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039,
        1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056,
        1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073,
        1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
        1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100
    ]
}

fn get_top_1000() -> Vec<u16> {
    let mut ports = get_top_100();
    for i in 1101..=2000 {
        ports.push(i);
    }
    ports
}