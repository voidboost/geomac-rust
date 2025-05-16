use futures::{ future, stream, StreamExt };
use reqwest::{ Client, StatusCode };
use std::time::Duration;
use tokio::{ self, time, main };

use std::collections::HashMap;
use itertools::Itertools;
use std::error::Error;

use std::env;
use protobuf::{ Message, MessageField };
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

use roxmltree::Document;
use serde_json::Value;
use chrono::offset::Local;

use std::io::Write;
use flate2::Compression;
use flate2::write::{ GzEncoder, GzDecoder };

use spinners::{ Spinner, Spinners };

use clap::Parser;
use regex::Regex;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "A simple program to get geolocation of Wi-Fi access points by their BSSIDs.\nGeolocation providers included in this release: Apple, Google, Microsoft, Mylnikov, Yandex.\nCopyright © 2025 voiboost",
    long_about = None
)]
struct Geomac {
    #[arg(
        value_parser = validate_bssid,
        required = true,
        help = "Router BSSID(s). Example: 11:22:33:44:55:66 or 11-22-33-44-55-66"
    )]
    bssids: Vec<String>,

    #[arg(
        short = 'P',
        long = "print-all",
        help = "Output providers that fail to determine location"
    )]
    print_all: bool,

    #[arg(
        short = 'T',
        long = "timeout",
        default_value_t = 3,
        help = "Requests timeout (in seconds, max=65535)"
    )]
    timeout: u16,
}

#[main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Geomac::parse();

    let timeout = Duration::from_secs(args.timeout.into());

    let client = Client::new();

    let providers: HashMap<String, String> = HashMap::from_iter([
        ("Apple".into(), "https://gs-loc.apple.com/clls/wloc".into()),
        ("Google".into(), "https://www.google.com/loc/m/api".into()),
        (
            "Microsoft".into(),
            "https://inference.location.live.net/inferenceservice/v21/Pox/GetLocationUsingFingerprint".into(),
        ),
        ("Mylnikov".into(), "https://api.mylnikov.org/geolocation/wifi".into()),
        ("Yandex".into(), "https://api.lbs.yandex.net/cellid_location/".into()),
    ]);

    let results: HashMap<String, ResponseResult> = HashMap::from_iter(
        providers.keys().map(|provider| { (provider.into(), ResponseResult::Timeout(true)) })
    );

    for bssid in &args.bssids {
        println!();

        let mut sp = Spinner::new(Spinners::Dots12, " calling the FBI..".into());

        let mut id = bssid.to_uppercase();
        id.retain(|c| c != ':' && c != '-');

        let mut normalized_mac = id.clone();
        for i in (2..11).step_by(2).rev() {
            normalized_mac.insert(i, ':');
        }

        let requests = vec![
            client
                .post(&providers["Apple"])
                .body({
                    let mut request = apple::Request::new();
                    request.set_noise(0);
                    request.set_signal(100);

                    let mut wifi = apple::request::RequestWifi::new();
                    wifi.set_mac(normalized_mac.clone());

                    request.wifis.push(wifi);

                    let bytes = request.write_to_bytes().unwrap();

                    let size = (bytes.len() as i16).to_be_bytes().to_vec();

                    let header =
                        b"\x00\x01\x00\x05en_US\x00\x13com.apple.locationd\x00\x0c8.4.1.12H321\x00\x00\x00\x01\x00\x00".to_vec();

                    vec![header, size, bytes].concat()
                })
                .send(),
            client
                .post(&providers["Google"])
                .body({
                    let mut request = google::Request::new();

                    let mut header = google::request::Header::new();
                    header.set_version("2021".to_string());
                    header.set_platform(
                        "android/LEAGOO/full_wf562g_leagoo/wf562g_leagoo:6.0/MRA58K/1511161770:user/release-keys".to_string()
                    );
                    header.set_locale("en_US".to_string());

                    request.header = MessageField::some(header);

                    let mut wifi1 = google::request::location::data::Wifi::new();
                    wifi1.set_text("".to_string());
                    wifi1.set_mac(i64::from_str_radix(&id, 16).unwrap());

                    let mut wifi2 = google::request::location::data::Wifi::new();
                    wifi2.set_text("".to_string());
                    wifi2.set_mac(i64::from_str_radix("112233445566", 16).unwrap());

                    let mut data = google::request::location::Data::new();
                    data.set_timestamp(162723);
                    data.wifis.push(wifi1);
                    data.wifis.push(wifi2);
                    data.set_size(2);

                    let mut location = google::request::Location::new();
                    location.data = MessageField::some(data);

                    request.locations.push(location);

                    let bytes = request.write_to_bytes().unwrap();

                    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
                    gzip.write_all(&bytes).unwrap();
                    let compressed_bytes = gzip.finish().unwrap();

                    let size = (compressed_bytes.len() as i32).to_be_bytes().to_vec();

                    let header = vec![
                        b"\x00\x02\x00\x00\x1flocation,2021,android,gms,en_US\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01g".to_vec(),
                        (187_i32).to_be_bytes().to_vec(),
                        b"\x00\x01\x01\x00\x01\x00\x08g:loc/ql\x00\x00\x00\x04POST\x6d\x72\x00\x00\x00\x04ROOT\x00".to_vec(),
                        size,
                        b"\x00\x01g".to_vec()
                    ].concat();

                    vec![header, compressed_bytes, b"\x00\x00".to_vec()].concat()
                })
                .send(),
            client
                .post(&providers["Microsoft"])
                .body(
                    format!(
                        "<GetLocationUsingFingerprint xmlns=\"http://inference.location.live.com\"><RequestHeader><Timestamp>{:?}</Timestamp><ApplicationId>e1e71f6b-2149-45f3-a298-a20682ab5017</ApplicationId><TrackingId>21BF9AD6-CFD3-46B3-B041-EE90BD34FDBC</TrackingId><DeviceProfile ClientGuid=\"0fc571be-4624-4ce0-b04e-911bdeb1a222\" Platform=\"Windows7\" DeviceType=\"PC\" OSVersion=\"7600.16695.amd64fre.win7_gdr.101026-1503\" LFVersion=\"9.0.8080.16413\" ExtendedDeviceInfo=\"\" /><Authorization /></RequestHeader><BeaconFingerprint><Detections><Wifi7 BssId=\"{}\" rssi=\"-1\" /></Detections></BeaconFingerprint></GetLocationUsingFingerprint>",
                        Local::now(),
                        normalized_mac
                    )
                )
                .send(),
            client
                .get(&providers["Mylnikov"])
                .query(
                    &[
                        ("v", "1.1"),
                        ("data", "open"),
                        ("bssid", &normalized_mac),
                    ]
                )
                .send(),
            client
                .get(&providers["Yandex"])
                .query(&[("wifinetworks", format!("{}:-65", id))])
                .send()
        ];

        let mut results = results.clone();

        let responses = stream
            ::iter(requests)
            .map(|request| { tokio::spawn(time::timeout(timeout, async move { request.await })) })
            .buffer_unordered(5)
            .filter_map(|join| future::ready(join.ok()))
            .filter_map(|timeout| future::ready(timeout.ok()))
            .filter_map(|result| {
                if result.is_err() {
                    let url = result.as_ref().err().unwrap().url().unwrap().to_string();

                    for provider in providers.keys() {
                        if url.contains(&providers[provider]) {
                            results.insert(provider.into(), ResponseResult::Timeout(false));
                        }
                    }
                }

                future::ready(result.ok())
            })
            .collect::<Vec<_>>().await;

        for response in responses {
            let url = response.url().to_string();

            if response.status() == StatusCode::OK {
                if url.contains(&providers["Apple"]) {
                    let data = response.bytes().await.unwrap().to_vec();

                    let index = {
                        let mut i = data.len();

                        let bytes = b"\x00\x00\x00\x01\x00\x00".to_vec();

                        for d in 0..data.len() - bytes.len() {
                            i = d;

                            for b in 0..bytes.len() {
                                if data[d + b] != bytes[b] {
                                    i = data.len();
                                    break;
                                }
                            }

                            if i != data.len() {
                                break;
                            }
                        }

                        i
                    };

                    let response = apple::Response::parse_from_bytes(&data[index + 8..]).unwrap();

                    if
                        response.wifis.len() > 0 &&
                        response.wifis[0].location.has_latitude() &&
                        response.wifis[0].location.has_longitude() &&
                        response.wifis[0].location.latitude() != -18000000000 &&
                        response.wifis[0].location.longitude() != -18000000000
                    {
                        results.insert(
                            "Apple".into(),
                            ResponseResult::Coordinates(
                                (response.wifis[0].location.latitude() as f64) *
                                    (10.0_f64).powf(-8.0),
                                (response.wifis[0].location.longitude() as f64) *
                                    (10.0_f64).powf(-8.0)
                            )
                        );
                    } else {
                        results.insert("Apple".into(), ResponseResult::Timeout(false));
                    }
                } else if url.contains(&providers["Google"]) {
                    let data = response.bytes().await.unwrap().to_vec();

                    let index = {
                        let mut i = data.len();

                        let bytes = b"\x1f\x8b".to_vec();

                        for d in 0..data.len() - bytes.len() {
                            i = d;

                            for b in 0..bytes.len() {
                                if data[d + b] != bytes[b] {
                                    i = data.len();
                                    break;
                                }
                            }

                            if i != data.len() {
                                break;
                            }
                        }

                        i
                    };

                    let mut gzip = GzDecoder::new(Vec::new());
                    gzip.write_all(&data[index..]).unwrap();
                    let decompressed_bytes = gzip.finish().unwrap();

                    let response = google::Response::parse_from_bytes(&decompressed_bytes).unwrap();

                    if response.data.wifis.len() > 0 {
                        for wifi in &response.data.wifis {
                            if
                                wifi.wifiData.location.has_latitude() &&
                                wifi.wifiData.location.has_longitude()
                            {
                                results.insert(
                                    "Google".into(),
                                    ResponseResult::Coordinates(
                                        (wifi.wifiData.location.latitude() as i32 as f64) *
                                            (10.0_f64).powf(-7.0),
                                        (wifi.wifiData.location.longitude() as i32 as f64) *
                                            (10.0_f64).powf(-7.0)
                                    )
                                );

                                break;
                            } else {
                                results.insert("Google".into(), ResponseResult::Timeout(false));
                            }
                        }
                    } else {
                        results.insert("Google".into(), ResponseResult::Timeout(false));
                    }
                } else if url.contains(&providers["Microsoft"]) {
                    let data = response.text().await.unwrap();
                    let xml = Document::parse(&data).unwrap();
                    let coordinates = xml
                        .descendants()
                        .find(|n| n.has_attribute("Latitude") && n.has_attribute("Longitude"));

                    if !coordinates.is_none() {
                        results.insert(
                            "Microsoft".into(),
                            ResponseResult::Coordinates(
                                coordinates
                                    .unwrap()
                                    .attribute("Latitude")
                                    .unwrap()
                                    .parse::<f64>()
                                    .unwrap(),
                                coordinates
                                    .unwrap()
                                    .attribute("Longitude")
                                    .unwrap()
                                    .parse::<f64>()
                                    .unwrap()
                            )
                        );
                    } else {
                        results.insert("Microsoft".into(), ResponseResult::Timeout(false));
                    }
                } else if url.contains(&providers["Mylnikov"]) {
                    let data = response.json::<Value>().await.unwrap();

                    if data["result"].as_i64().unwrap() == 200 {
                        results.insert(
                            "Mylnikov".into(),
                            ResponseResult::Coordinates(
                                data["data"]["lat"].as_f64().unwrap(),
                                data["data"]["lon"].as_f64().unwrap()
                            )
                        );
                    } else {
                        results.insert("Mylnikov".into(), ResponseResult::Timeout(false));
                    }
                } else if url.contains(&providers["Yandex"]) {
                    let data = response.text().await.unwrap();
                    let xml = Document::parse(&data).unwrap();
                    let coordinates = xml
                        .descendants()
                        .find(|n| n.has_attribute("latitude") && n.has_attribute("longitude"));

                    if !coordinates.is_none() {
                        results.insert(
                            "Yandex".into(),
                            ResponseResult::Coordinates(
                                coordinates
                                    .unwrap()
                                    .attribute("latitude")
                                    .unwrap()
                                    .parse::<f64>()
                                    .unwrap(),
                                coordinates
                                    .unwrap()
                                    .attribute("longitude")
                                    .unwrap()
                                    .parse::<f64>()
                                    .unwrap()
                            )
                        );
                    } else {
                        results.insert("Yandex".into(), ResponseResult::Timeout(false));
                    }
                }
            } else {
                for provider in providers.keys() {
                    if url.contains(&providers[provider]) {
                        results.insert(provider.into(), ResponseResult::Timeout(false));
                    }
                }
            }
        }

        if
            results.iter().any(|result| {
                match result.1 {
                    ResponseResult::Coordinates(_, _) => true,
                    ResponseResult::Timeout(_) => false,
                }
            })
        {
            sp.stop_with_message(format!("Results for {}", normalized_mac));
        } else if
            results.iter().all(|result| {
                match result.1 {
                    ResponseResult::Coordinates(_, _) => false,
                    ResponseResult::Timeout(timeout) => timeout.to_owned(),
                }
            })
        {
            sp.stop_with_message(format!("Results for {} not found (timeout)", normalized_mac));
        } else {
            sp.stop_with_message(format!("Results for {} not found", normalized_mac));
        }

        if args.print_all {
            for provider in providers.keys().sorted() {
                let result = results.get(provider).unwrap();

                match result {
                    ResponseResult::Coordinates(latitude, longitude) => {
                        println!("{:<12}| {:.6}, {:.6}", provider, latitude, longitude);
                    }
                    ResponseResult::Timeout(timeout) => {
                        if timeout.to_owned() {
                            println!("{:<12}| timeout", provider);
                        } else {
                            println!("{:<12}| not found", provider);
                        }
                    }
                }
            }
        } else {
            for (provider, result) in results.iter().sorted_by_key(|r| r.0) {
                match result {
                    ResponseResult::Coordinates(latitude, longitude) => {
                        println!("{:<12}| {:.6}, {:.6}", provider, latitude, longitude);
                    }
                    ResponseResult::Timeout(_) => {}
                }
            }
        }
    }

    Ok(())
}

lazy_static::lazy_static! {
    static ref BSSID_REGEX: Regex = Regex::new(
        r"^((?:[0-9a-fA-F]{2}[:-]?){5}[0-9a-fA-F]{2})$"
    ).unwrap();
}

fn validate_bssid(m: &str) -> Result<String, String> {
    if BSSID_REGEX.is_match(m) { Ok(m.into()) } else { Err("BSSID format invalid.".into()) }
}

#[derive(Clone)]
enum ResponseResult {
    Coordinates(f64, f64),
    Timeout(bool),
}
