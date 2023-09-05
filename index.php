<?php

header("Content-type: application/json;");
error_reporting(0);
include "functions.php";

function generateUniqueRandomNumbers($max, $count)
{
    $randomNumbers = [];

    while (count($randomNumbers) < $count) {
        $number = mt_rand(0, $max);

        if (!in_array($number, $randomNumbers)) {
            $randomNumbers[] = $number;
        }
    }

    sort($randomNumbers);

    return $randomNumbers;
}

function process_jsons($input, $locationNames)
{
    $input[0]["outbounds"] = array_merge(
        $input[0]["outbounds"],
        array_filter($locationNames)
    );
    return $input;
}

function extract_names($input)
{
    foreach ($input as $config) {
        if ($config["tag"] !== "") {
            $locationNames[] = $config["tag"];
        }
    }
    return $locationNames;
}

function VmessSingbox($VmessUrl, $counter)
{
    $decode_vmess = decode_vmess($VmessUrl);
    if (is_null($decode_vmess["ps"]) || $decode_vmess["ps"] === "") {
        return null;
    }
    $configResult = [
        "tag" => $decode_vmess["ps"] . " | " . $counter,
        "type" => "vmess",
        "server" => $decode_vmess["add"],
        "server_port" => intval($decode_vmess["port"]),
        "uuid" => $decode_vmess["id"],
        "security" => "auto",
        "alter_id" => intval($decode_vmess["aid"]),
        "global_padding" => false,
        "authenticated_length" => true,
        "packet_encoding" => "",
        "multiplex" => [
            "enabled" => false,
            "protocol" => "smux",
            "max_streams" => 32,
        ],
    ];

    if ($decode_vmess["port"] === "443" || $decode_vmess["tls"] === "tls") {
        $configResult["tls"] = [
            "enabled" => true,
            "server_name" =>
                $decode_vmess["sni"] !== ""
                    ? $decode_vmess["sni"]
                    : $decode_vmess["add"],
            "insecure" => true,
            "disable_sni" => false,
            "utls" => [
                "enabled" => true,
                "fingerprint" => "chrome",
            ],
        ];
    }

    if ($decode_vmess["net"] === "ws") {
        $configResult["transport"] = [
            "type" => $decode_vmess["net"],
            "path" => strpos($decode_vmess["path"], '/') === 0 ? $decode_vmess["path"] : "/" . $decode_vmess["path"],
            "headers" => [
                "Host" =>
                    $decode_vmess["host"] !== ""
                        ? $decode_vmess["host"]
                        : ($decode_vmess["add"] !== ""
                            ? $decode_vmess["add"]
                            : ""),
            ],
            "max_early_data" => 0,
            "early_data_header_name" => "Sec-WebSocket-Protocol",
        ];
    } elseif ($decode_vmess["net"] === "grpc") {
        $configResult["transport"] = [
            "type" => $decode_vmess["net"],
            "service_name" => $decode_vmess["path"],
            "idle_timeout" => "15s",
            "ping_timeout" => "15s",
            "permit_without_stream" => false,
        ];
    }

    return $configResult;
}

function VlessSingbox($VlessUrl, $counter)
{
    $decoded_vless = parseProxyUrl($VlessUrl, "vless");
    //print_r($decoded_vless);
    if (is_null($decoded_vless["hash"]) || $decoded_vless["hash"] === "") {
        return null;
    }
    $configResult = [
        "tag" => $decoded_vless["hash"] . " | " . $counter,
        "type" => "vless",
        "server" => $decoded_vless["hostname"],
        "server_port" => intval($decoded_vless["port"]),
        "uuid" => $decoded_vless["username"],
        "flow" => !is_null($decoded_vless["params"]["flow"])
            ? "xtls-rprx-vision"
            : "",
        "packet_encoding" => "xudp",
        "multiplex" => [
            "enabled" => false,
            "protocol" => "smux",
            "max_streams" => 32,
        ],
    ];

    if (
        $decoded_vless["port"] === "443" ||
        $decoded_vless["params"]["security"] === "tls" ||
        $decoded_vless["params"]["security"] === "reality"
    ) {
        $configResult["tls"] = [
            "enabled" => true,
            "server_name" => !is_null($decoded_vless["params"]["sni"])
                ? $decoded_vless["params"]["sni"]
                : "",
            "insecure" => false,
            "utls" => [
                "enabled" => true,
                "fingerprint" => "chrome",
            ],
        ];

        if (
            $decoded_vless["params"]["security"] === "reality" ||
            isset($decoded_vless["params"]["pbk"])
        ) {
            $configResult["tls"]["reality"] = [
                "enabled" => true,
                "public_key" => !is_null($decoded_vless["params"]["pbk"])
                    ? $decoded_vless["params"]["pbk"]
                    : "",
                "short_id" => !is_null($decoded_vless["params"]["sid"])
                    ? $decoded_vless["params"]["sid"]
                    : "",
            ];
        if (
            is_null($decoded_vless["params"]["pbk"]) or
            $decoded_vless["params"]["pbk"] === ""
        ) {
            return null;
        }
        }
    }
    $transportTypes = [
        "ws" => [
            "type" => $decoded_vless["params"]["type"],
            "path" => strpos($decoded_vless["params"]["path"], '/') === 0 ? $decoded_vless["params"]["path"] : "/" . $decoded_vless["params"]["path"],
            "headers" => [
                "Host" => !is_null($decoded_vless["params"]["host"])
                    ? $decoded_vless["params"]["host"]
                    : "",
            ],
            "max_early_data" => 0,
            "early_data_header_name" => "Sec-WebSocket-Protocol",
        ],
        "grpc" => [
            "type" => $decoded_vless["params"]["type"],
            "service_name" => $decoded_vless["params"]["serviceName"],
            "idle_timeout" => "15s",
            "ping_timeout" => "15s",
            "permit_without_stream" => false,
        ],
    ];
    if (isset($decoded_vless["params"]["type"])) {
        if (
            $decoded_vless["params"]["type"] === "ws" ||
            $decoded_vless["params"]["type"] === "grpc"
        ) {
            $configResult["transport"] =
                $transportTypes[$decoded_vless["params"]["type"]];
        }
    }
    return $configResult;
}

function TrojanSingbox($TrojanUrl, $counter)
{
    $decoded_trojan = parseProxyUrl($TrojanUrl);
    if (is_null($decoded_trojan["hash"]) || $decoded_trojan["hash"] === "") {
        return null;
    }
    $configResult = [
        "tag" => $decoded_trojan["hash"] . " | " . $counter,
        "type" => "trojan",
        "server" => $decoded_trojan["hostname"],
        "server_port" => intval($decoded_trojan["port"]),
        "password" => $decoded_trojan["username"],
        "multiplex" => [
            "enabled" => false,
            "protocol" => "smux",
            "max_streams" => 32,
        ],
    ];

    if (
        $decoded_trojan["port"] === "443" ||
        $decoded_trojan["params"]["security"] === "tls"
    ) {
        $configResult["tls"] = [
            "enabled" => true,
            "server_name" => !is_null($decoded_trojan["params"]["sni"])
                ? $decoded_trojan["params"]["sni"]
                : "",
            "insecure" => true,
            "utls" => [
                "enabled" => true,
                "fingerprint" => "chrome",
            ],
        ];
    }

    $transportTypes = [
        "ws" => [
            "type" => $decoded_trojan["params"]["type"],
            "path" => strpos($decoded_trojan["params"]["path"], '/') === 0 ? $decoded_trojan["params"]["path"] : "/" . $decoded_trojan["params"]["path"],
            "headers" => [
                "Host" => $decoded_trojan["params"]["host"],
            ],
        ],
        "grpc" => [
            "type" => $decoded_trojan["params"]["type"],
            "service_name" => $decoded_trojan["params"]["serviceName"],
            "idle_timeout" => "15s",
            "ping_timeout" => "15s",
            "permit_without_stream" => false,
        ],
    ];
    if (isset($decoded_trojan["params"]["type"])) {
        if (
            $decoded_trojan["params"]["type"] === "ws" ||
            $decoded_trojan["params"]["type"] === "grpc"
        ) {
            $configResult["transport"] =
                $transportTypes[$decoded_trojan["params"]["type"]];
        }
    }
    return $configResult;
}

function ShadowsocksSingbox($ShadowsocksUrl, $counter)
{
    $decoded_shadowsocks = ParseShadowsocks($ShadowsocksUrl);
    if (
        is_null($decoded_shadowsocks["name"]) ||
        $decoded_shadowsocks["name"] === ""
    ) {
        return null;
    }
    $configResult = [
        "tag" => $decoded_shadowsocks["name"] . " | " . $counter,
        "type" => "shadowsocks",
        "server" => $decoded_shadowsocks["server_address"],
        "server_port" => intval($decoded_shadowsocks["server_port"]),
        "method" => isset($decoded_shadowsocks["encryption_method"]) && $decoded_shadowsocks["encryption_method"] !== "" ? $decoded_shadowsocks["encryption_method"] : "chacha20-ietf-poly1305",
        "password" => $decoded_shadowsocks["password"],
        "plugin" => "",
        "plugin_opts" => "",
    ];
  
    if ($configResult['method'] === "chacha20-poly1305") {
        return null;
     }
    return $configResult;
}

function TuicSingbox($TuicUrl, $counter) {
    $decodedTuic = ParseTuic($TuicUrl);
    if (
        is_null($decodedTuic['hash']) ||
        $decodedTuic['hash'] === ""
    ) {
        return null;
    }

    $configResult = [
        "tag" => $decodedTuic["hash"] . " | " . $counter,
        "type" => "tuic",
        "server" => $decodedTuic['hostname'],
        "server_port" => intval($decodedTuic['port']),
        "uuid" => $decodedTuic['username'],
        "password" => $decodedTuic['password'],
        "congestion_control" => $decodedTuic['params']['congestion_control'],
        "udp_relay_mode" => $decodedTuic['params']['udp_relay_mode'],
        "zero_rtt_handshake" => false,
        "heartbeat" => "10s",
        "network" => "tcp",
    ];

    $configResult['tls'] = [
            "enabled" => true,
            "disable_sni" => isset($decodedTuic['params']['sni']) ? false : true,
            "server_name" => isset($decodedTuic['params']['sni']) ? $decodedTuic['params']['sni'] : "",
            "insecure" => isset($decodedTuic['params']['allow_insecure']) && intval($decodedTuic['params']['allow_insecure']) === 1 ? true : false,
            "alpn" => [
                "h3",
                "spdy/3.1"
            ],
        ];

    return $configResult;
}

function GenerateConfigLite($input, $output, $limit = 0, $tun = true)
{
    $outbound = [];
    $v2ray_subscription = str_replace(" ", "%20", $input);
    $pattern = '/(\w+:\/\/[^\s]+)/'; // Regular expression pattern

    preg_match_all($pattern, $v2ray_subscription, $matches);

    $configArray = $matches[0];
    $max = count($configArray);
    $counter = 1;
    $limitNumbersArray = [];
    if ($limit >= 1) {
        $limitNumbersArray = generateUniqueRandomNumbers($max - 1, $limit + 1);
    }
    foreach ($configArray as $config) {
        $configType = detect_type($config);
        $config = str_replace("%20", " ", $config);
        switch ($configType) {
            case "vmess":
                $configSingbox = VmessSingbox($config, $counter);
                break;
            case "vless":
                $configSingbox = VlessSingbox(urldecode($config), $counter);
                break;
            case "trojan":
                $configSingbox = TrojanSingbox(urldecode($config), $counter);
                break;
            case "ss":
                $configSingbox = ShadowsocksSingbox(urldecode($config), $counter);
                break;
            case "tuic":
                $configSingbox = TuicSingbox(urldecode($config), $counter);
                break;
            default:
                $configSingbox = null;
        }
        if (!is_null($configSingbox)) {
            if (!in_array($configSingbox, $outbound)) {
                if (isset($limitNumbersArray[0])) {
                    if (in_array($counter, $limitNumbersArray)) {
                        $outbound[] = $configSingbox;
                    }
                } else {
                    $outbound[] = $configSingbox;
                }
                $counter++;
            }
        }
    }
    if ($tun) {
        $templateMap = [
            "nold" => "nekobox_1.1.7.json",
            "nnew" => "nekobox_1.1.8.json",
            "sfia" => "sfi.json",
        ];
    } else {
        $templateMap = [
            "nold" => "nekobox_1.1.7_notun.json",
            "nnew" => "nekobox_1.1.8_notun.json",
            "sfia" => "sfi_notun.json",
        ];
    }
    $templateBase = json_decode(
        file_get_contents("templates/" . $templateMap[$output]),
        true
    );
    $templateManual = json_decode(
        file_get_contents("templates/manual.json"),
        true
    );
    $templateUrltest = json_decode(
        file_get_contents("templates/url_test.json"),
        true
    );

    $names = extract_names($outbound);
    $outboundManual = process_jsons($templateManual, $names);
    $outboundUrltest = process_jsons($templateUrltest, $names);

    $templateBase["outbounds"] = array_merge(
        $outboundManual,
        $outboundUrltest,
        $outbound,
        $templateBase["outbounds"]
    );
    return json_encode(
        $templateBase,
        JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
    );
}

function beginConvertSubLink($subLink, $limit = 0, $tun = true)
{
    $subData = file_get_contents($subLink);
    if (is_base64_encoded($subData) === "true") {
        $subDataFinal = base64_decode($subData);
    } else {
        $subDataFinal = $subData;
    }

    $convertedData = GenerateConfigLite($subDataFinal, "sfia", $limit, $tun);

    return $convertedData;
}

function beginConvertConfigs($configs, $limit = 0, $tun = true)
{
    $configData = base64_decode($configs);
    $convertedData = GenerateConfigLite($configData, "sfia", $limit, $tun);

    return $convertedData;
}
  
$url = filter_input(INPUT_GET, "url", FILTER_VALIDATE_URL);
$config = filter_input(INPUT_GET, "config", FILTER_SANITIZE_STRING);
$limiter = filter_input(INPUT_GET, "limit", FILTER_VALIDATE_INT);
$tun = filter_input(INPUT_GET, "tun", FILTER_VALIDATE_BOOLEAN);

try {
    if (!$url && !$config) {
        throw new Exception("url or config parameter is missing or invalid");
    }

    if ($url) {
        echo beginConvertSubLink(
            $url,
            isset($limiter) ? $limiter : 0,
            isset($tun) ? $tun : true,
        );
    } elseif ($config) {
        echo beginConvertConfigs(
            $config,
            isset($limiter) ? $limiter : 0,
            isset($tun) ? $tun : true,
        );
    }
} catch (Exception $e) {
    $output = [
        "ok" => false,
        "result" => $e->getMessage(),
    ];
    echo json_encode($output, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}
