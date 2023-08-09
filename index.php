<?php

header("Content-type: application/json;");
error_reporting(0);
include "functions.php";

function process_jsons($input, $locationNames){
    $input[0]['outbounds'] = array_merge($input[0]['outbounds'], array_filter($locationNames));
    return $input;
}

function extract_names($input){
    foreach($input as $config){
        if ($config['tag'] !== ""){
             $locationNames[] = $config['tag'];
        }
    }
    return $locationNames;
}

function VmessSingbox($VmessUrl, $counter) {
    $decode_vmess = decode_vmess($VmessUrl);
    if (is_null($decode_vmess['ps']) || $decode_vmess['ps'] === ""){
        return null;
    }
    $configResult = array(
        "tag"=> $decode_vmess['ps'] . " | " . $counter,
        "type"=> "vmess",
        "server"=> $decode_vmess['add'],
        "server_port"=> intval($decode_vmess['port']),
        "uuid"=> $decode_vmess['id'],
        "security"=> "auto",
        "alter_id"=> intval($decode_vmess['aid']),
        "global_padding"=> false,
        "authenticated_length"=> true,
        "packet_encoding"=> "",
        "multiplex"=> array(
          "enabled"=> false,
          "protocol"=> "smux",
          "max_streams"=> 32
        )
    );

    if ($decode_vmess['port'] === "443" || $decode_vmess['tls'] === "tls") {
        $configResult["tls"] = array(
            "enabled" => true,
            "server_name" => $decode_vmess['sni'] !== "" ? $decode_vmess['sni'] : $decode_vmess['add'],
            "insecure" => true,
            "disable_sni" => false,
            "utls"=> array(
                "enabled"=> true,
                "fingerprint"=> "chrome"
              )
        );
    }

    if ($decode_vmess['net'] === "ws") {
        $configResult["transport"] = array(
            "type" => $decode_vmess['net'],
            "path" => "/" . $decode_vmess['path'],
            "headers" => array(
                "Host" => ($decode_vmess['host'] !== "") ? $decode_vmess['host'] : ($decode_vmess['add'] !== "" ? $decode_vmess['add'] : "")
        ),
    "max_early_data" => 0,
    "early_data_header_name" => "Sec-WebSocket-Protocol"
);
    } elseif ($decode_vmess['net'] === "grpc") {
        $configResult["transport"] = array(
            "type" => $decode_vmess['net'],
            "service_name" => $decode_vmess['path'],
            "idle_timeout" => "15s",
            "ping_timeout" => "15s",
            "permit_without_stream" => false
        );
    }

    return $configResult;
}

function VlessSingbox($VlessUrl, $counter) {
    $decoded_vless = parseProxyUrl($VlessUrl, "vless");
    if (is_null($decoded_vless['hash']) || $decoded_vless['hash'] === ""){
        return null;
    }
    $configResult = array(
      "tag" => $decoded_vless['hash'] . " | " . $counter,
      "type" => "vless",
      "server" => $decoded_vless['hostname'],
      "server_port" => intval($decoded_vless['port']),
      "uuid" => $decoded_vless['username'],
      "flow" => !is_null($decoded_vless['params']['flow']) ?  $decoded_vless['params']['flow'] : "",
      "packet_encoding" => "xudp",
      "multiplex" => array(
        "enabled" => false,
        "protocol" => "smux",
        "max_streams" => 32
      )
    );
    
    if ($decoded_vless['port'] === "443" || $decoded_vless['params']["security"] === "tls" || $decoded_vless['params']["security"] === "reality") {
      $configResult["tls"] = array(
        "enabled"=> true,
          "server_name"=> !is_null($decoded_vless['params']['sni']) ? $decoded_vless['params']['sni'] : "",
          "insecure"=> false,
          "utls"=> array(
            "enabled"=> true,
            "fingerprint"=> "chrome"
          )
      );

      if ($decoded_vless['params']["security"] === "reality" || isset($decoded_vless['params']['pbk'])){
        $configResult['tls']['reality'] = array(
            "enabled"=> true,
            "public_key"=> $decoded_vless['params']["pbk"],
            "short_id"=> !is_null($decoded_vless['params']['sid']) ? $decoded_vless['params']["sid"] : ""
        );
      }
    }
    $transportTypes = array(
      "ws" => array(
        "type" => $decoded_vless['params']["type"],
        "path" => "/" . $decoded_vless['params']["path"],
        "headers" => array(
          "Host" => !is_null($decoded_vless['params']["host"]) ? $decoded_vless['params']["host"] : ""
        ),
        "max_early_data" => 0,
        "early_data_header_name" => "Sec-WebSocket-Protocol"
      ),
      "grpc" => array(
        "type" => $decoded_vless['params']["type"],
        "service_name" => $decoded_vless['params']["serviceName"],
        "idle_timeout" => "15s",
        "ping_timeout" => "15s",
        "permit_without_stream" => false
      )
    );
    if (isset($decoded_vless['params']["type"])){
        if ($decoded_vless['params']["type"] === "ws" || $decoded_vless['params']["type"] === "grpc"){
            $configResult["transport"] = $transportTypes[$decoded_vless['params']["type"]];
        }
        
    }
    return $configResult;
}

function TrojanSingbox($TrojanUrl , $counter){
    $decoded_trojan = parseProxyUrl($TrojanUrl);
    if (is_null($decoded_trojan['hash']) || $decoded_trojan['hash'] === ""){
        return null;
    }
    $configResult = array(
        "tag"=> $decoded_trojan['hash'] . " | " . $counter,
        "type"=> "trojan",
        "server"=> $decoded_trojan['hostname'],
        "server_port"=> intval($decoded_trojan['port']),
        "password"=> $decoded_trojan['username'],
        "multiplex"=> array(
          "enabled"=> false,
          "protocol"=> "smux",
          "max_streams"=> 32
        )
    );

    if ($decoded_trojan['port'] === "443" || $decoded_trojan['params']["security"] === "tls"){
        $configResult['tls'] = array(
            "enabled"=> true,
            "server_name"=> !is_null($decoded_trojan['params']['sni']) ? $decoded_trojan['params']['sni'] : "",
            "insecure"=> true,
            "utls"=> array(
                "enabled"=> true,
                "fingerprint"=> "chrome"
            )
        );
    }

    $transportTypes = array(
        "ws" => array(
            "type"=> $decoded_trojan['params']["type"],
            "path"=> "/" . $decoded_trojan['params']["path"],
            "headers"=> array(
                "Host"=> $decoded_trojan['params']["host"]
            )
          ),
          "grpc" => array(
            "type" => $decoded_trojan['params']["type"],
            "service_name" => $decoded_trojan['params']["serviceName"],
            "idle_timeout" => "15s",
            "ping_timeout" => "15s",
            "permit_without_stream" => false
          )
    );
    if (isset($decoded_trojan['params']["type"])){
        if ($decoded_trojan['params']["type"] === "ws" || $decoded_trojan['params']["type"] === "grpc"){
            $configResult["transport"] = $transportTypes[$decoded_trojan['params']["type"]];
        }
    }
    return $configResult;
}

function ShadowsocksSingbox($ShadowsocksUrl, $counter) {
    $decoded_shadowsocks = ParseShadowsocks($ShadowsocksUrl);
    if (is_null($decoded_shadowsocks['name']) || $decoded_shadowsocks['name'] === ""){
        return null;
    }
    $configResult = array(
        'tag' => $decoded_shadowsocks['name'] . " | " . $counter,
        'type' => "shadowsocks",
        'server' => $decoded_shadowsocks['server_address'],
        'server_port' => intval($decoded_shadowsocks['server_port']),
        'method' => $decoded_shadowsocks['encryption_method'],
        'password' => $decoded_shadowsocks['password'],
        'plugin' => "",
        'plugin_opts' => ""
    );
    return $configResult;
}

function GenerateConfigLite($input, $output){
    $outbound = array();
    $v2ray_subscription = $input;

    $configArray = explode("\n", $v2ray_subscription);
    $counter = 1;
    foreach ($configArray as $config) {
        $configType = detect_type($config);
        switch($configType) {
            case "vmess":
                $configSingbox = VmessSingbox($config, $counter);
                break;
            case "vless":
                $configSingbox = VlessSingbox($config, $counter);
                break;
            case "trojan":
                $configSingbox = TrojanSingbox($config, $counter);
                break;
            case "ss":
                $configSingbox = ShadowsocksSingbox($config, $counter);
                break;
            default:
                $configSingbox = null;
        }
        if (!is_null($configSingbox)){
            if (!in_array($configSingbox, $outbound)) {
                $outbound[] = $configSingbox;
              $counter++ ;
            }
        }
    }
    $templateMap = array(
        "nold" => "nekobox_1.1.7.json",
        "nnew" => "nekobox_1.1.8.json",
        "sfia" => "sfi.json"
    );
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

    $templateBase['outbounds'] = array_merge($outboundManual, $outboundUrltest, $outbound,  $templateBase['outbounds']);
    return json_encode($templateBase, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}

function beginConvertSubLink($subLink) {
    $subData = file_get_contents($subLink);
    if (is_base64_encoded($subData) === "true"){
        $subDataFinal = base64_decode($subData);
    } else {
        $subDataFinal = $subData;
    }

    $convertedData = GenerateConfigLite($subDataFinal, "sfia");
    
    return $convertedData;
}

function beginConvertConfigs($configs) {
    $configData = base64_decode($configs);
    $convertedData = GenerateConfigLite($configData, "sfia");

    return $convertedData;
}

  $url = filter_input(INPUT_GET, "url", FILTER_VALIDATE_URL);
  $config = filter_input(INPUT_GET, "config", FILTER_SANITIZE_STRING);
  
try {
    if (!$url &&!$config) {
        throw new Exception("url or config parameter is missing or invalid");
    }
  
    if ($url) {
        echo beginConvertSubLink($url);
    } elseif ($config) {
        echo beginConvertConfigs($config);
    }
  
}catch (Exception $e) {
    $output = array(
        "ok" => false,
        "result" => $e->getMessage(),
    );
    echo json_encode($output, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}

