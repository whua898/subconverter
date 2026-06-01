#include <string>
#include <map>

#include "utils/base64/base64.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/network.h"
#include "utils/rapidjson_extra.h"
#include "utils/regexp.h"
#include "utils/string.h"
#include "utils/string_hash.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "config/proxy.h"
#include "subparser.h"
#include "utils/logger.h"

using namespace rapidjson;
using namespace rapidjson_ext;
using namespace YAML;

string_array ss_ciphers = {
    "rc4-md5", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb",
    "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "camellia-128-cfb",
    "camellia-192-cfb", "camellia-256-cfb", "bf-cfb", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "salsa20", "chacha20", "chacha20-ietf", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "2022-blake3-chacha12-poly1305",
    "2022-blake3-chacha8-poly1305"
};
string_array ssr_ciphers = {
    "none", "table", "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "bf-cfb", "camellia-128-cfb",
    "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb",
    "seed-cfb", "salsa20", "chacha20", "chacha20-ietf"
};

std::map<std::string, std::string> parsedMD5;
std::string modSSMD5 = "f7653207090ce3389115e9c88541afe0";

//remake from speedtestutil
std::string removeBrackets(const std::string& input) {
    std::string result = input;
    size_t left = result.find('[');
    size_t right = result.find(']');

    if (left != std::string::npos && right != std::string::npos && right > left) {
        result.erase(right, 1); // 删除 ']'
        result.erase(left, 1);  // 删除 '['
    }

    return result;
}
void commonConstruct(Proxy &node, ProxyType type, const std::string &group, const std::string &remarks,
                     const std::string &server, const std::string &port, const tribool &udp, const tribool &tfo,
                     const tribool &scv, const tribool &tls13, const std::string &underlying_proxy) {
    node.Type = type;
    node.Group = group;
    node.Remark = remarks;
    node.Hostname = removeBrackets(server);
    node.Port = to_int(port);
    node.UDP = udp;
    node.TCPFastOpen = tfo;
    node.AllowInsecure = scv;
    node.TLS13 = tls13;
    node.UnderlyingProxy = underlying_proxy;
}

void vmessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                    const std::string &port, const std::string &type, const std::string &id, const std::string &aid,
                    const std::string &net, const std::string &cipher, const std::string &path, const std::string &host,
                    const std::string &edge, const std::string &tls, const std::string &sni,
                    const std::vector<std::string> &alpnList, tribool udp, tribool tfo,
                    tribool scv, tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::VMess, group, remarks, add, port, udp, tfo, scv, tls13, underlying_proxy);
    node.UserId = id.empty() ? "00000000-0000-0000-0000-000000000000" : id;
    node.AlterId = to_int(aid);
    node.EncryptMethod = cipher;
    node.TransferProtocol = net.empty() ? "tcp" : net;
    node.Edge = edge;
    node.ServerName = sni;

    if (net == "quic") {
        node.QUICSecure = host;
        node.QUICSecret = path;
    } else {
        node.Host = (host.empty() && !isIPv4(add) && !isIPv6(add)) ? add.data() : trim(host);
        node.Path = path.empty() ? "/" : trim(path);
    }
    node.FakeType = type;
    node.TLSSecure = tls == "tls";
}

void ssrConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                  const std::string &port, const std::string &protocol, const std::string &method,
                  const std::string &obfs, const std::string &password, const std::string &obfsparam,
                  const std::string &protoparam, tribool udp, tribool tfo, tribool scv,
                  const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::ShadowsocksR, group, remarks, server, port, udp, tfo, scv, tribool(),
                    underlying_proxy);
    node.Password = password;
    node.EncryptMethod = method;
    node.Protocol = protocol;
    node.ProtocolParam = protoparam;
    node.OBFS = obfs;
    node.OBFSParam = obfsparam;
}

void ssConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                 const std::string &port, const std::string &password, const std::string &method,
                 const std::string &plugin, const std::string &pluginopts, tribool udp, tribool tfo, tribool scv,
                 tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Shadowsocks, group, remarks, server, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Password = password;
    node.EncryptMethod = method;
    node.Plugin = plugin;
    node.PluginOption = pluginopts;
}

void socksConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                    const std::string &port, const std::string &username, const std::string &password, tribool udp,
                    tribool tfo, tribool scv, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::SOCKS5, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Username = username;
    node.Password = password;
}

void httpConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                   const std::string &port, const std::string &username, const std::string &password, bool tls,
                   tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, tls ? ProxyType::HTTPS : ProxyType::HTTP, group, remarks, server, port, tribool(), tfo, scv,
                    tls13, underlying_proxy);
    node.Username = username;
    node.Password = password;
    node.TLSSecure = tls;
}

void trojanConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                     const std::string &port, const std::string &password, const std::string &network,
                     const std::string &host, const std::string &path, const std::string &fp, const std::string &sni,
                     const std::vector<std::string> &alpnList,
                     bool tlssecure,
                     tribool udp, tribool tfo,
                     tribool scv, tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Trojan, group, remarks, server, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Password = password;
    node.Host = host;
    node.TLSSecure = tlssecure;
    node.TransferProtocol = network.empty() ? "tcp" : network;
    node.Path = path;
    node.Fingerprint = fp;
    node.ServerName = sni;
    node.AlpnList = alpnList;
}

void snellConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                    const std::string &port, const std::string &password, const std::string &obfs,
                    const std::string &host, uint16_t version, tribool udp, tribool tfo, tribool scv,
                    const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Snell, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.OBFS = obfs;
    node.Host = host;
    node.SnellVersion = version;
}

void wireguardConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                        const std::string &port, const std::string &selfIp, const std::string &selfIpv6,
                        const std::string &privKey, const std::string &pubKey, const std::string &psk,
                        const string_array &dns, const std::string &mtu, const std::string &keepalive,
                        const std::string &testUrl, const std::string &clientId, const tribool &udp,
                        const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::WireGuard, group, remarks, server, port, udp, tribool(), tribool(), tribool(),
                    underlying_proxy);
    node.SelfIP = selfIp;
    node.SelfIPv6 = selfIpv6;
    node.PrivateKey = privKey;
    node.PublicKey = pubKey;
    node.PreSharedKey = psk;
    node.DnsServers = dns;
    node.Mtu = to_int(mtu);
    node.KeepAlive = to_int(keepalive);
    node.TestUrl = testUrl;
    node.ClientId = clientId;
}

void hysteriaConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                       const std::string &port, const std::string &type, const std::string &auth,
                       const std::string &auth_str,
                       const std::string &host, const std::string &up, const std::string &down, const std::string &alpn,
                       const std::string &obfsParam, const std::string &insecure, const std::string &ports,
                       const std::string &sni, tribool udp,
                       tribool tfo, tribool scv,
                       tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Hysteria, group, remarks, add, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Auth = auth;
    node.Host = (host.empty() && !isIPv4(add) && !isIPv6(add)) ? add.data() : trim(host);
    node.UpMbps = up;
    node.DownMbps = down;
    node.Alpn = alpn;
    node.OBFSParam = obfsParam;
    node.Insecure = insecure;
    node.FakeType = type;
    node.AuthStr = auth_str;
    node.Ports = ports;
    node.ServerName = sni;
}

void anyTlSConstruct(Proxy &node, const std::string &group, const std::string &remarks,
                     const std::string &port, const std::string &password,
                     const std::string &host, const std::vector<String> &AlpnList,
                     const std::string &fingerprint,
                     const std::string &sni, tribool udp,
                     tribool tfo, tribool scv,
                     tribool tls13, const std::string &underlying_proxy, uint16_t idleSessionCheckInterval,
                     uint16_t idleSessionTimeout, uint16_t minIdleSession) {
    commonConstruct(node, ProxyType::AnyTLS, group, remarks, host, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Host = trim(host);
    node.Password = password;
    node.AlpnList = AlpnList;
    node.SNI = sni;
    node.Fingerprint = fingerprint;
    node.IdleSessionCheckInterval = idleSessionCheckInterval;
    node.IdleSessionTimeout = idleSessionTimeout;
    node.MinIdleSession = minIdleSession;
}

void mieruConstruct(Proxy &node, const std::string &group, const std::string &remarks,
                    const std::string &port, const std::string &password,
                    const std::string &host, const std::string &ports,
                    const std::string &username, const std::string &multiplexing,
                    const std::string &transfer_protocol, tribool udp,
                    tribool tfo, tribool scv,
                    tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Mieru, group, remarks, host, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Host = trim(host);
    node.Password = password;
    node.Ports = ports;
    node.TransferProtocol = transfer_protocol.empty() ? "TCP" : trim(transfer_protocol);
    node.Username = username;
    node.Multiplexing = multiplexing.empty() ? "MULTIPLEXING_LOW" : trim(multiplexing);
}

void vlessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                    const std::string &port, const std::string &type, const std::string &id, const std::string &aid,
                    const std::string &net, const std::string &cipher, const std::string &flow, const std::string &mode,
                    const std::string &path, const std::string &host, const std::string &edge, const std::string &tls,
                    const std::string &pbk, const std::string &sid, const std::string &fp, const std::string &sni,
                    const std::vector<std::string> &alpnList, const std::string &packet_encoding, const std::string &encryption,
                    tribool udp, tribool tfo,
                    tribool scv, tribool tls13, const std::string &underlying_proxy, tribool v2ray_http_upgrade) {
    commonConstruct(node, ProxyType::VLESS, group, remarks, add, port, udp, tfo, scv, tls13, underlying_proxy);
    node.UserId = id.empty() ? "00000000-0000-0000-0000-000000000000" : id;
    node.AlterId = to_int(aid);
    node.EncryptMethod = cipher;
    node.TransferProtocol = net.empty() ? "tcp" : type == "http" ? "http" : net;
    node.Edge = edge;
    node.Flow = flow;
    node.Encryption = encryption;
    node.FakeType = type;
    node.TLSSecure = tls == "tls" || tls == "xtls" || tls == "reality";
    node.PublicKey = pbk;
    node.ShortId = sid;
    node.Fingerprint = fp;
    node.ServerName = sni;
    node.AlpnList = alpnList;
    node.PacketEncoding = packet_encoding;
    node.TLSStr = tls;
    switch (hash_(net)) {
        case "grpc"_hash:
            node.Host = host;
            node.GRPCMode = mode.empty() ? "gun" : mode;
            node.GRPCServiceName = path.empty() ? "/" : urlEncode(urlDecode(trim(path)));
            break;
        case "quic"_hash:
            node.Host = host;
            node.QUICSecret = path.empty() ? "/" : trim(path);
            break;
        default:
            node.Host = (host.empty() && !isIPv4(add) && !isIPv6(add)) ? add.data() : trim(host);
            node.Path = path.empty() ? "/" : urlDecode(trim(path));
            node.V2rayHttpUpgrade = v2ray_http_upgrade;
            break;
    }
}


void hysteria2Construct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                        const std::string &port, const std::string &password, const std::string &host,
                        const std::string &up, const std::string &down, const std::string &alpn,
                        const std::string &obfsParam, const std::string &obfsPassword, const std::string &sni,
                        const std::string &publicKey, const std::string &ports,
                        tribool udp, tribool tfo,
                        tribool scv, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Hysteria2, group, remarks, add, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.Host = (host.empty() && !isIPv4(add) && !isIPv6(add)) ? add.data() : trim(host);
    node.UpMbps = up;
    node.DownMbps = down;
    node.Alpn = alpn;
    node.OBFSParam = obfsParam;
    node.OBFSPassword = obfsPassword;
    node.ServerName = sni;
    node.PublicKey = publicKey;
    node.Ports = ports;
}

void tuicConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                   const std::string &port, const std::string &password, const std::string &congestion_control,
                   const std::string &alpn,
                   const std::string &sni, const std::string &uuid, const std::string &udpRelayMode,
                   const std::string &token,
                   tribool udp, tribool tfo,
                   tribool scv, tribool reduceRtt, tribool disableSni, uint16_t request_timeout,
                   const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::TUIC, group, remarks, add, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.Alpn = alpn;
    node.ServerName = sni;
    node.CongestionControl = congestion_control;
    node.ReduceRtt = reduceRtt;
    node.DisableSni = disableSni;
    node.UserId = uuid;
    node.UdpRelayMode = udpRelayMode;
    node.token = token;
    node.RequestTimeout = request_timeout;
}


void explodeVmess(std::string vmess, Proxy &node) {
    std::string version, ps, add, port, type, id, aid, net, path, host, tls, sni;
    Document jsondata;
    std::vector<std::string> vArray;

    if (regMatch(vmess, "vmess://([A-Za-z0-9-_]+)\\?(.*)")) //shadowrocket style link
    {
        explodeShadowrocket(vmess, node);
        return;
    } else if (regMatch(vmess, "vmess://(.*?)@(.*)")) {
        explodeStdVMess(vmess, node);
        return;
    } else if (regMatch(vmess, "vmess1://(.*?)\\?(.*)")) //kitsunebi style link
    {
        explodeKitsunebi(vmess, node);
        return;
    }
    vmess = urlSafeBase64Decode(regReplace(vmess, "(vmess|vmess1)://", ""));
    if (regMatch(vmess, "(.*?) = (.*)")) {
        explodeQuan(vmess, node);
        return;
    }
    jsondata.Parse(vmess.data());
    if (jsondata.HasParseError() || !jsondata.IsObject())
        return;

    version = "1"; //link without version will treat as version 1
    GetMember(jsondata, "v", version); //try to get version

    GetMember(jsondata, "ps", ps);
    GetMember(jsondata, "add", add);
    port = GetMember(jsondata, "port");
    if (port == "0")
        return;
    GetMember(jsondata, "type", type);
    GetMember(jsondata, "id", id);
    GetMember(jsondata, "aid", aid);
    GetMember(jsondata, "net", net);
    GetMember(jsondata, "tls", tls);

    GetMember(jsondata, "host", host);
    GetMember(jsondata, "sni", sni);
    switch (to_int(version)) {
        case 1:
            if (!host.empty()) {
                vArray = split(host, ";");
                if (vArray.size() == 2) {
                    host = vArray[0];
                    path = vArray[1];
                }
            }
            break;
        case 2:
            path = GetMember(jsondata, "path");
            break;
    }

    add = trim(add);

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, type, id, aid, net, "auto", path, host, "", tls, sni,
                   std::vector<std::string>{});
}

void explodeVmessConf(std::string content, std::vector<Proxy> &nodes) {
    Document json;
    rapidjson::Value nodejson, settings;
    std::string group, ps, add, port, type, id, aid, net, path, host, edge, tls, cipher, subid, sni;
    tribool udp, tfo, scv;
    int configType;
    uint32_t index = nodes.size();
    std::map<std::string, std::string> subdata;
    std::map<std::string, std::string>::iterator iter;
    std::string streamset = "streamSettings", tcpset = "tcpSettings", wsset = "wsSettings";
    regGetMatch(content, "((?i)streamsettings)", 2, 0, &streamset);
    regGetMatch(content, "((?i)tcpsettings)", 2, 0, &tcpset);
    regGetMatch(content, "((?i)wssettings)", 2, 0, &wsset);

    json.Parse(content.data());
    if (json.HasParseError() || !json.IsObject())
        return;
    try {
        if (json.HasMember("outbounds")) //single config
        {
            if (json["outbounds"].Size() > 0 && json["outbounds"][0].HasMember("settings") &&
                json["outbounds"][0]["settings"].HasMember("vnext") &&
                json["outbounds"][0]["settings"]["vnext"].Size() > 0) {
                Proxy node;
                nodejson = json["outbounds"][0];
                add = GetMember(nodejson["settings"]["vnext"][0], "address");
                port = GetMember(nodejson["settings"]["vnext"][0], "port");
                if (port == "0")
                    return;
                if (nodejson["settings"]["vnext"][0]["users"].Size()) {
                    id = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "id");
                    aid = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "alterId");
                    cipher = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "security");
                }
                if (nodejson.HasMember(streamset.data())) {
                    net = GetMember(nodejson[streamset.data()], "network");
                    tls = GetMember(nodejson[streamset.data()], "security");
                    if (net == "ws") {
                        if (nodejson[streamset.data()].HasMember(wsset.data()))
                            settings = nodejson[streamset.data()][wsset.data()];
                        else
                            settings.RemoveAllMembers();
                        path = GetMember(settings, "path");
                        if (settings.HasMember("headers")) {
                            host = GetMember(settings["headers"], "Host");
                            edge = GetMember(settings["headers"], "Edge");
                        }
                    }
                    if (nodejson[streamset.data()].HasMember(tcpset.data()))
                        settings = nodejson[streamset.data()][tcpset.data()];
                    else
                        settings.RemoveAllMembers();
                    if (settings.IsObject() && settings.HasMember("header")) {
                        type = GetMember(settings["header"], "type");
                        if (type == "http") {
                            if (settings["header"].HasMember("request")) {
                                if (settings["header"]["request"].HasMember("path") &&
                                    settings["header"]["request"]["path"].Size())
                                    settings["header"]["request"]["path"][0] >> path;
                                if (settings["header"]["request"].HasMember("headers")) {
                                    host = GetMember(settings["header"]["request"]["headers"], "Host");
                                    edge = GetMember(settings["header"]["request"]["headers"], "Edge");
                                }
                            }
                        }
                    }
                }
                vmessConstruct(node, V2RAY_DEFAULT_GROUP, add + ":" + port, add, port, type, id, aid, net, cipher, path,
                               host, edge, tls, "", std::vector<std::string>{}, udp, tfo, scv);
                nodes.emplace_back(std::move(node));
            }
            return;
        }
    } catch (std::exception &e) {
        //writeLog(0, "VMessConf parser throws an error. Leaving...", LOG_LEVEL_WARNING);
        //return;
        //ignore
        throw;
    }
    //read all subscribe remark as group name
    for (uint32_t i = 0; i < json["subItem"].Size(); i++)
        subdata.insert(std::pair<std::string, std::string>(json["subItem"][i]["id"].GetString(),
                                                           json["subItem"][i]["remarks"].GetString()));

    for (uint32_t i = 0; i < json["vmess"].Size(); i++) {
        Proxy node;
        if (json["vmess"][i]["address"].IsNull() || json["vmess"][i]["port"].IsNull() ||
            json["vmess"][i]["id"].IsNull())
            continue;

        //common info
        json["vmess"][i]["remarks"] >> ps;
        json["vmess"][i]["address"] >> add;
        port = GetMember(json["vmess"][i], "port");
        if (port == "0")
            continue;
        json["vmess"][i]["subid"] >> subid;

        if (!subid.empty()) {
            iter = subdata.find(subid);
            if (iter != subdata.end())
                group = iter->second;
        }
        if (ps.empty())
            ps = add + ":" + port;

        scv = GetMember(json["vmess"][i], "allowInsecure");
        json["vmess"][i]["configType"] >> configType;
        switch (configType) {
            case 1: //vmess config
                json["vmess"][i]["headerType"] >> type;
                json["vmess"][i]["id"] >> id;
                json["vmess"][i]["alterId"] >> aid;
                json["vmess"][i]["network"] >> net;
                json["vmess"][i]["path"] >> path;
                json["vmess"][i]["requestHost"] >> host;
                json["vmess"][i]["streamSecurity"] >> tls;
                json["vmess"][i]["security"] >> cipher;
                json["vmess"][i]["sni"] >> sni;
                vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, type, id, aid, net, cipher, path, host, "",
                               tls, sni, std::vector<std::string>{}, udp, tfo, scv);
                break;
            case 3: //ss config
                json["vmess"][i]["id"] >> id;
                json["vmess"][i]["security"] >> cipher;
                ssConstruct(node, SS_DEFAULT_GROUP, ps, add, port, id, cipher, "", "", udp, tfo, scv);
                break;
            case 4: //socks config
                socksConstruct(node, SOCKS_DEFAULT_GROUP, ps, add, port, "", "", udp, tfo, scv);
                break;
            default:
                continue;
        }
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSS(std::string ss, Proxy &node) {
    std::string ps, password, method, server, port, plugins, plugin, pluginopts, addition, group = SS_DEFAULT_GROUP,
            secret;
    //std::vector<std::string> args, secret;
    ss = replaceAllDistinct(ss.substr(5), "/?", "?");
    if (strFind(ss, "#")) {
        auto sspos = ss.find('#');
        ps = urlDecode(ss.substr(sspos + 1));
        ss.erase(sspos);
    }

    if (strFind(ss, "?")) {
        addition = ss.substr(ss.find('?') + 1);
        plugins = urlDecode(getUrlArg(addition, "plugin"));
        auto pluginpos = plugins.find(';');
        plugin = plugins.substr(0, pluginpos);
        pluginopts = plugins.substr(pluginpos + 1);
        group = getUrlArg(addition, "group");
        if (!group.empty())
            group = urlSafeBase64Decode(group);
        ss.erase(ss.find('?'));
    }
    if (strFind(ss, "@")) {
        if (regGetMatch(ss, "(\\S+?)@(\\S+):(\\d+)", 4, 0, &secret, &server, &port))
            return;
        if (regGetMatch(urlSafeBase64Decode(secret), "(\\S+?):(\\S+)", 3, 0, &method, &password))
            return;
    } else {
        if (regGetMatch(urlSafeBase64Decode(ss), "(\\S+?):(\\S+)@(\\S+):(\\d+)", 5, 0, &method, &password, &server,
                        &port))
            return;
    }
    if (port == "0")
        return;
    if (ps.empty())
        ps = server + ":" + port;

    ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
}

void explodeSSD(std::string link, std::vector<Proxy> &nodes) {
    Document jsondata;
    uint32_t index = nodes.size(), listType = 0, listCount = 0;
    std::string group, port, method, password, server, remarks;
    std::string plugin, pluginopts;
    std::map<uint32_t, std::string> node_map;

    link = urlSafeBase64Decode(link.substr(6));
    jsondata.Parse(link.c_str());
    if (jsondata.HasParseError() || !jsondata.IsObject())
        return;
    if (!jsondata.HasMember("servers"))
        return;
    GetMember(jsondata, "airport", group);

    if (jsondata["servers"].IsArray()) {
        listType = 0;
        listCount = jsondata["servers"].Size();
    } else if (jsondata["servers"].IsObject()) {
        listType = 1;
        listCount = jsondata["servers"].MemberCount();
        uint32_t node_index = 0;
        for (rapidjson::Value::MemberIterator iter = jsondata["servers"].MemberBegin();
             iter != jsondata["servers"].MemberEnd(); iter++) {
            node_map.emplace(node_index, iter->name.GetString());
            node_index++;
        }
    } else
        return;

    rapidjson::Value singlenode;
    for (uint32_t i = 0; i < listCount; i++) {
        //get default info
        port = GetMember(jsondata, "port");
        method = GetMember(jsondata, "encryption");
        password = GetMember(jsondata, "password");
        plugin = GetMember(jsondata, "plugin");
        pluginopts = GetMember(jsondata, "plugin_options");

        //get server-specific info
        switch (listType) {
            case 0:
                singlenode = jsondata["servers"][i];
                break;
            case 1:
                singlenode = jsondata["servers"].FindMember(node_map[i].data())->value;
                break;
            default:
                continue;
        }
        singlenode["server"] >> server;
        GetMember(singlenode, "remarks", remarks);
        GetMember(singlenode, "port", port);
        GetMember(singlenode, "encryption", method);
        GetMember(singlenode, "password", password);
        GetMember(singlenode, "plugin", plugin);
        GetMember(singlenode, "plugin_options", pluginopts);

        if (port == "0")
            continue;

        Proxy node;
        ssConstruct(node, group, remarks, server, port, password, method, plugin, pluginopts);
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSAndroid(std::string ss, std::vector<Proxy> &nodes) {
    std::string ps, password, method, server, port, group = SS_DEFAULT_GROUP;
    std::string plugin, pluginopts;

    Document json;
    auto index = nodes.size();
    //first add some extra data before parsing
    ss = "{\"nodes\":" + ss + "}";
    json.Parse(ss.data());
    if (json.HasParseError() || !json.IsObject())
        return;

    for (uint32_t i = 0; i < json["nodes"].Size(); i++) {
        Proxy node;
        server = GetMember(json["nodes"][i], "server");
        if (server.empty())
            continue;
        ps = GetMember(json["nodes"][i], "remarks");
        port = GetMember(json["nodes"][i], "server_port");
        if (port == "0")
            continue;
        if (ps.empty())
            ps = server + ":" + port;
        password = GetMember(json["nodes"][i], "password");
        method = GetMember(json["nodes"][i], "method");
        plugin = GetMember(json["nodes"][i], "plugin");
        pluginopts = GetMember(json["nodes"][i], "plugin_opts");

        ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSConf(std::string content, std::vector<Proxy> &nodes) {
    Document json;
    std::string ps, password, method, server, port, plugin, pluginopts, group = SS_DEFAULT_GROUP;
    auto index = nodes.size();

    json.Parse(content.data());
    if (json.HasParseError() || !json.IsObject())
        return;
    const char *section = json.HasMember("version") && json.HasMember("servers") ? "servers" : "configs";
    if (!json.HasMember(section))
        return;
    GetMember(json, "remarks", group);

    for (uint32_t i = 0; i < json[section].Size(); i++) {
        Proxy node;
        ps = GetMember(json[section][i], "remarks");
        port = GetMember(json[section][i], "server_port");
        if (port == "0")
            continue;
        if (ps.empty())
            ps = server + ":" + port;

        password = GetMember(json[section][i], "password");
        method = GetMember(json[section][i], "method");
        server = GetMember(json[section][i], "server");
        plugin = GetMember(json[section][i], "plugin");
        pluginopts = GetMember(json[section][i], "plugin_opts");

        node.Id = index;
        ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSR(std::string ssr, Proxy &node) {
    std::string strobfs;
    std::string remarks, group, server, port, method, password, protocol, protoparam, obfs, obfsparam;
    ssr = replaceAllDistinct(ssr.substr(6), "\r", "");
    ssr = urlSafeBase64Decode(ssr);
    if (strFind(ssr, "/?")) {
        strobfs = ssr.substr(ssr.find("/?") + 2);
        ssr = ssr.substr(0, ssr.find("/?"));
        group = urlSafeBase64Decode(getUrlArg(strobfs, "group"));
        remarks = urlSafeBase64Decode(getUrlArg(strobfs, "remarks"));
        obfsparam = regReplace(urlSafeBase64Decode(getUrlArg(strobfs, "obfsparam")), "\\s", "");
        protoparam = regReplace(urlSafeBase64Decode(getUrlArg(strobfs, "protoparam")), "\\s", "");
    }

    if (regGetMatch(ssr, "(\\S+):(\\d+?):(\\S+?):(\\S+?):(\\S+?):(\\S+)", 7, 0, &server, &port, &protocol, &method,
                    &obfs, &password))
        return;
    password = urlSafeBase64Decode(password);
    if (port == "0")
        return;

    if (group.empty())
        group = SSR_DEFAULT_GROUP;
    if (remarks.empty())
        remarks = server + ":" + port;

    if (find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() && (obfs.empty() || obfs == "plain") &&
        (protocol.empty() || protocol == "origin")) {
        ssConstruct(node, group, remarks, server, port, password, method, "", "");
    } else {
        ssrConstruct(node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
    }
}

void explodeSSRConf(std::string content, std::vector<Proxy> &nodes) {
    Document json;
    std::string remarks, group, server, port, method, password, protocol, protoparam, obfs, obfsparam, plugin,
            pluginopts;
    auto index = nodes.size();

    json.Parse(content.data());
    if (json.HasParseError() || !json.IsObject())
        return;

    if (json.HasMember("local_port") && json.HasMember("local_address")) //single libev config
    {
        Proxy node;
        server = GetMember(json, "server");
        port = GetMember(json, "server_port");
        remarks = server + ":" + port;
        method = GetMember(json, "method");
        obfs = GetMember(json, "obfs");
        protocol = GetMember(json, "protocol");
        if (find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() &&
            (obfs.empty() || obfs == "plain") && (protocol.empty() || protocol == "origin")) {
            plugin = GetMember(json, "plugin");
            pluginopts = GetMember(json, "plugin_opts");
            ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts);
        } else {
            protoparam = GetMember(json, "protocol_param");
            obfsparam = GetMember(json, "obfs_param");
            ssrConstruct(node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method, obfs, password, obfsparam,
                         protoparam);
        }
        nodes.emplace_back(std::move(node));
        return;
    }

    for (uint32_t i = 0; i < json["configs"].Size(); i++) {
        Proxy node;
        group = GetMember(json["configs"][i], "group");
        if (group.empty())
            group = SSR_DEFAULT_GROUP;
        remarks = GetMember(json["configs"][i], "remarks");
        server = GetMember(json["configs"][i], "server");
        port = GetMember(json["configs"][i], "server_port");
        if (port == "0")
            continue;
        if (remarks.empty())
            remarks = server + ":" + port;

        password = GetMember(json["configs"][i], "password");
        method = GetMember(json["configs"][i], "method");

        protocol = GetMember(json["configs"][i], "protocol");
        protoparam = GetMember(json["configs"][i], "protocolparam");
        obfs = GetMember(json["configs"][i], "obfs");
        obfsparam = GetMember(json["configs"][i], "obfsparam");

        ssrConstruct(node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSocks(std::string link, Proxy &node) {
    std::string group, remarks, server, port, username, password;
    if (strFind(link, "socks://")) //v2rayn socks link
    {
        if (strFind(link, "#")) {
            auto pos = link.find('#');
            remarks = urlDecode(link.substr(pos + 1));
            link.erase(pos);
        }
        link = urlSafeBase64Decode(link.substr(8));
        if (strFind(link, "@")) {
            auto userinfo = split(link, '@');
            if (userinfo.size() < 2)
                return;
            link = userinfo[1];
            userinfo = split(userinfo[0], ':');
            if (userinfo.size() < 2)
                return;
            username = userinfo[0];
            password = userinfo[1];
        }
        auto arguments = split(link, ':');
        if (arguments.size() < 2)
            return;
        server = arguments[0];
        port = arguments[1];
    } else if (strFind(link, "https://t.me/socks") || strFind(link, "tg://socks")) //telegram style socks link
    {
        server = getUrlArg(link, "server");
        port = getUrlArg(link, "port");
        username = urlDecode(getUrlArg(link, "user"));
        password = urlDecode(getUrlArg(link, "pass"));
        remarks = urlDecode(getUrlArg(link, "remarks"));
        group = urlDecode(getUrlArg(link, "group"));
    }
    if (group.empty())
        group = SOCKS_DEFAULT_GROUP;
    if (remarks.empty())
        remarks = server + ":" + port;
    if (port == "0")
        return;

    socksConstruct(node, group, remarks, server, port, username, password);
}

void explodeHTTP(const std::string &link, Proxy &node) {
    std::string group, remarks, server, port, username, password;
    server = getUrlArg(link, "server");
    port = getUrlArg(link, "port");
    username = urlDecode(getUrlArg(link, "user"));
    password = urlDecode(getUrlArg(link, "pass"));
    remarks = urlDecode(getUrlArg(link, "remarks"));
    group = urlDecode(getUrlArg(link, "group"));

    if (group.empty())
        group = HTTP_DEFAULT_GROUP;
    if (remarks.empty())
        remarks = server + ":" + port;
    if (port == "0")
        return;

    httpConstruct(node, group, remarks, server, port, username, password, strFind(link, "/https"));
}

void explodeHTTPSub(std::string link, Proxy &node) {
    std::string group, remarks, server, port, username, password;
    std::string addition;
    bool tls = strFind(link, "https://");
    auto pos = link.find('?');
    if (pos != std::string::npos) {
        addition = link.substr(pos + 1);
        link.erase(pos);
        remarks = urlDecode(getUrlArg(addition, "remarks"));
        group = urlDecode(getUrlArg(addition, "group"));
    }
    link.erase(0, link.find("://") + 3);
    link = urlSafeBase64Decode(link);
    if (strFind(link, "@")) {
        if (regGetMatch(link, "(.*?):(.*?)@(.*):(.*)", 5, 0, &username, &password, &server, &port))
            return;
    } else {
        if (regGetMatch(link, "(.*):(.*)", 3, 0, &server, &port))
            return;
    }

    if (group.empty())
        group = HTTP_DEFAULT_GROUP;
    if (remarks.empty())
        remarks = server + ":" + port;
    if (port == "0")
        return;

    httpConstruct(node, group, remarks, server, port, username, password, tls);
}

void explodeTrojan(std::string trojan, Proxy &node) {
    std::string server, port, psk, addition, group, remark, host, path, network, fp, sni;
    tribool tfo, scv;
    if (startsWith(trojan, "trojan://")) {
        trojan.erase(0, 9);
    }
    if (startsWith(trojan, "trojan-go://")) {
        trojan.erase(0, 12);
    }
    string_size pos = trojan.rfind('#');
    if (pos != std::string::npos) {
        remark = urlDecode(trojan.substr(pos + 1));
        trojan.erase(pos);
    }
    pos = trojan.find('?');
    if (pos != std::string::npos) {
        addition = trojan.substr(pos + 1);
        trojan.erase(pos);
    }

    if (regGetMatch(trojan, "(.*?)@(.*):(.*)", 4, 0, &psk, &server, &port))
        return;
    if (port == "0")
        return;

    host = getUrlArg(addition, "sni");
    sni = getUrlArg(addition, "sni");
    host = getUrlArg(addition, "host");
    if (host.empty())
        host = sni;
    if (host.empty())
        host = getUrlArg(addition, "peer");
    tfo = getUrlArg(addition, "tfo");
    fp = getUrlArg(addition, "fp");
    scv = getUrlArg(addition, "allowInsecure");
    group = urlDecode(getUrlArg(addition, "group"));

    if (getUrlArg(addition, "ws") == "1") {
        path = getUrlArg(addition, "wspath");
        network = "ws";
    }
    // support the trojan link format used by v2ryaN and X-ui.
    // format: trojan://{password}@{server}:{port}?type=ws&security=tls&path={path (urlencoded)}&sni={host}#{name}
    else if (getUrlArg(addition, "type") == "ws") {
        path = getUrlArg(addition, "path");
        if (path.substr(0, 3) == "%2F")
            path = urlDecode(path);
        network = "ws";
    }

    else if (getUrlArg(addition, "type") == "grpc") {  
        path = getUrlArg(addition, "serviceName");  
        network = "grpc";  
    }
    
    if (remark.empty())
        remark = server + ":" + port;
    if (group.empty())
        group = TROJAN_DEFAULT_GROUP;
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if (!alpn.empty()) {
        alpnList.push_back(alpn);
    }
    trojanConstruct(node, group, remark, server, port, psk, network, host, path, fp, sni, alpnList, true, tribool(),
                    tfo, scv);
}

void explodeVless(std::string vless, Proxy &node) {
    if (regMatch(vless, "vless://(.*?)@(.*)")) {
        explodeStdVless(vless, node);
        return;
    }
}

void explodeMierus(std::string mierus, Proxy &node) {
    if (strFind(mierus, "mierus://")) {
        if (regMatch(mierus, "mierus://(.*?)@(.*)")) {
            explodeStdMieru(mierus.substr(9), node);
        } else {
            mierus = urlSafeBase64Decode(mierus.substr(9));
            explodeStdMieru("mierus://" + mierus, node);
        }
    } else if (strFind(mierus, "mieru://")) {
        if (regMatch(mierus, "mierus://(.*?)@(.*)")) {
            explodeStdMieru(mierus.substr(8), node);
        } else {
            mierus = urlSafeBase64Decode(mierus.substr(8));
            explodeStdMieru("mierus://" + mierus, node);
        }
    }
}

void explodeHysteria(std::string hysteria, Proxy &node) {
    printf("explodeHysteria\n");
    hysteria = regReplace(hysteria, "(hysteria|hy)://", "hysteria://");
    if (regMatch(hysteria, "hysteria://(.*?)[:](.*)")) {
        explodeStdHysteria(hysteria, node);
        return;
    }
}

void explodeHysteria2(std::string hysteria2, Proxy &node) {
    hysteria2 = regReplace(hysteria2, "(hysteria2|hy2)://", "hysteria2://");

    // replace /? with ?
    hysteria2 = regReplace(hysteria2, "/\\?", "?", true, false);
    if (regMatch(hysteria2, "hysteria2://(.*?)[:](.*)")) {
        explodeStdHysteria2(hysteria2, node);
        return;
    }
}

void explodeQuan(const std::string &quan, Proxy &node) {
    std::string strTemp, itemName, itemVal;
    std::string group = V2RAY_DEFAULT_GROUP, ps, add, port, cipher, type = "none", id, aid = "0", net = "tcp", path,
            host, edge, tls;
    string_array configs, vArray, headers;
    strTemp = regReplace(quan, "(.*?) = (.*)", "$1,$2");
    configs = split(strTemp, ",");

    if (configs[1] == "vmess") {
        if (configs.size() < 6)
            return;
        ps = trim(configs[0]);
        add = trim(configs[2]);
        port = trim(configs[3]);
        if (port == "0")
            return;
        cipher = trim(configs[4]);
        id = trim(replaceAllDistinct(configs[5], "\"", ""));

        //read link
        for (uint32_t i = 6; i < configs.size(); i++) {
            vArray = split(configs[i], "=");
            if (vArray.size() < 2)
                continue;
            itemName = trim(vArray[0]);
            itemVal = trim(vArray[1]);
            switch (hash_(itemName)) {
                case "group"_hash:
                    group = itemVal;
                    break;
                case "over-tls"_hash:
                    tls = itemVal == "true" ? "tls" : "";
                    break;
                case "tls-host"_hash:
                    host = itemVal;
                    break;
                case "obfs-path"_hash:
                    path = replaceAllDistinct(itemVal, "\"", "");
                    break;
                case "obfs-header"_hash:
                    headers = split(replaceAllDistinct(replaceAllDistinct(itemVal, "\"", ""), "[Rr][Nn]", "|"), "|");
                    for (std::string &x: headers) {
                        if (regFind(x, "(?i)Host: "))
                            host = x.substr(6);
                        else if (regFind(x, "(?i)Edge: "))
                            edge = x.substr(6);
                    }
                    break;
                case "obfs"_hash:
                    if (itemVal == "ws")
                        net = "ws";
                    break;
                default:
                    continue;
            }
        }
        if (path.empty())
            path = "/";

        vmessConstruct(node, group, ps, add, port, type, id, aid, net, cipher, path, host, edge, tls, "",
                       std::vector<std::string>{});
    }
}

void explodeNetch(std::string netch, Proxy &node) {
    Document json;
    std::string type, group, remark, address, port, username, password, method, plugin, pluginopts;
    std::string protocol, protoparam, obfs, obfsparam, id, aid, transprot, faketype, host, edge, path, tls, sni, fp;
    tribool udp, tfo, scv;
    netch = urlSafeBase64Decode(netch.substr(8));

    json.Parse(netch.data());
    if (json.HasParseError() || !json.IsObject())
        return;
    type = GetMember(json, "Type");
    group = GetMember(json, "Group");
    remark = GetMember(json, "Remark");
    address = GetMember(json, "Hostname");
    udp = GetMember(json, "EnableUDP");
    tfo = GetMember(json, "EnableTFO");
    scv = GetMember(json, "AllowInsecure");
    port = GetMember(json, "Port");
    fp = GetMember(json, "FingerPrint");
    if (port == "0")
        return;
    method = GetMember(json, "EncryptMethod");
    password = GetMember(json, "Password");
    if (remark.empty())
        remark = address + ":" + port;
    switch (hash_(type)) {
        case "SS"_hash:
            plugin = GetMember(json, "Plugin");
            pluginopts = GetMember(json, "PluginOption");
            if (group.empty())
                group = SS_DEFAULT_GROUP;
            ssConstruct(node, group, remark, address, port, password, method, plugin, pluginopts, udp, tfo, scv);
            break;
        case "SSR"_hash:
            protocol = GetMember(json, "Protocol");
            obfs = GetMember(json, "OBFS");
            if (find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() &&
                (obfs.empty() || obfs == "plain") && (protocol.empty() || protocol == "origin")) {
                plugin = GetMember(json, "Plugin");
                pluginopts = GetMember(json, "PluginOption");
                if (group.empty())
                    group = SS_DEFAULT_GROUP;
                ssConstruct(node, group, remark, address, port, password, method, plugin, pluginopts, udp, tfo, scv);
            } else {
                protoparam = GetMember(json, "ProtocolParam");
                obfsparam = GetMember(json, "OBFSParam");
                if (group.empty())
                    group = SSR_DEFAULT_GROUP;
                ssrConstruct(node, group, remark, address, port, protocol, method, obfs, password, obfsparam,
                             protoparam, udp, tfo, scv);
            }
            break;
        case "VMess"_hash:
            id = GetMember(json, "UserID");
            aid = GetMember(json, "AlterID");
            transprot = GetMember(json, "TransferProtocol");
            faketype = GetMember(json, "FakeType");
            host = GetMember(json, "Host");
            path = GetMember(json, "Path");
            edge = GetMember(json, "Edge");
            tls = GetMember(json, "TLSSecure");
            sni = GetMember(json, "ServerName");

            if (group.empty())
                group = V2RAY_DEFAULT_GROUP;
            vmessConstruct(node, group, remark, address, port, faketype, id, aid, transprot, method, path, host, edge,
                           tls, sni, std::vector<std::string>{}, udp, tfo, scv);
            break;
        case "Socks5"_hash:
            username = GetMember(json, "Username");
            if (group.empty())
                group = SOCKS_DEFAULT_GROUP;
            socksConstruct(node, group, remark, address, port, username, password, udp, tfo, scv);
            break;
        case "HTTP"_hash:
        case "HTTPS"_hash:
            if (group.empty())
                group = HTTP_DEFAULT_GROUP;
            httpConstruct(node, group, remark, address, port, username, password, type == "HTTPS", tfo, scv);
            break;
        case "Trojan"_hash:
            host = GetMember(json, "Host");
            path = GetMember(json, "Path");
            transprot = GetMember(json, "TransferProtocol");
            tls = GetMember(json, "TLSSecure");
            sni = host;
            if (group.empty())
                group = TROJAN_DEFAULT_GROUP;
            trojanConstruct(node, group, remark, address, port, password, transprot, host, path, fp, sni,
                            std::vector<std::string>{}, tls == "true",
                            udp,
                            tfo, scv);
            break;
        case "Snell"_hash:
            obfs = GetMember(json, "OBFS");
            host = GetMember(json, "Host");
            aid = GetMember(json, "SnellVersion");
            if (group.empty())
                group = SNELL_DEFAULT_GROUP;
            snellConstruct(node, group, remark, address, port, password, obfs, host, to_int(aid, 0), udp, tfo, scv);
            break;
        default:
            return;
    }
}

void explodeClash(Node yamlnode, std::vector<Proxy> &nodes) {
    Node singleproxy;
    uint32_t index = nodes.size();
    const std::string section = yamlnode["proxies"].IsDefined() ? "proxies" : "Proxy";
    for (uint32_t i = 0; i < yamlnode[section].size(); i++) {
        std::string proxytype, ps, server, port, cipher, group, password = "", ports, tempPassword; //common
        std::string type = "none", id, aid = "0", net = "tcp", path, host, edge, tls, sni; //vmess
        std::string fp = "chrome", pbk, sid, packet_encoding, encryption; //vless
        std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, pluginopts_mux; //ss
        std::string protocol, protoparam, obfs, obfsparam; //ssr
        std::string flow, mode; //trojan
        std::string user; //socks
        std::string ip, ipv6, private_key, public_key, mtu; //wireguard
        std::string auth, up, down, obfsParam, insecure, alpn; //hysteria
        std::string obfsPassword; //hysteria2
        std::string congestion_control, udp_relay_mode, token; // tuic
        std::string underlying_proxy;
        string_array dns_server;
        std::vector<String> alpns;
        String alpn2;
        std::string fingerprint, multiplexing, transfer_protocol, v2ray_http_upgrade;
        tribool udp, tfo, scv;
        bool reduceRtt, disableSni; //tuic
        std::vector<std::string> alpnList;
        Proxy node;
        singleproxy = yamlnode[section][i];
        singleproxy["type"] >>= proxytype;
        singleproxy["name"] >>= ps;
        singleproxy["server"] >>= server;
        singleproxy["port"] >>= port;
        singleproxy["port-range"] >>= ports;

        if (port.empty() || port == "0")
            if (ports.empty())
                continue;
        udp = safe_as<std::string>(singleproxy["udp"]);
        scv = safe_as<std::string>(singleproxy["skip-cert-verify"]);
        singleproxy["dialer-proxy"] >>= underlying_proxy;
        switch (hash_(proxytype)) {
            case "vmess"_hash:
                singleproxy["uuid"] >>= id;
                if (id.length() < 36) {
                    break;
                }
                group = V2RAY_DEFAULT_GROUP;
                singleproxy["alterId"] >>= aid;
                singleproxy["cipher"] >>= cipher;
                net = singleproxy["network"].IsDefined() ? safe_as<std::string>(singleproxy["network"]) : "tcp";
                singleproxy["servername"] >>= sni;
                switch (hash_(net)) {
                    case "http"_hash:
                        singleproxy["http-opts"]["path"][0] >>= path;
                        singleproxy["http-opts"]["headers"]["Host"][0] >>= host;
                        edge.clear();
                        break;
                    case "ws"_hash:
                        if (singleproxy["ws-opts"].IsDefined()) {
                            path = singleproxy["ws-opts"]["path"].IsDefined()
                                       ? safe_as<std::string>(
                                           singleproxy["ws-opts"]["path"])
                                       : "/";
                            singleproxy["ws-opts"]["headers"]["Host"] >>= host;
                            if (host.empty()) {
                                singleproxy["ws-opts"]["headers"]["host"] >>= host;
                            }
                            singleproxy["ws-opts"]["headers"]["Edge"] >>= edge;
                        } else {
                            path = singleproxy["ws-path"].IsDefined()
                                       ? safe_as<std::string>(singleproxy["ws-path"])
                                       : "/";
                            singleproxy["ws-headers"]["Host"] >>= host;
                            singleproxy["ws-headers"]["Edge"] >>= edge;
                        }
                        break;
                    case "h2"_hash:
                        singleproxy["h2-opts"]["path"] >>= path;
                        singleproxy["h2-opts"]["host"][0] >>= host;
                        edge.clear();
                        break;
                    case "grpc"_hash:
                        singleproxy["servername"] >>= host;
                        singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                        edge.clear();
                        break;
                }
                tls = safe_as<std::string>(singleproxy["tls"]) == "true" ? "tls" : "";
                singleproxy["alpn"] >>= alpnList;
                vmessConstruct(node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge, tls, sni,
                               alpnList, udp,
                               tfo, scv, tribool(), underlying_proxy);
                break;
            case "ss"_hash:
                group = SS_DEFAULT_GROUP;

                singleproxy["cipher"] >>= cipher;
                singleproxy["password"] >>= password;
                if (singleproxy["plugin"].IsDefined()) {
                    switch (hash_(safe_as<std::string>(singleproxy["plugin"]))) {
                        case "obfs"_hash:
                            plugin = "obfs-local";
                            if (singleproxy["plugin-opts"].IsDefined()) {
                                singleproxy["plugin-opts"]["mode"] >>= pluginopts_mode;
                                singleproxy["plugin-opts"]["host"] >>= pluginopts_host;
                            }
                            break;
                        case "v2ray-plugin"_hash:
                            plugin = "v2ray-plugin";
                            if (singleproxy["plugin-opts"].IsDefined()) {
                                singleproxy["plugin-opts"]["mode"] >>= pluginopts_mode;
                                singleproxy["plugin-opts"]["host"] >>= pluginopts_host;
                                tls = safe_as<bool>(singleproxy["plugin-opts"]["tls"]) ? "tls;" : "";
                                singleproxy["plugin-opts"]["path"] >>= path;
                                pluginopts_mux = safe_as<bool>(singleproxy["plugin-opts"]["mux"]) ? "4" : "";
                            }
                            break;
                        default:
                            break;
                    }
                } else if (singleproxy["obfs"].IsDefined()) {
                    plugin = "obfs-local";
                    singleproxy["obfs"] >>= pluginopts_mode;
                    singleproxy["obfs-host"] >>= pluginopts_host;
                } else
                    plugin.clear();

                switch (hash_(plugin)) {
                    case "simple-obfs"_hash:
                    case "obfs-local"_hash:
                        pluginopts = "obfs=" + pluginopts_mode;
                        pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
                        break;
                    case "v2ray-plugin"_hash:
                        pluginopts = "mode=" + pluginopts_mode + ";" + tls;
                        if (!pluginopts_host.empty())
                            pluginopts += "host=" + pluginopts_host + ";";
                        if (!path.empty())
                            pluginopts += "path=" + path + ";";
                        if (!pluginopts_mux.empty())
                            pluginopts += "mux=" + pluginopts_mux + ";";
                        break;
                }

            //support for go-shadowsocks2
                if (cipher == "AEAD_CHACHA20_POLY1305")
                    cipher = "chacha20-ietf-poly1305";
                else if (strFind(cipher, "AEAD")) {
                    cipher = replaceAllDistinct(replaceAllDistinct(cipher, "AEAD_", ""), "_", "-");
                    std::transform(cipher.begin(), cipher.end(), cipher.begin(), ::tolower);
                }

                ssConstruct(node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, tfo, scv,
                            tribool(), underlying_proxy);
                break;
            case "socks5"_hash:
                group = SOCKS_DEFAULT_GROUP;

                singleproxy["username"] >>= user;
                singleproxy["password"] >>= password;

                socksConstruct(node, group, ps, server, port, user, password, tribool(), tribool(), tribool(),
                               underlying_proxy);
                break;
            case "ssr"_hash:
                group = SSR_DEFAULT_GROUP;

                singleproxy["cipher"] >>= cipher;
                if (cipher == "dummy") cipher = "none";
                singleproxy["password"] >>= password;
                singleproxy["protocol"] >>= protocol;
                singleproxy["obfs"] >>= obfs;
                if (singleproxy["protocol-param"].IsDefined())
                    singleproxy["protocol-param"] >>= protoparam;
                else
                    singleproxy["protocolparam"] >>= protoparam;
                if (singleproxy["obfs-param"].IsDefined())
                    singleproxy["obfs-param"] >>= obfsparam;
                else
                    singleproxy["obfsparam"] >>= obfsparam;

                ssrConstruct(node, group, ps, server, port, protocol, cipher, obfs, password, obfsparam, protoparam,
                             udp, tfo, scv, underlying_proxy);
                break;
            case "http"_hash:
                group = HTTP_DEFAULT_GROUP;

                singleproxy["username"] >>= user;
                singleproxy["password"] >>= password;
                singleproxy["tls"] >>= tls;

                httpConstruct(node, group, ps, server, port, user, password, tls == "true", tfo, scv, tribool(),
                              underlying_proxy);
                break;
            case "trojan"_hash:
                group = TROJAN_DEFAULT_GROUP;
                singleproxy["password"] >>= password;
                singleproxy["sni"] >>= host;
                singleproxy["sni"] >>= sni;
                singleproxy["network"] >>= net;
                switch (hash_(net)) {
                    case "grpc"_hash:
                        singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                        break;
                    case "ws"_hash:
                        singleproxy["ws-opts"]["path"] >>= path;
                        break;
                    default:
                        net = "tcp";
                        path.clear();
                        break;
                }
                singleproxy["alpn"] >>= alpnList;

                trojanConstruct(node, group, ps, server, port, password, net, host, path, fp, sni, alpnList, true,
                                udp, tfo, scv, tribool(), underlying_proxy);
                break;
            case "snell"_hash:
                group = SNELL_DEFAULT_GROUP;
                singleproxy["psk"] >> password;
                singleproxy["obfs-opts"]["mode"] >>= obfs;
                singleproxy["obfs-opts"]["host"] >>= host;
                singleproxy["version"] >>= aid;

                snellConstruct(node, group, ps, server, port, password, obfs, host, to_int(aid, 0), udp, tfo, scv,
                               underlying_proxy);
                break;
            case "wireguard"_hash:
                group = WG_DEFAULT_GROUP;
                singleproxy["public-key"] >>= public_key;
                singleproxy["private-key"] >>= private_key;
                singleproxy["dns"] >>= dns_server;
                singleproxy["mtu"] >>= mtu;
                singleproxy["preshared-key"] >>= password;
                singleproxy["ip"] >>= ip;
                singleproxy["ipv6"] >>= ipv6;

                wireguardConstruct(node, group, ps, server, port, ip, ipv6, private_key, public_key, password,
                                   dns_server, mtu, "0", "", "", udp, underlying_proxy);
                break;
            case "vless"_hash:
                group = XRAY_DEFAULT_GROUP;
                singleproxy["uuid"] >>= id;
                singleproxy["alterId"] >>= aid;
                net = singleproxy["network"].IsDefined() ? safe_as<std::string>(singleproxy["network"]) : "tcp";
                sni = singleproxy["sni"].IsDefined()
                          ? safe_as<std::string>(singleproxy["sni"])
                          : safe_as<std::string>(
                              singleproxy["servername"]);
                switch (hash_(net)) {
                    case "tcp"_hash:
                    case "http"_hash:
                        singleproxy["http-opts"]["path"][0] >>= path;
                        singleproxy["http-opts"]["headers"]["Host"][0] >>= host;
                        edge.clear();
                        break;
                    case "ws"_hash:
                        if (singleproxy["ws-opts"].IsDefined()) {
                            path = singleproxy["ws-opts"]["path"].IsDefined()
                                       ? safe_as<std::string>(
                                           singleproxy["ws-opts"]["path"])
                                       : "/";
                            singleproxy["ws-opts"]["headers"]["Host"] >>= host;
                            if (host.empty()) {
                                singleproxy["ws-opts"]["headers"]["host"] >>= host;
                            }
                            singleproxy["ws-opts"]["headers"]["Edge"] >>= edge;
                            if (singleproxy["ws-opts"]["v2ray-http-upgrade"].IsDefined()) {
                                v2ray_http_upgrade = safe_as<std::string>(singleproxy["ws-opts"]["v2ray-http-upgrade"]);
                            }
                        } else {
                            path = singleproxy["ws-path"].IsDefined()
                                       ? safe_as<std::string>(singleproxy["ws-path"])
                                       : "/";
                            singleproxy["ws-headers"]["Host"] >>= host;
                            singleproxy["ws-headers"]["Edge"] >>= edge;
                        }

                        break;
                    case "h2"_hash:
                        singleproxy["h2-opts"]["path"] >>= path;
                        singleproxy["h2-opts"]["host"][0] >>= host;
                        edge.clear();
                        break;
                    case "grpc"_hash:
                        singleproxy["servername"] >>= host;
                        singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                        edge.clear();
                        break;
                    default:
                        continue;
                }

                tls = safe_as<std::string>(singleproxy["tls"]) == "true" ? "tls" : "";
                if (singleproxy["reality-opts"].IsDefined()) {
                    host = singleproxy["sni"].IsDefined()
                               ? safe_as<std::string>(singleproxy["sni"])
                               : safe_as<std::string>(singleproxy["servername"]);
                    printf("host:%s", host.c_str());
                    singleproxy["reality-opts"]["public-key"] >>= pbk;
                    singleproxy["reality-opts"]["short-id"] >>= sid;
                }
                singleproxy["flow"] >>= flow;
                singleproxy["client-fingerprint"] >>= fp;
                singleproxy["alpn"] >>= alpnList;
                singleproxy["packet-encoding"] >>= packet_encoding;
                singleproxy["encryption"] >>= encryption;
                bool vless_udp;
                singleproxy["udp"] >> vless_udp;
                vlessConstruct(node, XRAY_DEFAULT_GROUP, ps, server, port, type, id, aid, net, "auto", flow, mode,
                               path, host, "", tls, pbk, sid, fp, sni, alpnList, packet_encoding, encryption, udp,
                               tribool(), tribool(), tribool(), underlying_proxy, v2ray_http_upgrade);
                break;
            case "hysteria"_hash:
                group = HYSTERIA_DEFAULT_GROUP;
                singleproxy["auth_str"] >> auth;
                if (auth.empty()) {
                    singleproxy["auth-str"] >> auth;
                    if (auth.empty()) {
                        singleproxy["password"] >> auth;
                    }
                }
                singleproxy["up"] >> up;
                singleproxy["down"] >> down;
                singleproxy["obfs"] >> obfsParam;
                singleproxy["protocol"] >> type;
                singleproxy["sni"] >> host;
                singleproxy["alpn"][0] >> alpn;
                singleproxy["alpn"] >> alpnList;
                singleproxy["protocol"] >> insecure;
                singleproxy["ports"] >> ports;
                sni = host;
                hysteriaConstruct(node, group, ps, server, port, type, auth, "", host, up, down, alpn, obfsParam,
                                  insecure, ports, sni,
                                  udp, tfo, scv, tribool(), underlying_proxy);
                break;
            case "hysteria2"_hash:
                group = HYSTERIA2_DEFAULT_GROUP;
                singleproxy["password"] >>= password;
                if (password.empty())
                    singleproxy["auth"] >>= password;
                if (singleproxy["up"].IsDefined()) {
                    singleproxy["up"] >>= up;
                    if (up.empty()) {
                        try {
                            up = singleproxy["up"].as<std::string>();
                        } catch (const YAML::BadConversion& e) {
                        }
                    }
                }
                if (singleproxy["down"].IsDefined()) {
                    singleproxy["down"] >>= down;
                    if (down.empty()) {
                        try {
                            down = singleproxy["down"].as<std::string>();
                        } catch (const YAML::BadConversion& e) {
                        }
                    }
                }
                singleproxy["obfs"] >>= obfsParam;
                singleproxy["obfs-password"] >>= obfsPassword;
                singleproxy["sni"] >>= host;
                singleproxy["alpn"][0] >>= alpn;
                singleproxy["ports"] >> ports;
                sni = host;
                hysteria2Construct(node, group, ps, server, port, password, host, up, down, alpn, obfsParam,
                                   obfsPassword, sni, public_key, ports, udp, tfo, scv, underlying_proxy);
                break;
            case "tuic"_hash:
                group = TUIC_DEFAULT_GROUP;
                uint16_t request_timeout;
                singleproxy["password"] >>= password;
                singleproxy["uuid"] >>= id;
                singleproxy["congestion-controller"] >>= congestion_control;
                singleproxy["udp-relay-mode"] >>= udp_relay_mode;
                singleproxy["sni"] >>= sni;
                if (!singleproxy["alpn"].IsNull()) {
                    singleproxy["alpn"][0] >>= alpn;
                }
                singleproxy["disable-sni"] >>= disableSni;
                singleproxy["reduce-rtt"] >>= reduceRtt;
                singleproxy["token"] >>= token;
                singleproxy["request-timeout"] >>= request_timeout;
                tuicConstruct(node, TUIC_DEFAULT_GROUP, ps, server, port, password, congestion_control, alpn, sni, id,
                              udp_relay_mode, token,
                              tribool(),
                              tribool(), scv, reduceRtt, disableSni, request_timeout, underlying_proxy);

                break;
            case "anytls"_hash:
                group = ANYTLS_DEFAULT_GROUP;
                singleproxy["password"] >>= password;
                singleproxy["sni"] >>= sni;

                if (!singleproxy["alpn"].IsNull() && singleproxy["alpn"].size() >= 1) {
                    singleproxy["alpn"][0] >>= alpn;
                    alpns.push_back(alpn);
                    if (singleproxy["alpn"].size() >= 2 && !singleproxy["alpn"][1].IsNull()) {
                        singleproxy["alpn"][1] >>= alpn2;
                        alpns.push_back(alpn2);
                    }
                }
                singleproxy["fingerprint"] >>= fingerprint;
                anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, ps, port, password, server, alpns, fingerprint, sni,
                                udp,
                                tribool(), scv, tribool(), underlying_proxy, 30, 30, 0);
                break;
            case "mieru"_hash:
                group = MIERU_DEFAULT_GROUP;
                singleproxy["password"] >>= password;
                singleproxy["username"] >>= user;
                singleproxy["port-range"] >>= ports;
                if (!singleproxy["multiplexing"].IsNull()) {
                    singleproxy["multiplexing"] >>= multiplexing;
                }
                transfer_protocol = "TCP";
                if (!singleproxy["transport"].IsNull()) {
                    singleproxy["transport"] >>= transfer_protocol;
                }
                mieruConstruct(node, MIERU_DEFAULT_GROUP, ps, port, password, server, ports, user, multiplexing,
                               transfer_protocol,
                               udp,
                               tribool(), scv, tribool(), underlying_proxy);
                break;
            default:
                continue;
        }

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeStdVMess(std::string vmess, Proxy &node) {
    std::string add, port, type, id, aid, net, path, host, tls, remarks;
    std::string addition;
    vmess = vmess.substr(8);
    string_size pos;

    pos = vmess.rfind('#');
    if (pos != std::string::npos) {
        remarks = urlDecode(vmess.substr(pos + 1));
        vmess.erase(pos);
    }
    const std::string stdvmess_matcher =
            R"(^([a-z]+)(?:\+([a-z]+))?:([\da-f]{4}(?:[\da-f]{4}-){4}[\da-f]{12})-(\d+)@(.+):(\d+)(?:\/?\?(.*))?$)";
    if (regGetMatch(vmess, stdvmess_matcher, 8, 0, &net, &tls, &id, &aid, &add, &port, &addition))
        return;

    switch (hash_(net)) {
        case "tcp"_hash:
        case "kcp"_hash:
            type = getUrlArg(addition, "type");
            break;
        case "http"_hash:
        case "ws"_hash:
            host = getUrlArg(addition, "host");
            path = getUrlArg(addition, "path");
            break;
        case "quic"_hash:
            type = getUrlArg(addition, "security");
            host = getUrlArg(addition, "type");
            path = getUrlArg(addition, "key");
            break;
        default:
            return;
    }

    if (remarks.empty())
        remarks = add + ":" + port;
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if (!alpn.empty()) {
        alpnList.push_back(alpn);
    }
    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, "auto", path, host, "", tls, "",
                   alpnList);
}


void explodeStdHysteria(std::string hysteria, Proxy &node) {
    std::string add, port, type, auth, host, insecure, up, down, alpn, obfsParam, remarks, auth_str, sni;
    std::string addition;
    hysteria = hysteria.substr(11);
    string_size pos;

    pos = hysteria.rfind("#");
    if (pos != hysteria.npos) {
        remarks = urlDecode(hysteria.substr(pos + 1));
        hysteria.erase(pos);
    }
    const std::string stdhysteria_matcher = R"(^(.*)[:](\d+)[?](.*)$)";
    if (regGetMatch(hysteria, stdhysteria_matcher, 4, 0, &add, &port, &addition))
        return;
    type = getUrlArg(addition, "protocol");
    auth = getUrlArg(addition, "auth");
    auth_str = getUrlArg(addition, "auth_str");
    host = getUrlArg(addition, "peer");
    insecure = getUrlArg(addition, "insecure");
    up = getUrlArg(addition, "upmbps");
    down = getUrlArg(addition, "downmbps");
    alpn = getUrlArg(addition, "alpn");
    obfsParam = getUrlArg(addition, "obfsParam");
    sni = getUrlArg(addition, "peer");

    if (remarks.empty())
        remarks = add + ":" + port;
    std::vector<std::string> alpnList;
    if (!alpn.empty()) {
        alpnList.push_back(alpn);
    }
    hysteriaConstruct(node, HYSTERIA_DEFAULT_GROUP, remarks, add, port, type, auth, auth_str, host, up, down, alpn,
                      obfsParam,
                      insecure, "", sni);
    return;
}

void explodeStdMieru(std::string mieru, Proxy &node) {
    std::string username, password, host, port, ports, profile, protocol, multiplexing, mtu, remarks;
    std::string addition;
    tribool udp, tfo, scv, tls13;

    // 去除前缀
    string_size pos;

    // 提取 remarks
    pos = mieru.rfind("#");
    if (pos != mieru.npos) {
        remarks = urlDecode(mieru.substr(pos + 1));
        mieru.erase(pos);
    }

    // 提取参数
    pos = mieru.rfind("?");
    if (pos != mieru.npos) {
        addition = mieru.substr(pos + 1);
        mieru.erase(pos);
    }

    // 账号密码@host
    if (regGetMatch(mieru, R"(^(.*?):(.*?)@(.*)$)", 4, 0, &username, &password, &host))
        return;

    // 提取端口（port=多个情况）
    port = getUrlArg(addition, "port");
    if (port.find('-') != std::string::npos) {
        ports = port;
    }
    // 提取协议（多个 protocol）
    protocol = getUrlArg(addition, "protocol");

    multiplexing = getUrlArg(addition, "multiplexing");
    mtu = getUrlArg(addition, "mtu");

    if (remarks.empty())
        remarks = host;

    mieruConstruct(node, "MieruGroup", remarks, port,
                   password, host, ports, username, multiplexing, protocol,
                   udp, tfo, scv, tls13, "");
}

void explodeStdHysteria2(std::string hysteria2, Proxy &node) {
    std::string add, port, password, host, insecure, up, down, alpn, obfsParam, obfsPassword, remarks, sni, ports;
    std::string addition;
    tribool scv;
    hysteria2 = hysteria2.substr(12);
    string_size pos;

    pos = hysteria2.rfind("#");
    if (pos != hysteria2.npos) {
        remarks = urlDecode(hysteria2.substr(pos + 1));
        hysteria2.erase(pos);
    }

    pos = hysteria2.rfind("?");
    if (pos != hysteria2.npos) {
        addition = hysteria2.substr(pos + 1);
        hysteria2.erase(pos);
    }

    if (strFind(hysteria2, "@")) {
        if (regGetMatch(hysteria2, R"(^(.*?)@(.*)[:](\d+)$)", 4, 0, &password, &add, &port))
            return;
    } else {
        password = getUrlArg(addition, "password");
        if (password.empty())
            return;

        if (!strFind(hysteria2, ":"))
            return;

        if (regGetMatch(hysteria2, R"(^(.*)[:](\d+)$)", 3, 0, &add, &port))
            return;
    }

    scv = getUrlArg(addition, "insecure");
    up = getUrlArg(addition, "up");
    down = getUrlArg(addition, "down");
    alpn = getUrlArg(addition, "alpn");
    obfsParam = getUrlArg(addition, "obfs");
    obfsPassword = getUrlArg(addition, "obfs-password");
    host = getUrlArg(addition, "sni");
    sni = getUrlArg(addition, "sni");
    ports = getUrlArg(addition, "ports");
    if (remarks.empty())
        remarks = add + ":" + port;

    hysteria2Construct(node, HYSTERIA2_DEFAULT_GROUP, remarks, add, port, password, host, up, down, alpn, obfsParam,
                       obfsPassword, host, "", ports, tribool(), tribool(), scv);
    return;
}


void explodeStdVless(std::string vless, Proxy &node) {
    std::string add, port, type, id, aid, net, flow, pbk, sid, fp, mode, path, host, tls, remarks, sni, encryption;
    std::string addition;
    vless = vless.substr(8);
    string_size pos;

    pos = vless.rfind("#");
    if (pos != vless.npos) {
        remarks = urlDecode(vless.substr(pos + 1));
        vless.erase(pos);
    }
    const std::string stdvless_matcher =
            R"(^([\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12})@\[?([\d\-a-zA-Z:.]+)\]?:(\d+)(?:\/?\?(.*))?$)";
    if (regGetMatch(vless, stdvless_matcher, 5, 0, &id, &add, &port, &addition))
        return;

    tls = getUrlArg(addition, "security");
    net = getUrlArg(addition, "type");
    flow = getUrlArg(addition, "flow");
    pbk = getUrlArg(addition, "pbk");
    sid = getUrlArg(addition, "sid");
    encryption = getUrlArg(addition, "encryption");
    fp = getUrlArg(addition, "fp");
    std::string packet_encoding = getUrlArg(addition, "packet-encoding");
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if (!alpn.empty()) {
        alpnList.push_back(alpn);
    }
    switch (hash_(net)) {
        case "tcp"_hash:
        case "ws"_hash:
        case "h2"_hash:
            type = getUrlArg(addition, "headerType");
            host = getUrlArg(addition, strFind(addition, "sni") ? "sni" : "host");
            path = getUrlArg(addition, "path");
            break;
        case "xhttp"_hash: // 新增对 type=xhttp 的支持
            net = "h2"; // 视为 h2/http2 传输
            type = getUrlArg(addition, "headerType");
            host = getUrlArg(addition, strFind(addition, "sni") ? "sni" : "host");
            path = getUrlArg(addition, "path");
            break;
        case "grpc"_hash:
            host = getUrlArg(addition, "sni");
            path = getUrlArg(addition, "serviceName");
            mode = getUrlArg(addition, "mode");
            break;
        case "quic"_hash:
            type = getUrlArg(addition, "headerType");
            host = getUrlArg(addition, strFind(addition, "sni") ? "sni" : "quicSecurity");
            path = getUrlArg(addition, "key");
            break;
        default:
            return;
    }

    if (remarks.empty())
        remarks = add + ":" + port;
    sni = getUrlArg(addition, "sni");
    vlessConstruct(node, XRAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, "auto", flow, mode, path, host, "",
                   tls, pbk, sid, fp, sni, alpnList, packet_encoding, encryption);
    return;
}

void explodeShadowrocket(std::string rocket, Proxy &node) {
    std::string add, port, type, id, aid, net = "tcp", path, host, tls, cipher, remarks;
    std::string obfs; //for other style of link
    std::string addition;
    rocket = rocket.substr(8);

    string_size pos = rocket.find('?');
    addition = rocket.substr(pos + 1);
    rocket.erase(pos);

    if (regGetMatch(urlSafeBase64Decode(rocket), "(.*?):(.*)@(.*):(.*)", 5, 0, &cipher, &id, &add, &port))
        return;
    if (port == "0")
        return;
    remarks = urlDecode(getUrlArg(addition, "remarks"));
    obfs = getUrlArg(addition, "obfs");
    if (!obfs.empty()) {
        if (obfs == "websocket") {
            net = "ws";
            host = getUrlArg(addition, "obfsParam");
            path = getUrlArg(addition, "path");
        }
    } else {
        net = getUrlArg(addition, "network");
        host = getUrlArg(addition, "wsHost");
        path = getUrlArg(addition, "wspath");
    }
    tls = getUrlArg(addition, "tls") == "1" ? "tls" : "";
    aid = getUrlArg(addition, "aid");

    if (aid.empty())
        aid = "0";

    if (remarks.empty())
        remarks = add + ":" + port;
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if (!alpn.empty()) {
        alpnList.push_back(alpn);
    }
    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, "",
                   alpnList);
}

void explodeKitsunebi(std::string kit, Proxy &node) {
    std::string add, port, type, id, aid = "0", net = "tcp", path, host, tls, cipher = "auto", remarks;
    std::string addition;
    string_size pos;
    kit = kit.substr(9);

    pos = kit.find('#');
    if (pos != std::string::npos) {
        remarks = kit.substr(pos + 1);
        kit = kit.substr(0, pos);
    }

    pos = kit.find('?');
    addition = kit.substr(pos + 1);
    kit = kit.substr(0, pos);

    if (regGetMatch(kit, "(.*?)@(.*):(.*)", 4, 0, &id, &add, &port))
        return;
    pos = port.find('/');
    if (pos != std::string::npos) {
        path = port.substr(pos);
        port.erase(pos);
    }
    if (port == "0")
        return;
    net = getUrlArg(addition, "network");
    tls = getUrlArg(addition, "tls") == "true" ? "tls" : "";
    host = getUrlArg(addition, "ws.host");

    if (remarks.empty())
        remarks = add + ":" + port;
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if (!alpn.empty()) {
        alpnList.push_back(alpn);
    }
    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, "",
                   alpnList);
}

// peer = (public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, allowed-ips = "0.0.0.0/0, ::/0", endpoint = engage.cloudflareclient.com:2408, client-id = 139/184/125),(public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, endpoint = engage.cloudflareclient.com:2408)
void parsePeers(Proxy &node, const std::string &data) {
    auto peers = regGetAllMatch(data, R"(\((.*?)\))", true);
    if (peers.empty())
        return;
    auto peer = peers[0];
    auto peerdata = regGetAllMatch(peer, R"(([a-z-]+) ?= ?([^" ),]+|".*?"),? ?)", true);
    if (peerdata.size() % 2 != 0)
        return;
    for (size_t i = 0; i < peerdata.size(); i += 2) {
        auto key = peerdata[i];
        auto val = peerdata[i + 1];
        switch (hash_(key)) {
            case "public-key"_hash:
                node.PublicKey = val;
                break;
            case "endpoint"_hash:
                node.Hostname = val.substr(0, val.rfind(':'));
                node.Port = to_int(val.substr(val.rfind(':') + 1));
                break;
            case "client-id"_hash:
                node.ClientId = val;
                break;
            case "allowed-ips"_hash:
                node.AllowedIPs = trimOf(val, '"');
                break;
            default:
                break;
        }
    }
}

bool explodeSurge(std::string surge, std::vector<Proxy> &nodes) {
    std::multimap<std::string, std::string> proxies;
    uint32_t i, index = nodes.size();
    INIReader ini;

    /*
    if(!strFind(surge, "[Proxy]"))
        return false;
    */

    ini.store_isolated_line = true;
    ini.keep_empty_section = false;
    ini.allow_dup_section_titles = true;
    ini.set_isolated_items_section("Proxy");
    ini.add_direct_save_section("Proxy");
    if (surge.find("[Proxy]") != surge.npos)
        surge = regReplace(surge, R"(^[\S\s]*?\[)", "[", false);
    ini.parse(surge);

    if (!ini.section_exist("Proxy"))
        return false;
    ini.enter_section("Proxy");
    ini.get_items(proxies);

    const std::string proxystr = "(.*?)\\s*=\\s*(.*)";

    for (auto &x: proxies) {
        std::string remarks, server, port, method, username, password, sni; //common
        std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, mod_url, mod_md5; //ss
        std::string id, net, tls, host, edge, path, fp; //v2
        std::string protocol, protoparam; //ssr
        std::string section, ip, ipv6, private_key, public_key, mtu, test_url, client_id, peer, keepalive; //wireguard
        string_array dns_servers;
        string_multimap wireguard_config;
        std::string version, aead = "1";
        std::string itemName, itemVal, config;
        std::vector<std::string> configs, vArray, headers, header;
        tribool udp, tfo, scv, tls13;
        Proxy node;

        /*
        remarks = regReplace(x.second, proxystr, "$1");
        configs = split(regReplace(x.second, proxystr, "$2"), ",");
        */
        regGetMatch(x.second, proxystr, 3, 0, &remarks, &config);
        configs = split(config, ",");
        if (configs.size() < 3)
            continue;
        switch (hash_(configs[0])) {
            case "direct"_hash:
            case "reject"_hash:
            case "reject-tinygif"_hash:
                continue;
            case "custom"_hash: //surge 2 style custom proxy
                //remove module detection to speed up parsing and compatible with broken module
                /*
                mod_url = trim(configs[5]);
                if(parsedMD5.count(mod_url) > 0)
                {
                    mod_md5 = parsedMD5[mod_url]; //read calculated MD5 from map
                }
                else
                {
                    mod_md5 = getMD5(webGet(mod_url)); //retrieve module and calculate MD5
                    parsedMD5.insert(std::pair<std::string, std::string>(mod_url, mod_md5)); //save unrecognized module MD5 to map
                }
                */

                //if(mod_md5 == modSSMD5) //is SSEncrypt module
            {
                if (configs.size() < 5)
                    continue;
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;
                method = trim(configs[3]);
                password = trim(configs[4]);

                for (i = 6; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() < 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "obfs"_hash:
                            plugin = "simple-obfs";
                            pluginopts_mode = itemVal;
                            break;
                        case "obfs-host"_hash:
                            pluginopts_host = itemVal;
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        default:
                            continue;
                    }
                }
                if (!plugin.empty()) {
                    pluginopts = "obfs=" + pluginopts_mode;
                    pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
                }

                ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp,
                            tfo, scv);
            }
            //else
            //    continue;
            break;
            case "ss"_hash: //surge 3 style ss proxy
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;

                for (i = 3; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() < 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "encrypt-method"_hash:
                            method = itemVal;
                            break;
                        case "password"_hash:
                            password = itemVal;
                            break;
                        case "obfs"_hash:
                            plugin = "simple-obfs";
                            pluginopts_mode = itemVal;
                            break;
                        case "obfs-host"_hash:
                            pluginopts_host = itemVal;
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        default:
                            continue;
                    }
                }
                if (!plugin.empty()) {
                    pluginopts = "obfs=" + pluginopts_mode;
                    pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
                }

                ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp,
                            tfo, scv);
                break;
            case "socks5"_hash: //surge 3 style socks5 proxy
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;
                if (configs.size() >= 5) {
                    username = trim(configs[3]);
                    password = trim(configs[4]);
                }
                for (i = 5; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() < 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        case "skip-cert-verify"_hash:
                            scv = itemVal;
                            break;
                        default:
                            continue;
                    }
                }
                socksConstruct(node, SOCKS_DEFAULT_GROUP, remarks, server, port, username, password, udp, tfo, scv);
                break;
            case "vmess"_hash: //surge 4 style vmess proxy
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;
                net = "tcp";
                method = "auto";

                for (i = 3; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "username"_hash:
                            id = itemVal;
                            break;
                        case "ws"_hash:
                            net = itemVal == "true" ? "ws" : "tcp";
                            break;
                        case "tls"_hash:
                            tls = itemVal == "true" ? "tls" : "";
                            break;
                        case "ws-path"_hash:
                            path = itemVal;
                            break;
                        case "obfs-host"_hash:
                            host = itemVal;
                            break;
                        case "ws-headers"_hash:
                            headers = split(itemVal, "|");
                            for (auto &y: headers) {
                                header = split(trim(y), ":");
                                if (header.size() != 2)
                                    continue;
                                else if (regMatch(header[0], "(?i)host"))
                                    host = trimQuote(header[1]);
                                else if (regMatch(header[0], "(?i)edge"))
                                    edge = trimQuote(header[1]);
                            }
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        case "skip-cert-verify"_hash:
                            scv = itemVal;
                            break;
                        case "tls13"_hash:
                            tls13 = itemVal;
                            break;
                        case "vmess-aead"_hash:
                            aead = itemVal == "true" ? "0" : "1";
                        default:
                            continue;
                    }
                }

                vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host,
                               edge, tls, "", std::vector<std::string>{}, udp, tfo, scv, tls13);
                break;
            case "http"_hash: //http proxy
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;
                for (i = 3; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() < 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "username"_hash:
                            username = itemVal;
                            break;
                        case "password"_hash:
                            password = itemVal;
                            break;
                        case "skip-cert-verify"_hash:
                            scv = itemVal;
                            break;
                        default:
                            continue;
                    }
                }
                httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, false, tfo, scv);
                break;
            case "trojan"_hash: // surge 4 style trojan proxy
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;

                for (i = 3; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "password"_hash:
                            password = itemVal;
                            break;
                        case "sni"_hash:
                            host = itemVal;
                            sni = itemVal;
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        case "skip-cert-verify"_hash:
                            scv = itemVal;
                            break;
                        case "fingerprint"_hash:
                            fp = itemVal;
                            break;
                        default:
                            continue;
                    }
                }

                trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", fp, sni,
                                std::vector<std::string>{},
                                true,
                                udp,
                                tfo, scv);
                break;
            case "snell"_hash:
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;

                for (i = 3; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "psk"_hash:
                            password = itemVal;
                            break;
                        case "obfs"_hash:
                            plugin = itemVal;
                            break;
                        case "obfs-host"_hash:
                            host = itemVal;
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        case "skip-cert-verify"_hash:
                            scv = itemVal;
                            break;
                        case "version"_hash:
                            version = itemVal;
                            break;
                        default:
                            continue;
                    }
                }

                snellConstruct(node, SNELL_DEFAULT_GROUP, remarks, server, port, password, plugin, host,
                               to_int(version, 0), udp, tfo, scv);
                break;
            case "wireguard"_hash:
                for (i = 1; i < configs.size(); i++) {
                    vArray = split(trim(configs[i]), "=");
                    if (vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "section-name"_hash:
                            section = itemVal;
                            break;
                        case "test-url"_hash:
                            test_url = itemVal;
                            break;
                    }
                }
                if (section.empty())
                    continue;
                ini.get_items("WireGuard " + section, wireguard_config);
                if (wireguard_config.empty())
                    continue;

                for (auto &c: wireguard_config) {
                    itemName = trim(c.first);
                    itemVal = trim(c.second);
                    switch (hash_(itemName)) {
                        case "self-ip"_hash:
                            ip = itemVal;
                            break;
                        case "self-ip-v6"_hash:
                            ipv6 = itemVal;
                            break;
                        case "private-key"_hash:
                            private_key = itemVal;
                            break;
                        case "dns-server"_hash:
                            vArray = split(itemVal, ",");
                            for (auto &y: vArray)
                                dns_servers.emplace_back(trim(y));
                            break;
                        case "mtu"_hash:
                            mtu = itemVal;
                            break;
                        case "peer"_hash:
                            peer = itemVal;
                            break;
                        case "keepalive"_hash:
                            keepalive = itemVal;
                            break;
                    }
                }

                wireguardConstruct(node, WG_DEFAULT_GROUP, remarks, "", "0", ip, ipv6, private_key, "", "", dns_servers,
                                   mtu, keepalive, test_url, "", udp, "");
                parsePeers(node, peer);
                break;
            default:
                switch (hash_(remarks)) {
                    case "shadowsocks"_hash: //quantumult x style ss/ssr link
                        server = trim(configs[0].substr(0, configs[0].rfind(":")));
                        port = trim(configs[0].substr(configs[0].rfind(":") + 1));
                        if (port == "0")
                            continue;

                        for (i = 1; i < configs.size(); i++) {
                            vArray = split(trim(configs[i]), "=");
                            if (vArray.size() != 2)
                                continue;
                            itemName = trim(vArray[0]);
                            itemVal = trim(vArray[1]);
                            switch (hash_(itemName)) {
                                case "method"_hash:
                                    method = itemVal;
                                    break;
                                case "password"_hash:
                                    password = itemVal;
                                    break;
                                case "tag"_hash:
                                    remarks = itemVal;
                                    break;
                                case "ssr-protocol"_hash:
                                    protocol = itemVal;
                                    break;
                                case "ssr-protocol-param"_hash:
                                    protoparam = itemVal;
                                    break;
                                case "obfs"_hash: {
                                    switch (hash_(itemVal)) {
                                        case "http"_hash:
                                        case "tls"_hash:
                                            plugin = "simple-obfs";
                                            pluginopts_mode = itemVal;
                                            break;
                                        case "wss"_hash:
                                            tls = "tls";
                                            [[fallthrough]];
                                        case "ws"_hash:
                                            pluginopts_mode = "websocket";
                                            plugin = "v2ray-plugin";
                                            break;
                                        default:
                                            pluginopts_mode = itemVal;
                                    }
                                    break;
                                }
                                case "obfs-host"_hash:
                                    pluginopts_host = itemVal;
                                    break;
                                case "obfs-uri"_hash:
                                    path = itemVal;
                                    break;
                                case "udp-relay"_hash:
                                    udp = itemVal;
                                    break;
                                case "fast-open"_hash:
                                    tfo = itemVal;
                                    break;
                                case "tls13"_hash:
                                    tls13 = itemVal;
                                    break;
                                default:
                                    continue;
                            }
                        }
                        if (remarks.empty())
                            remarks = server + ":" + port;
                        switch (hash_(plugin)) {
                            case "simple-obfs"_hash:
                                pluginopts = "obfs=" + pluginopts_mode;
                                if (!pluginopts_host.empty())
                                    pluginopts += ";obfs-host=" + pluginopts_host;
                                break;
                            case "v2ray-plugin"_hash:
                                if (pluginopts_host.empty() && !isIPv4(server) && !isIPv6(server))
                                    pluginopts_host = server;
                                pluginopts = "mode=" + pluginopts_mode;
                                if (!pluginopts_host.empty())
                                    pluginopts += ";host=" + pluginopts_host;
                                if (!path.empty())
                                    pluginopts += ";path=" + path;
                                pluginopts += ";" + tls;
                                break;
                        }

                        if (!protocol.empty()) {
                            ssrConstruct(node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method,
                                         pluginopts_mode, password, pluginopts_host, protoparam, udp, tfo, scv);
                        } else {
                            ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin,
                                        pluginopts, udp, tfo, scv, tls13);
                        }
                        break;
                    case "vmess"_hash: //quantumult x style vmess link
                        server = trim(configs[0].substr(0, configs[0].rfind(":")));
                        port = trim(configs[0].substr(configs[0].rfind(":") + 1));
                        if (port == "0")
                            continue;
                        net = "tcp";

                        for (i = 1; i < configs.size(); i++) {
                            vArray = split(trim(configs[i]), "=");
                            if (vArray.size() != 2)
                                continue;
                            itemName = trim(vArray[0]);
                            itemVal = trim(vArray[1]);
                            switch (hash_(itemName)) {
                                case "method"_hash:
                                    method = itemVal;
                                    break;
                                case "password"_hash:
                                    id = itemVal;
                                    break;
                                case "tag"_hash:
                                    remarks = itemVal;
                                    break;
                                case "obfs"_hash:
                                    switch (hash_(itemVal)) {
                                        case "ws"_hash:
                                            net = "ws";
                                            break;
                                        case "over-tls"_hash:
                                            tls = "tls";
                                            break;
                                        case "wss"_hash:
                                            net = "ws";
                                            tls = "tls";
                                            break;
                                    }
                                    break;
                                case "obfs-host"_hash:
                                    host = itemVal;
                                    break;
                                case "obfs-uri"_hash:
                                    path = itemVal;
                                    break;
                                case "over-tls"_hash:
                                    tls = itemVal == "true" ? "tls" : "";
                                    break;
                                case "udp-relay"_hash:
                                    udp = itemVal;
                                    break;
                                case "fast-open"_hash:
                                    tfo = itemVal;
                                    break;
                                case "tls13"_hash:
                                    tls13 = itemVal;
                                    break;
                                case "aead"_hash:
                                    aead = itemVal == "true" ? "0" : "1";
                                default:
                                    continue;
                            }
                        }
                        if (remarks.empty())
                            remarks = server + ":" + port;

                        vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method,
                                       path, host, "", tls, "", std::vector<std::string>{}, udp, tfo, scv, tls13);
                        break;
                    case "vless"_hash: //quantumult x style vless link
                        server = trim(configs[0].substr(0, configs[0].rfind(":")));
                        port = trim(configs[0].substr(configs[0].rfind(":") + 1));
                        if (port == "0")
                            continue;
                        net = "tcp";

                        for (i = 1; i < configs.size(); i++) {
                            vArray = split(trim(configs[i]), "=");
                            if (vArray.size() != 2)
                                continue;
                            itemName = trim(vArray[0]);
                            itemVal = trim(vArray[1]);
                            switch (hash_(itemName)) {
                                case "method"_hash:
                                    method = itemVal;
                                    break;
                                case "password"_hash:
                                    id = itemVal;
                                    break;
                                case "tag"_hash:
                                    remarks = itemVal;
                                    break;
                                case "obfs"_hash:
                                    switch (hash_(itemVal)) {
                                        case "ws"_hash:
                                            net = "ws";
                                            break;
                                        case "over-tls"_hash:
                                            tls = "tls";
                                            break;
                                        case "wss"_hash:
                                            net = "ws";
                                            tls = "tls";
                                            break;
                                    }
                                    break;
                                case "obfs-host"_hash:
                                    host = itemVal;
                                    break;
                                case "obfs-uri"_hash:
                                    path = itemVal;
                                    break;
                                case "over-tls"_hash:
                                    tls = itemVal == "true" ? "tls" : "";
                                    break;
                                case "udp-relay"_hash:
                                    udp = itemVal;
                                    break;
                                case "fast-open"_hash:
                                    tfo = itemVal;
                                    break;
                                case "tls13"_hash:
                                    tls13 = itemVal;
                                    break;
                                case "aead"_hash:
                                    aead = itemVal == "true" ? "0" : "1";
                                default:
                                    continue;
                            }
                        }
                        if (remarks.empty())
                            remarks = server + ":" + port;
                        vlessConstruct(node, XRAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method,
                                       "chrome", "", path, host, "",
                                       tls, "", "", fp, sni, std::vector<std::string>{}, "","", udp, tfo, scv, tls13);
                        break;
                    case "trojan"_hash: //quantumult x style trojan link
                        server = trim(configs[0].substr(0, configs[0].rfind(':')));
                        port = trim(configs[0].substr(configs[0].rfind(':') + 1));
                        if (port == "0")
                            continue;

                        for (i = 1; i < configs.size(); i++) {
                            vArray = split(trim(configs[i]), "=");
                            if (vArray.size() != 2)
                                continue;
                            itemName = trim(vArray[0]);
                            itemVal = trim(vArray[1]);
                            switch (hash_(itemName)) {
                                case "password"_hash:
                                    password = itemVal;
                                    break;
                                case "tag"_hash:
                                    remarks = itemVal;
                                    break;
                                case "over-tls"_hash:
                                    tls = itemVal;
                                    break;
                                case "tls-host"_hash:
                                    host = itemVal;
                                    sni = itemVal;
                                    break;
                                case "udp-relay"_hash:
                                    udp = itemVal;
                                    break;
                                case "fast-open"_hash:
                                    tfo = itemVal;
                                    break;
                                case "tls-verification"_hash:
                                    scv = itemVal == "false";
                                    break;
                                case "tls13"_hash:
                                    tls13 = itemVal;
                                    break;
                                case "fp"_hash:
                                    fp = itemVal;
                                    break;
                                default:
                                    continue;
                            }
                        }
                        if (remarks.empty())
                            remarks = server + ":" + port;

                        trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", fp,
                                        sni, std::vector<std::string>{},
                                        tls == "true", udp, tfo, scv, tls13);
                        break;
                    case "http"_hash: //quantumult x style http links
                        server = trim(configs[0].substr(0, configs[0].rfind(':')));
                        port = trim(configs[0].substr(configs[0].rfind(':') + 1));
                        if (port == "0")
                            continue;

                        for (i = 1; i < configs.size(); i++) {
                            vArray = split(trim(configs[i]), "=");
                            if (vArray.size() != 2)
                                continue;
                            itemName = trim(vArray[0]);
                            itemVal = trim(vArray[1]);
                            switch (hash_(itemName)) {
                                case "username"_hash:
                                    username = itemVal;
                                    break;
                                case "password"_hash:
                                    password = itemVal;
                                    break;
                                case "tag"_hash:
                                    remarks = itemVal;
                                    break;
                                case "over-tls"_hash:
                                    tls = itemVal;
                                    break;
                                case "tls-verification"_hash:
                                    scv = itemVal == "false";
                                    break;
                                case "tls13"_hash:
                                    tls13 = itemVal;
                                    break;
                                case "fast-open"_hash:
                                    tfo = itemVal;
                                    break;
                                default:
                                    continue;
                            }
                        }
                        if (remarks.empty())
                            remarks = server + ":" + port;

                        if (username == "none")
                            username.clear();
                        if (password == "none")
                            password.clear();

                        httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password,
                                      tls == "true", tfo, scv, tls13);
                        break;
                    default:
                        continue;
                }
                break;
        }

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
    return index;
}

void explodeSSTap(std::string sstap, std::vector<Proxy> &nodes) {
    std::string configType, group, remarks, server, port;
    std::string cipher;
    std::string user, pass;
    std::string protocol, protoparam, obfs, obfsparam;
    Document json;
    uint32_t index = nodes.size();
    json.Parse(sstap.data());
    if (json.HasParseError() || !json.IsObject())
        return;

    for (uint32_t i = 0; i < json["configs"].Size(); i++) {
        Proxy node;
        json["configs"][i]["group"] >> group;
        json["configs"][i]["remarks"] >> remarks;
        json["configs"][i]["server"] >> server;
        port = GetMember(json["configs"][i], "server_port");
        if (port == "0")
            continue;

        if (remarks.empty())
            remarks = server + ":" + port;

        json["configs"][i]["password"] >> pass;
        json["configs"][i]["type"] >> configType;
        switch (to_int(configType, 0)) {
            case 5: //socks 5
                json["configs"][i]["username"] >> user;
                socksConstruct(node, group, remarks, server, port, user, pass);
                break;
            case 6: //ss/ssr
                json["configs"][i]["protocol"] >> protocol;
                json["configs"][i]["obfs"] >> obfs;
                json["configs"][i]["method"] >> cipher;
                if (find(ss_ciphers.begin(), ss_ciphers.end(), cipher) != ss_ciphers.end() && protocol == "origin" &&
                    obfs == "plain") //is ss
                {
                    ssConstruct(node, group, remarks, server, port, pass, cipher, "", "");
                } else //is ssr cipher
                {
                    json["configs"][i]["obfsparam"] >> obfsparam;
                    json["configs"][i]["protocolparam"] >> protoparam;
                    ssrConstruct(node, group, remarks, server, port, protocol, cipher, obfs, pass, obfsparam,
                                 protoparam);
                }
                break;
            default:
                continue;
        }

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeNetchConf(std::string netch, std::vector<Proxy> &nodes) {
    Document json;
    uint32_t index = nodes.size();

    json.Parse(netch.data());
    if (json.HasParseError() || !json.IsObject())
        return;

    if (!json.HasMember("Server"))
        return;

    for (uint32_t i = 0; i < json["Server"].Size(); i++) {
        Proxy node;
        explodeNetch("Netch://" + base64Encode(json["Server"][i] | SerializeObject()), node);

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

int explodeConfContent(const std::string &content, std::vector<Proxy> &nodes) {
    ConfType filetype = ConfType::Unknow;

    // 优先检测 JSON 数组格式的订阅（BPB /sub/normal/ 返回的格式）
    // 支持三种格式：
    // 1. JSON 数组：[{"remarks":"...", "outbounds":[...]}]
    // 2. 单个完整配置文件：{"remarks":"...", "outbounds":[...], "inbounds":[...]}
    // 3. Singbox 格式：{"type":"vless","server":"...","server_port":...}
    // 4. Xray 核心格式：{"protocol":"vless","settings":{"vnext":[...]},"streamSettings":{...}}
    
    std::string trimmed = content;
    size_t first_bracket = trimmed.find_first_of("[{");
    if (first_bracket != std::string::npos) {
        trimmed = trimmed.substr(first_bracket);
    }
    
    // 如果是 JSON 数组格式，跳过配置类型检测，直接走订阅解析路径
    // 需要跳过空白字符检测：[\n    { 或 [{" 都应该匹配
    bool is_json_array = startsWith(trimmed, "[{\"");
    if (!is_json_array) {
        // 跳过空白字符后再检测
        std::string trimmed_no_ws;
        for (char c : trimmed) {
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                trimmed_no_ws += c;
            }
        }
        is_json_array = startsWith(trimmed_no_ws, "[{\"");
    }
    bool is_single_xray = (startsWith(trimmed, "{\"remarks\"") || startsWith(trimmed, "\n{\"remarks\"")) && 
                          (strFind(content, "\"outbounds\"") && strFind(content, "\"inbounds\""));
    bool is_singbox = startsWith(trimmed, "{\"type\"") || startsWith(trimmed, "\n{\"type\"");
    
    // 调试日志
    writeLog(LOG_TYPE_INFO, "explodeConfContent: is_json_array=" + std::to_string(is_json_array) + 
             ", is_single_xray=" + std::to_string(is_single_xray) + 
             ", is_singbox=" + std::to_string(is_singbox));
    writeLog(LOG_TYPE_INFO, "explodeConfContent: trimmed_start=" + trimmed.substr(0, std::min((size_t)50, trimmed.size())));
    
    if (!is_json_array && !is_single_xray && !is_singbox) {
        if (strFind(content, "\"version\""))
            filetype = ConfType::SS;
        else if (strFind(content, "\"serverSubscribes\""))
            filetype = ConfType::SSR;
        else if (strFind(content, "\"uiItem\"") || strFind(content, "vnext"))
            filetype = ConfType::V2Ray;
        else if (strFind(content, "\"proxy_apps\""))
            filetype = ConfType::SSConf;
        else if (strFind(content, "\"idInUse\""))
            filetype = ConfType::SSTap;
        else if (strFind(content, "\"local_address\"") && strFind(content, "\"local_port\""))
            filetype = ConfType::SSR; //use ssr config parser
        else if (strFind(content, "\"ModeFileNameType\""))
            filetype = ConfType::Netch;
    }

    switch (filetype) {
        case ConfType::SS:
            explodeSSConf(content, nodes);
            break;
        case ConfType::SSR:
            explodeSSRConf(content, nodes);
            break;
        case ConfType::V2Ray:
            explodeVmessConf(content, nodes);
            break;
        case ConfType::SSConf:
            explodeSSAndroid(content, nodes);
            break;
        case ConfType::SSTap:
            explodeSSTap(content, nodes);
            break;
        case ConfType::Netch:
            explodeNetchConf(content, nodes);
            break;
        default:
            //try to parse as a local subscription
            explodeSub(content, nodes);
    }

    return !nodes.empty();
}

void explodeSingboxTransport(rapidjson::Value &singboxNode, std::string &net, std::string &host, std::string &path,
                             std::string edge) {
    if (singboxNode.HasMember("transport") && singboxNode["transport"].IsObject()) {
        rapidjson::Value transport = singboxNode["transport"].GetObject();
        net = GetMember(transport, "type");
        switch (hash_(net)) {
            case "http"_hash: {
                host = GetMember(transport, "host");
                break;
            }
            case "ws"_hash: {
                path = GetMember(transport, "path");
                if (transport.HasMember("headers") && transport["headers"].IsObject()) {
                    rapidjson::Value headers = transport["headers"].GetObject();
                    host = GetMember(headers, "Host");
                    edge = GetMember(headers, "Edge");
                }
                break;
            }
            case "grpc"_hash: {
                path = GetMember(transport, "service_name");
                break;
            }
            default:
                net = "tcp";
                path.clear();
                break;
        }
    } else {
        net = "tcp";
        host.clear();
        edge.clear();
        path.clear();
    }
}

void explodeSingbox(rapidjson::Value &outbounds, std::vector<Proxy> &nodes) {
    uint32_t index = nodes.size();
    for (rapidjson::SizeType i = 0; i < outbounds.Size(); ++i) {
        if (outbounds[i].IsObject()) {
            std::string proxytype, ps, server, port, cipher, group, password, ports, tempPassword; //common
            std::string type = "none", id, aid = "0", net = "tcp", path, host, edge, tls, sni; //vmess
            std::string fp = "chrome", pbk, sid, packet_encoding, encryption; //vless
            std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, pluginopts_mux; //ss
            std::string protocol, protoparam, obfs, obfsparam; //ssr
            std::string flow, mode; //trojan
            std::string user; //socks
            std::string ip, ipv6, private_key, public_key, mtu; //wireguard
            std::string auth, up, down, obfsParam, insecure, alpn; //hysteria
            std::string obfsPassword; //hysteria2
            string_array dns_server;
            std::string fingerprint;
            std::string congestion_control, udp_relay_mode; //quic
            std::string underlying_proxy;
            tribool udp, tfo, scv, rrt, disableSni;
            rapidjson::Value singboxNode = outbounds[i].GetObject();
            if (singboxNode.HasMember("type") && singboxNode["type"].IsString()) {
                Proxy node;
                proxytype = singboxNode["type"].GetString();
                ps = GetMember(singboxNode, "tag");
                server = GetMember(singboxNode, "server");
                port = GetMember(singboxNode, "server_port");
                underlying_proxy = GetMember(singboxNode, "detour");
                tfo = GetMember(singboxNode, "tcp_fast_open");
                std::vector<std::string> alpnList;
                if (singboxNode.HasMember("tls") && singboxNode["tls"].IsObject()) {
                    rapidjson::Value tlsObj = singboxNode["tls"].GetObject();
                    if (tlsObj.HasMember("enabled") && tlsObj["enabled"].IsBool() && tlsObj["enabled"].GetBool()) {
                        tls = "tls";
                    }
                    sni = GetMember(tlsObj, "server_name");
                    if (tlsObj.HasMember("alpn") && tlsObj["alpn"].IsArray() && !tlsObj["alpn"].Empty()) {
                        rapidjson::Value alpns = tlsObj["alpn"].GetArray();
                        if (alpns.Size() > 0) {
                            alpn = alpns[0].GetString();
                            for (auto &item: tlsObj["alpn"].GetArray()) {
                                if (item.IsString())
                                    alpnList.emplace_back(item.GetString());
                            }
                        }
                    }
                    if (tlsObj.HasMember("insecure") && tlsObj["insecure"].IsBool()) {
                        scv = tlsObj["insecure"].GetBool();
                    }
                    if (tlsObj.HasMember("disable_sni") && tlsObj["disable_sni"].IsBool()) {
                        disableSni = tlsObj["disable_sni"].GetBool();
                    }
                    if (tlsObj.HasMember("certificate") && tlsObj["certificate"].IsString()) {
                        public_key = tlsObj["certificate"].GetString();
                    }
                    if (tlsObj.HasMember("reality") && tlsObj["reality"].IsObject()) {
                        tls = "reality";
                        rapidjson::Value reality = tlsObj["reality"].GetObject();
                        if (reality.HasMember("server_name") && reality["server_name"].IsString()) {
                            host = reality["server_name"].GetString();
                        }
                        if (reality.HasMember("public_key") && reality["public_key"].IsString()) {
                            pbk = reality["public_key"].GetString();
                        }
                        if (reality.HasMember("short_id") && reality["short_id"].IsString()) {
                            sid = reality["short_id"].GetString();
                        }
                    }
                    if (tlsObj.HasMember("utls") && tlsObj["utls"].IsObject()) {
                        if (rapidjson::Value reality = tlsObj["utls"].GetObject();
                            reality.HasMember("fingerprint") && reality["fingerprint"].IsString()) {
                            fingerprint = reality["fingerprint"].GetString();
                        }
                    }
                } else {
                    tls = "false";
                }
                switch (hash_(proxytype)) {
                    case "vmess"_hash:
                        group = V2RAY_DEFAULT_GROUP;
                        id = GetMember(singboxNode, "uuid");
                        if (id.length() < 36) {
                            break;
                        }
                        aid = GetMember(singboxNode, "alter_id");
                        cipher = GetMember(singboxNode, "security");
                        explodeSingboxTransport(singboxNode, net, host, path, edge);
                        vmessConstruct(node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge,
                                       tls, sni, alpnList, udp,
                                       tfo, scv, tribool(), underlying_proxy);
                        break;
                    case "shadowsocks"_hash:
                        group = SS_DEFAULT_GROUP;
                        cipher = GetMember(singboxNode, "method");
                        password = GetMember(singboxNode, "password");
                        plugin = GetMember(singboxNode, "plugin");
                        pluginopts = GetMember(singboxNode, "plugin_opts");
                        ssConstruct(node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, tfo,
                                    scv, tribool(), underlying_proxy);
                        break;
                    case "trojan"_hash:
                        group = TROJAN_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        explodeSingboxTransport(singboxNode, net, host, path, edge);
                        trojanConstruct(node, group, ps, server, port, password, net, host, path, fp, sni, alpnList,
                                        true, udp,
                                        tfo,
                                        scv, tribool(), underlying_proxy);
                        break;
                    case "vless"_hash:
                        group = XRAY_DEFAULT_GROUP;
                        id = GetMember(singboxNode, "uuid");
                        flow = GetMember(singboxNode, "flow");
                        encryption = GetMember(singboxNode, "encryption");
                        packet_encoding = GetMember(singboxNode, "packet_encoding");
                        if (singboxNode.HasMember("transport") && singboxNode["transport"].IsObject()) {
                            rapidjson::Value transport = singboxNode["transport"].GetObject();
                            net = GetMember(transport, "type");
                            switch (hash_(net)) {
                                case "tcp"_hash: {
                                    break;
                                }
                                case "ws"_hash: {
                                    path = GetMember(transport, "path");
                                    if (transport.HasMember("headers") && transport["headers"].IsObject()) {
                                        rapidjson::Value headers = transport["headers"].GetObject();
                                        host = GetMember(headers, "Host");
                                        edge = GetMember(headers, "Edge");
                                    }
                                    break;
                                }
                                case "http"_hash: {
                                    host = GetMember(transport, "host");
                                    path = GetMember(transport, "path");
                                    edge.clear();
                                    break;
                                }
                                case "httpupgrade"_hash: {
                                    net = "h2";
                                    host = GetMember(transport, "host");
                                    path = GetMember(transport, "path");
                                    edge.clear();
                                    break;
                                }
                                case "grpc"_hash: {
                                    host = server;
                                    path = GetMember(transport, "service_name");
                                    break;
                                }
                            }
                        }

                        vlessConstruct(node, group, ps, server, port, type, id, aid, net, "auto", flow, mode, path,
                                       host, "", tls, pbk, sid, fp, sni, alpnList, packet_encoding, encryption,
                                       udp, tribool(), tribool(), tribool(), underlying_proxy);
                        break;
                    case "http"_hash:
                        password = GetMember(singboxNode, "password");
                        user = GetMember(singboxNode, "username");
                        httpConstruct(node, group, ps, server, port, user, password, tls == "tls", tfo, scv,
                                      tribool(), underlying_proxy);
                        break;
                    case "wireguard"_hash:
                        group = WG_DEFAULT_GROUP;
                        ip = GetMember(singboxNode, "inet4_bind_address");
                        ipv6 = GetMember(singboxNode, "inet6_bind_address");
                        public_key = GetMember(singboxNode, "private_key");
                        private_key = GetMember(singboxNode, "public_key");
                        mtu = GetMember(singboxNode, "mtu");
                        password = GetMember(singboxNode, "pre_shared_key");
                        dns_server = {"8.8.8.8"};
                        wireguardConstruct(node, group, ps, server, port, ip, ipv6, private_key, public_key,
                                           password, dns_server, mtu, "0", "", "", udp, underlying_proxy);
                        break;
                    case "socks"_hash:
                        group = SOCKS_DEFAULT_GROUP;
                        user = GetMember(singboxNode, "username");
                        password = GetMember(singboxNode, "password");
                        socksConstruct(node, group, ps, server, port, user, password, tribool(), tribool(),
                                       tribool(), underlying_proxy);
                        break;
                    case "hysteria"_hash:
                        group = HYSTERIA_DEFAULT_GROUP;
                        up = GetMember(singboxNode, "up");
                        if (up.empty()) {
                            up = GetMember(singboxNode, "up_mbps");
                        }
                        down = GetMember(singboxNode, "down");
                        if (down.empty()) {
                            down = GetMember(singboxNode, "down_mbps");
                        }
                        auth = GetMember(singboxNode, "auth_str");
                        type = GetMember(singboxNode, "network");
                        obfsParam = GetMember(singboxNode, "obfs");
                        hysteriaConstruct(node, group, ps, server, port, type, auth, "", host, up, down, alpn,
                                          obfsParam, insecure, ports, sni,
                                          udp, tfo, scv, tribool(), underlying_proxy);
                        break;
                    case "anytls"_hash:
                        group = ANYTLS_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, ps, port, password, server, alpnList,
                                        fingerprint, sni,
                                        udp,
                                        tribool(), scv, tribool(), underlying_proxy, 30, 30, 0);
                        break;
                    case "hysteria2"_hash:
                        group = HYSTERIA2_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        up = GetMember(singboxNode, "up");
                        down = GetMember(singboxNode, "down");
                        if (singboxNode.HasMember("obfs") && singboxNode["obfs"].IsObject()) {
                            rapidjson::Value obfsOpt = singboxNode["obfs"].GetObject();
                            obfsParam = GetMember(obfsOpt, "type");
                            obfsPassword = GetMember(obfsOpt, "password");
                        }
                        hysteria2Construct(node, group, ps, server, port, password, host, up, down, alpn,
                                           obfsParam, obfsPassword, sni, public_key, "", udp, tfo, scv,
                                           underlying_proxy);
                        break;
                    case "tuic"_hash:
                        group = TUIC_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        id = GetMember(singboxNode, "uuid");
                        congestion_control = GetMember(singboxNode, "congestion_control");
                        if (singboxNode.HasMember("zero_rtt_handshake") && singboxNode["zero_rtt_handshake"].IsBool()) {
                            rrt = singboxNode["zero_rtt_handshake"].GetBool();
                        }
                        udp_relay_mode = GetMember(singboxNode, "udp_relay_mode");
                        tuicConstruct(node, TUIC_DEFAULT_GROUP, ps, server, port, password, congestion_control, alpn,
                                      sni, id, udp_relay_mode, "",
                                      tribool(),
                                      tribool(), scv, rrt, disableSni, 15000, underlying_proxy);
                        break;
                    default:
                        continue;
                }
                node.Id = index;
                nodes.emplace_back(std::move(node));
                index++;
            }
        }
    }
}

void explodeTuic(const std::string &tuic, Proxy &node) {
    std::string add, port, password, host, insecure, alpn, remarks, sni, ports, congestion_control, udp_relay_mode;
    std::string addition;
    tribool scv, reduce_rtt, disable_sni;
    std::string link = tuic.substr(7);
    string_size pos;

    pos = link.rfind("#");
    if (pos != std::string::npos) {
        remarks = urlDecode(link.substr(pos + 1));
        link.erase(pos);
    }

    pos = link.rfind("?");
    if (pos != std::string::npos) {
        addition = link.substr(pos + 1);
        link.erase(pos);
    }

    std::string uuid;
    pos = link.find(":");
    if (pos != std::string::npos) {
        uuid = link.substr(0, pos);
        link = link.substr(pos + 1);
        if (strFind(link, "@")) {
            pos = link.find("@");
            if (pos != std::string::npos) {
                password = link.substr(0, pos);
                link = link.substr(pos + 1);
            }
        }
    }

    pos = link.rfind(":");
    if (pos != std::string::npos) {
        add = link.substr(0, pos);
        port = link.substr(pos + 1);
    }

    if (add.length() > 2 && add.front() == '[' && add.back() == ']')
        add = add.substr(1, add.length() - 2);

    scv = getUrlArg(addition, "insecure");
    alpn = getUrlArg(addition, "alpn");
    sni = getUrlArg(addition, "sni");
    congestion_control = getUrlArg(addition, "congestion_control");
    udp_relay_mode = getUrlArg(addition, "udp_relay_mode");
    reduce_rtt = getUrlArg(addition, "reduce_rtt");
    disable_sni = getUrlArg(addition, "disable_sni");

    if (remarks.empty())
        remarks = add + ":" + port;
    tuicConstruct(node, TUIC_DEFAULT_GROUP, remarks, add, port, password, congestion_control, alpn, sni, uuid, udp_relay_mode,
                  "",
                  tribool(),
                  tribool(), scv, reduce_rtt, disable_sni);

    return;
}

void explodeAnyTLS(std::string anytls, Proxy &node) {
    std::string add, port, password, remarks, addition, sni, fp;
    std::vector<std::string> alpnList;
    tribool udp, tfo, scv;
    anytls = anytls.substr(9);
    string_size pos;

    pos = anytls.rfind("#");
    if (pos != anytls.npos) {
        remarks = urlDecode(anytls.substr(pos + 1));
        anytls.erase(pos);
    }

    pos = anytls.rfind("?");
    if (pos != anytls.npos) {
        addition = anytls.substr(pos + 1);
        anytls.erase(pos);
    }

    pos = anytls.find("@");
    if (pos != anytls.npos) {
        password = anytls.substr(0, pos);
        anytls = anytls.substr(pos + 1);
    }

    pos = anytls.rfind(":");
    if (pos != anytls.npos) {
        add = anytls.substr(0, pos);
        port = anytls.substr(pos + 1);
    }

    if (add.length() > 2 && add.front() == '[' && add.back() == ']')
        add = add.substr(1, add.length() - 2);

    if (remarks.empty())
        remarks = add + ":" + port;

    std::string alpn = getUrlArg(addition, "alpn");
    if (!alpn.empty()) {
        auto alpns = split(alpn, ",");
        for (auto &item : alpns) {
            if (!item.empty())
                alpnList.emplace_back(item);
        }
    }

    fp = getUrlArg(addition, "fp");
    if (fp.empty())
        fp = getUrlArg(addition, "fingerprint");
    if (fp.empty())
        fp = urlDecode(getUrlArg(addition, "hpkp"));
    sni = getUrlArg(addition, "sni");
    if (sni.empty())
        sni = getUrlArg(addition, "peer");
    udp = getUrlArg(addition, "udp");
    tfo = getUrlArg(addition, "tfo");
    scv = getUrlArg(addition, "insecure");

    anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, remarks, port, password, add, alpnList, fp, sni, udp, tfo, scv,
                    tribool(), "", 30, 30, 0);
}

void explode(const std::string &link, Proxy &node) {
    if (startsWith(link, "ssr://"))
        explodeSSR(link, node);
    else if (startsWith(link, "vmess://") || startsWith(link, "vmess1://"))
        explodeVmess(link, node);
    else if (startsWith(link, "ss://"))
        explodeSS(link, node);
    else if (startsWith(link, "socks://") || startsWith(link, "https://t.me/socks") || startsWith(link, "tg://socks"))
        explodeSocks(link, node);
    else if (startsWith(link, "https://t.me/http") || startsWith(link, "tg://http")) //telegram style http link
        explodeHTTP(link, node);
    else if (startsWith(link, "Netch://"))
        explodeNetch(link, node);
    else if (startsWith(link, "trojan://") || startsWith(link, "trojan-go://"))
        explodeTrojan(link, node);
    else if (strFind(link, "vless://") || strFind(link, "vless1://"))
        explodeVless(link, node);
    else if (strFind(link, "hysteria://") || strFind(link, "hy://"))
        explodeHysteria(link, node);
    else if (strFind(link, "tuic://"))
        explodeTuic(link, node);
    else if (strFind(link, "anytls://"))
        explodeAnyTLS(link, node);
    else if (strFind(link, "hysteria2://") || strFind(link, "hy2://"))
        explodeHysteria2(link, node);
    else if (strFind(link, "mierus://") || strFind(link, "mieru://"))
        explodeMierus(link, node);
    else if (isLink(link))
        explodeHTTPSub(link, node);
}

void explodeSub(std::string sub, std::vector<Proxy> &nodes) {
    std::stringstream strstream;
    std::string strLink;
    bool processed = false;

    //try to parse as SSD configuration
    if (startsWith(sub, "ssd://")) {
        explodeSSD(sub, nodes);
        processed = true;
    }

    //try to parse as clash configuration
    try {
        if (!processed && regFind(sub, "\"?(Proxy|proxies)\"?:")) {
            regGetMatch(sub, R"(^(?:Proxy|proxies):$\s(?:(?:^ +?.*$| *?-.*$|)\s?)+)", 1, &sub);
            Node yamlnode = Load(sub);
            if (yamlnode.size() && (yamlnode["Proxy"].IsDefined() || yamlnode["proxies"].IsDefined())) {
                explodeClash(yamlnode, nodes);
                processed = true;
            }
        }
    } catch (std::exception &e) {
        //writeLog(0, e.what(), LOG_LEVEL_DEBUG);
        //ignore
        throw;
    }
    try {
        std::string pattern = "\"?(inbounds)\"?:";
        if (!processed &&
            regFind(sub, pattern)) {
            pattern = "\"?(outbounds)\"?:";
            if (regFind(sub, pattern)) {
                // 支持 Sing-Box (route) 和 Xray (routing) 两种格式
                bool isSingbox = regFind(sub, "\"?(route)\"?:");
                bool isXray = regFind(sub, "\"?(routing)\"?:");
                
                if (isSingbox || isXray) {
                    rapidjson::Document document;
                    document.Parse(sub.c_str());
                    if (!document.HasParseError() && document.IsObject()) {
                        rapidjson::Value &value = document["outbounds"];
                        if (value.IsArray() && !value.Empty()) {
                            // Sing-Box 格式
                            if (isSingbox) {
                                explodeSingbox(value, nodes);
                            } 
                            // Xray 格式 - 遍历 outbounds 提取节点
                            else if (isXray) {
                                for (rapidjson::SizeType i = 0; i < value.Size(); ++i) {
                                    if (!value[i].IsObject()) continue;
                                    
                                    std::string type;
                                    GetMember(value[i], "type", type);
                                    if (type.empty()) GetMember(value[i], "protocol", type);
                                    
                                    // 只解析代理节点，跳过其他类型
                                    if (type == "freedom" || type == "blackhole" || type == "dns" || 
                                        type == "direct" || type == "block" || type == "blocked") {
                                        continue;
                                    }
                                    
                                    // 解析 VLESS 节点
                                    if (type == "vless" && value[i].HasMember("settings")) {
                                        auto &settings = value[i]["settings"];
                                        if (settings.HasMember("vnext") && settings["vnext"].Size() > 0) {
                                            auto &vnext = settings["vnext"][0];
                                            std::string add, port, id, flow, encryption = "none";
                                            GetMember(vnext, "address", add);
                                            port = GetMember(vnext, "port");
                                            if (vnext.HasMember("users") && vnext["users"].Size() > 0) {
                                                GetMember(vnext["users"][0], "id", id);
                                                GetMember(vnext["users"][0], "flow", flow);
                                                GetMember(vnext["users"][0], "encryption", encryption);
                                            }
                                            
                                            std::string network = "tcp", security = "none", sni, fp, pbk, sid;
                                            std::string path, host;
                                            if (value[i].HasMember("streamSettings")) {
                                                auto &stream = value[i]["streamSettings"];
                                                GetMember(stream, "network", network);
                                                GetMember(stream, "security", security);
                                                
                                                if (stream.HasMember("tlsSettings")) {
                                                    GetMember(stream["tlsSettings"], "serverName", sni);
                                                    GetMember(stream["tlsSettings"], "fingerprint", fp);
                                                }
                                                if (stream.HasMember("realitySettings")) {
                                                    GetMember(stream["realitySettings"], "serverName", sni);
                                                    GetMember(stream["realitySettings"], "fingerprint", fp);
                                                    GetMember(stream["realitySettings"], "publicKey", pbk);
                                                    GetMember(stream["realitySettings"], "shortId", sid);
                                                }
                                                if (network == "ws" && stream.HasMember("wsSettings")) {
                                                    GetMember(stream["wsSettings"], "path", path);
                                                    if (stream["wsSettings"].HasMember("headers")) {
                                                        GetMember(stream["wsSettings"]["headers"], "Host", host);
                                                    }
                                                }
                                                if (network == "grpc" && stream.HasMember("grpcSettings")) {
                                                    GetMember(stream["grpcSettings"], "serviceName", path);
                                                }
                                            }
                                            
                                            std::string remarks = add + ":" + port;
                                            if (value[i].HasMember("tag")) {
                                                GetMember(value[i], "tag", remarks);
                                            }
                                            
                                            Proxy node;
                                            vlessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, "", id, "0", 
                                                          network, "auto", flow, "", path, host, "", security, pbk, sid, 
                                                          fp, sni, std::vector<std::string>{}, "", encryption,
                                                          tribool(), tribool(), tribool(), tribool(), "", tribool());
                                            node.Id = nodes.size();
                                            nodes.emplace_back(std::move(node));
                                        }
                                    }
                                    // 解析 Trojan 节点
                                    else if (type == "trojan" && value[i].HasMember("settings")) {
                                        auto &settings = value[i]["settings"];
                                        if (settings.HasMember("servers") && settings["servers"].Size() > 0) {
                                            auto &server = settings["servers"][0];
                                            std::string add, port, password;
                                            GetMember(server, "address", add);
                                            port = GetMember(server, "port");
                                            GetMember(server, "password", password);
                                            
                                            std::string network = "tcp", security = "tls", sni, fp;
                                            std::string path, host;
                                            if (value[i].HasMember("streamSettings")) {
                                                auto &stream = value[i]["streamSettings"];
                                                GetMember(stream, "network", network);
                                                GetMember(stream, "security", security);
                                                
                                                if (stream.HasMember("tlsSettings")) {
                                                    GetMember(stream["tlsSettings"], "serverName", sni);
                                                    GetMember(stream["tlsSettings"], "fingerprint", fp);
                                                }
                                                if (network == "ws" && stream.HasMember("wsSettings")) {
                                                    GetMember(stream["wsSettings"], "path", path);
                                                    if (stream["wsSettings"].HasMember("headers")) {
                                                        GetMember(stream["wsSettings"]["headers"], "Host", host);
                                                    }
                                                }
                                            }
                                            
                                            std::string remarks = add + ":" + port;
                                            if (value[i].HasMember("tag")) {
                                                GetMember(value[i], "tag", remarks);
                                            }
                                            
                                            Proxy node;
                                            trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, add, port, password, 
                                                           network, host, path, fp, sni, std::vector<std::string>{}, 
                                                           true, tribool(), tribool(), tribool(), tribool(), "");
                                            node.Id = nodes.size();
                                            nodes.emplace_back(std::move(node));
                                        }
                                    }
                                }
                            }
                            processed = true;
                        }
                    }
                }
            }
        }
    } catch (std::exception &e) {
        writeLog(LOG_TYPE_ERROR, e.what(), LOG_LEVEL_ERROR);
        //writeLog(0, e.what(), LOG_LEVEL_DEBUG);
        //ignore
        throw;
    }
    //try to parse as surge configuration
    if (!processed && explodeSurge(sub, nodes)) {
        processed = true;
    }

    //try to parse as normal subscription
    if (!processed) {
        // 先检测是否是 JSON 格式（BPB /sub/normal/ 返回的格式），如果是则跳过 Base64 解码
        // 支持三种格式：
        // 1. JSON 数组：[{"remarks":"...", "outbounds":[...]}]
        // 2. 单个完整配置文件：{"remarks":"...", "outbounds":[...], "inbounds":[...]}
        // 3. Singbox 格式：{"type":"vless","server":"...","server_port":...}
        // 4. Xray 核心格式：{"protocol":"vless","settings":{"vnext":[...]},"streamSettings":{...}}
        
        // 检测 JSON 数组或对象格式，需要跳过空白字符
        bool is_json = false;
        std::string sub_trimmed = sub;
        size_t first_char = sub_trimmed.find_first_of("[{");
        if (first_char != std::string::npos) {
            sub_trimmed = sub_trimmed.substr(first_char);
            // fix: BPB returns [\n    { (multi-line with whitespace), strip whitespace first
            std::string sub_trimmed_no_ws;
            for (char c : sub_trimmed) {
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
                    sub_trimmed_no_ws += c;
            }
            is_json = (sub_trimmed_no_ws.find("[{\"") == 0 || 
                      sub_trimmed_no_ws.find("{\"") == 0);
        }
        // 兼容原来的检测方式
        if (!is_json) {
            is_json = (sub.find("[{\"") != std::string::npos || 
                      sub.find("\n[{\"") != std::string::npos || 
                      sub.find("{\"remarks\"") != std::string::npos || 
                      sub.find("\n{\"remarks\"") != std::string::npos);
        }
        
        if (!is_json) {
            sub = urlSafeBase64Decode(sub);
        }
        
        if (regFind(sub, "(vmess|shadowsocks|http|trojan)\\s*?=")) {
            if (explodeSurge(sub, nodes))
                return;
        }
        
        if (is_json) {
            std::string trimmed = sub;
            // 找到第一个 [ 或 { 开始的位置
            size_t json_start = trimmed.find_first_of("[{");
            if (json_start != std::string::npos) {
                trimmed = trimmed.substr(json_start);
            }
            
            try {
                rapidjson::Document json;
                json.Parse(trimmed.c_str());
                if (!json.HasParseError()) {
                    std::string xray_nodes;
                    
                    // 支持 JSON 数组格式：[{...}, {...}]
                    if (json.IsArray()) {
                        // 遍历数组中的每个配置对象
                        for (rapidjson::SizeType i = 0; i < json.Size(); ++i) {
                            if (!json[i].IsObject()) continue;
                            auto &config = json[i];
                            
                            if (!config.HasMember("outbounds") || !config["outbounds"].IsArray()) continue;
                            
                            // 提取节点名称
                            std::string remarks;
                            if (config.HasMember("remarks") && config["remarks"].IsString()) {
                                remarks = config["remarks"].GetString();
                            }
                            
                            // 遍历 outbounds
                            for (rapidjson::SizeType j = 0; j < config["outbounds"].Size(); ++j) {
                                if (!config["outbounds"][j].IsObject()) continue;
                                auto &outbound = config["outbounds"][j];
                                
                                std::string protocol;
                                if (outbound.HasMember("protocol") && outbound["protocol"].IsString()) {
                                    protocol = outbound["protocol"].GetString();
                                } else if (outbound.HasMember("type") && outbound["type"].IsString()) {
                                    protocol = outbound["type"].GetString();
                                } else {
                                    continue;
                                }
                                
                                if (protocol != "vless" && protocol != "trojan" && protocol != "vmess" && 
                                    protocol != "shadowsocks" && protocol != "ss" && protocol != "shadowsocksr" && 
                                    protocol != "ssr" && protocol != "hysteria2" && protocol != "tuic") continue;
                                
                                // 提取字段并构建 URI（复用下面的逻辑）
                                std::string server, server_port, uuid, password, flow, sni;
                                std::string network = "tcp", path, host, security = "none";
                                
                                if (protocol == "vless") {
                                    if (outbound.HasMember("settings") && outbound["settings"].IsObject()) {
                                        auto &settings = outbound["settings"];
                                        if (settings.HasMember("vnext") && settings["vnext"].IsArray() && !settings["vnext"].Empty()) {
                                            auto &vnext = settings["vnext"][0];
                                            if (vnext.HasMember("address") && vnext["address"].IsString()) server = vnext["address"].GetString();
                                            if (vnext.HasMember("port")) server_port = vnext["port"].IsInt() ? std::to_string(vnext["port"].GetInt()) : vnext["port"].GetString();
                                            if (vnext.HasMember("users") && vnext["users"].IsArray() && !vnext["users"].Empty()) {
                                                auto &user = vnext["users"][0];
                                                if (user.HasMember("id") && user["id"].IsString()) uuid = user["id"].GetString();
                                                if (user.HasMember("flow") && user["flow"].IsString()) flow = user["flow"].GetString();
                                            }
                                        }
                                    }
                                    if (outbound.HasMember("streamSettings") && outbound["streamSettings"].IsObject()) {
                                        auto &streamSettings = outbound["streamSettings"];
                                        if (streamSettings.HasMember("network") && streamSettings["network"].IsString()) network = streamSettings["network"].GetString();
                                        if (streamSettings.HasMember("security") && streamSettings["security"].IsString()) security = streamSettings["security"].GetString();
                                        if (network == "ws" && streamSettings.HasMember("wsSettings") && streamSettings["wsSettings"].IsObject()) {
                                            auto &wsSettings = streamSettings["wsSettings"];
                                            if (wsSettings.HasMember("path") && wsSettings["path"].IsString()) path = wsSettings["path"].GetString();
                                            if (wsSettings.HasMember("headers") && wsSettings["headers"].IsObject() && wsSettings["headers"].HasMember("Host") && wsSettings["headers"]["Host"].IsString()) host = wsSettings["headers"]["Host"].GetString();
                                        }
                                        if (streamSettings.HasMember("tlsSettings") && streamSettings["tlsSettings"].IsObject()) {
                                            auto &tlsSettings = streamSettings["tlsSettings"];
                                            if (tlsSettings.HasMember("serverName") && tlsSettings["serverName"].IsString()) sni = tlsSettings["serverName"].GetString();
                                        }
                                    }
                                    if (!server.empty() && !server_port.empty() && !uuid.empty()) {
                                        std::string uri = "vless://" + uuid + "@" + server + ":" + server_port;
                                        uri += "?encryption=none&security=" + security;
                                        if (!network.empty()) uri += "&type=" + network;
                                        if (!host.empty()) uri += "&host=" + urlEncode(host);
                                        if (!path.empty()) uri += "&path=" + urlEncode(path);
                                        if (!sni.empty()) uri += "&sni=" + urlEncode(sni);
                                        if (!flow.empty()) uri += "&flow=" + flow;
                                        if (!remarks.empty()) uri += "#" + urlEncode(remarks);
                                        xray_nodes += uri + "\n";
                                    }
                                } else if (protocol == "vmess") {
                                    // VMess 协议解析
                                    std::string vmess_uuid, vmess_aid, vmess_net, vmess_type, vmess_path, vmess_host, vmess_tls;
                                    
                                    // Xray 核心格式：从 settings.vnext 提取
                                    if (outbound.HasMember("settings") && outbound["settings"].IsObject()) {
                                        auto &settings = outbound["settings"];
                                        if (settings.HasMember("vnext") && settings["vnext"].IsArray() && !settings["vnext"].Empty()) {
                                            auto &vnext = settings["vnext"][0];
                                            if (vnext.HasMember("address") && vnext["address"].IsString()) server = vnext["address"].GetString();
                                            if (vnext.HasMember("port")) server_port = vnext["port"].IsInt() ? std::to_string(vnext["port"].GetInt()) : vnext["port"].GetString();
                                            if (vnext.HasMember("users") && vnext["users"].IsArray() && !vnext["users"].Empty()) {
                                                auto &user = vnext["users"][0];
                                                if (user.HasMember("id") && user["id"].IsString()) vmess_uuid = user["id"].GetString();
                                                if (user.HasMember("alterId") && user["alterId"].IsInt()) vmess_aid = std::to_string(user["alterId"].GetInt());
                                            }
                                        }
                                    }
                                    // Singbox 格式：直接提取字段
                                    else {
                                        if (outbound.HasMember("server") && outbound["server"].IsString()) server = outbound["server"].GetString();
                                        if (outbound.HasMember("server_port")) server_port = outbound["server_port"].IsInt() ? std::to_string(outbound["server_port"].GetInt()) : outbound["server_port"].GetString();
                                        if (outbound.HasMember("uuid") && outbound["uuid"].IsString()) vmess_uuid = outbound["uuid"].GetString();
                                        if (outbound.HasMember("alterId") && outbound["alterId"].IsInt()) vmess_aid = std::to_string(outbound["alterId"].GetInt());
                                    }
                                    
                                    // 提取传输配置
                                    if (outbound.HasMember("streamSettings") && outbound["streamSettings"].IsObject()) {
                                        auto &streamSettings = outbound["streamSettings"];
                                        if (streamSettings.HasMember("network") && streamSettings["network"].IsString()) vmess_net = streamSettings["network"].GetString();
                                        if (streamSettings.HasMember("security") && streamSettings["security"].IsString()) vmess_tls = streamSettings["security"].GetString();
                                        
                                        if (vmess_net == "ws" && streamSettings.HasMember("wsSettings") && streamSettings["wsSettings"].IsObject()) {
                                            auto &wsSettings = streamSettings["wsSettings"];
                                            if (wsSettings.HasMember("path") && wsSettings["path"].IsString()) vmess_path = wsSettings["path"].GetString();
                                            if (wsSettings.HasMember("headers") && wsSettings["headers"].IsObject() && wsSettings["headers"].HasMember("Host") && wsSettings["headers"]["Host"].IsString()) vmess_host = wsSettings["headers"]["Host"].GetString();
                                        }
                                    }
                                    // Singbox 格式：从 transport 提取
                                    else if (outbound.HasMember("transport") && outbound["transport"].IsObject()) {
                                        auto &transport = outbound["transport"];
                                        if (transport.HasMember("type") && transport["type"].IsString()) vmess_net = transport["type"].GetString();
                                        if (transport.HasMember("path") && transport["path"].IsString()) vmess_path = transport["path"].GetString();
                                        if (transport.HasMember("headers") && transport["headers"].IsObject() && transport["headers"].HasMember("Host") && transport["headers"]["Host"].IsString()) vmess_host = transport["headers"]["Host"].GetString();
                                    }
                                    
                                    // 构建 VMess URI (Base64 编码的 JSON)
                                    if (!server.empty() && !server_port.empty() && !vmess_uuid.empty()) {
                                        if (vmess_net.empty()) vmess_net = "tcp";
                                        if (vmess_aid.empty()) vmess_aid = "0";
                                        
                                        // 构建 VMess JSON
                                        std::string vmess_json = "{";
                                        vmess_json += "\"v\":\"2\",";
                                        vmess_json += "\"ps\":\"" + remarks + "\",";
                                        vmess_json += "\"add\":\"" + server + "\",";
                                        vmess_json += "\"port\":" + server_port + ",";
                                        vmess_json += "\"id\":\"" + vmess_uuid + "\",";
                                        vmess_json += "\"aid\":" + vmess_aid + ",";
                                        vmess_json += "\"net\":\"" + vmess_net + "\",";
                                        vmess_json += "\"type\":\"" + vmess_type + "\",";
                                        vmess_json += "\"host\":\"" + vmess_host + "\",";
                                        vmess_json += "\"path\":\"" + vmess_path + "\",";
                                        vmess_json += "\"tls\":\"" + vmess_tls + "\"";
                                        vmess_json += "}";
                                        
                                        // Base64 编码
                                        std::string vmess_b64 = urlSafeBase64Encode(vmess_json);
                                        xray_nodes += "vmess://" + vmess_b64 + "\n";
                                    }
                                } else if (protocol == "shadowsocks" || protocol == "ss") {
                                    // Shadowsocks 协议解析
                                    std::string ss_method, ss_password, ss_plugin, ss_plugin_opts;
                                    
                                    if (outbound.HasMember("settings") && outbound["settings"].IsObject()) {
                                        auto &settings = outbound["settings"];
                                        if (settings.HasMember("servers") && settings["servers"].IsArray() && !settings["servers"].Empty()) {
                                            auto &srv = settings["servers"][0];
                                            if (srv.HasMember("address") && srv["address"].IsString()) server = srv["address"].GetString();
                                            if (srv.HasMember("port")) server_port = srv["port"].IsInt() ? std::to_string(srv["port"].GetInt()) : srv["port"].GetString();
                                            if (srv.HasMember("password") && srv["password"].IsString()) ss_password = srv["password"].GetString();
                                            if (srv.HasMember("method") && srv["method"].IsString()) ss_method = srv["method"].GetString();
                                        }
                                    }
                                    // Singbox 格式
                                    else {
                                        if (outbound.HasMember("server") && outbound["server"].IsString()) server = outbound["server"].GetString();
                                        if (outbound.HasMember("server_port")) server_port = outbound["server_port"].IsInt() ? std::to_string(outbound["server_port"].GetInt()) : outbound["server_port"].GetString();
                                        if (outbound.HasMember("password") && outbound["password"].IsString()) ss_password = outbound["password"].GetString();
                                        if (outbound.HasMember("method") && outbound["method"].IsString()) ss_method = outbound["method"].GetString();
                                    }
                                    
                                    // 构建 SS URI
                                    if (!server.empty() && !server_port.empty() && !ss_method.empty() && !ss_password.empty()) {
                                        std::string userinfo = urlSafeBase64Encode(ss_method + ":" + ss_password);
                                        std::string uri = "ss://" + userinfo + "@" + server + ":" + server_port;
                                        if (!remarks.empty()) uri += "#" + urlEncode(remarks);
                                        xray_nodes += uri + "\n";
                                    }
                                } else if (protocol == "shadowsocksr" || protocol == "ssr") {
                                    // ShadowsocksR 协议解析
                                    std::string ssr_method, ssr_password, ssr_protocol, ssr_obfs, ssr_protocol_param, ssr_obfs_param;
                                    
                                    if (outbound.HasMember("settings") && outbound["settings"].IsObject()) {
                                        auto &settings = outbound["settings"];
                                        if (settings.HasMember("servers") && settings["servers"].IsArray() && !settings["servers"].Empty()) {
                                            auto &srv = settings["servers"][0];
                                            if (srv.HasMember("address") && srv["address"].IsString()) server = srv["address"].GetString();
                                            if (srv.HasMember("port")) server_port = srv["port"].IsInt() ? std::to_string(srv["port"].GetInt()) : srv["port"].GetString();
                                            if (srv.HasMember("password") && srv["password"].IsString()) ssr_password = srv["password"].GetString();
                                            if (srv.HasMember("method") && srv["method"].IsString()) ssr_method = srv["method"].GetString();
                                            if (srv.HasMember("protocol") && srv["protocol"].IsString()) ssr_protocol = srv["protocol"].GetString();
                                            if (srv.HasMember("obfs") && srv["obfs"].IsString()) ssr_obfs = srv["obfs"].GetString();
                                        }
                                    }
                                    
                                    // 构建 SSR URI (Base64 编码)
                                    if (!server.empty() && !server_port.empty() && !ssr_method.empty() && !ssr_password.empty()) {
                                        if (ssr_protocol.empty()) ssr_protocol = "origin";
                                        if (ssr_obfs.empty()) ssr_obfs = "plain";
                                        
                                        std::string base_part = server + ":" + server_port + ":" + ssr_protocol + ":" + ssr_method + ":" + ssr_obfs + ":" + urlSafeBase64Encode(ssr_password);
                                        std::string params = "";
                                        if (!remarks.empty()) params += "&remarks=" + urlSafeBase64Encode(remarks);
                                        
                                        std::string uri = "ssr://" + urlSafeBase64Encode(base_part + "/?" + params.substr(1));
                                        xray_nodes += uri + "\n";
                                    }
                                } else if (protocol == "hysteria2") {
                                    // Hysteria2 协议解析
                                    std::string hy_password, hy_sni, hy_alpn, hy_obfs, hy_obfs_password;
                                    
                                    if (outbound.HasMember("settings") && outbound["settings"].IsObject()) {
                                        auto &settings = outbound["settings"];
                                        if (settings.HasMember("servers") && settings["servers"].IsArray() && !settings["servers"].Empty()) {
                                            auto &srv = settings["servers"][0];
                                            if (srv.HasMember("address") && srv["address"].IsString()) server = srv["address"].GetString();
                                            if (srv.HasMember("port")) server_port = srv["port"].IsInt() ? std::to_string(srv["port"].GetInt()) : srv["port"].GetString();
                                            if (srv.HasMember("password") && srv["password"].IsString()) hy_password = srv["password"].GetString();
                                        }
                                    }
                                    // Singbox 格式
                                    else {
                                        if (outbound.HasMember("server") && outbound["server"].IsString()) server = outbound["server"].GetString();
                                        if (outbound.HasMember("server_port")) server_port = outbound["server_port"].IsInt() ? std::to_string(outbound["server_port"].GetInt()) : outbound["server_port"].GetString();
                                        if (outbound.HasMember("password") && outbound["password"].IsString()) hy_password = outbound["password"].GetString();
                                    }
                                    
                                    // 提取 TLS 配置
                                    if (outbound.HasMember("tls") && outbound["tls"].IsObject()) {
                                        auto &tls = outbound["tls"];
                                        if (tls.HasMember("server_name") && tls["server_name"].IsString()) hy_sni = tls["server_name"].GetString();
                                        if (tls.HasMember("alpn") && tls["alpn"].IsArray() && !tls["alpn"].Empty()) {
                                            hy_alpn = tls["alpn"][0].IsString() ? tls["alpn"][0].GetString() : "";
                                        }
                                    }
                                    
                                    // 构建 Hysteria2 URI
                                    if (!server.empty() && !server_port.empty() && !hy_password.empty()) {
                                        std::string uri = "hysteria2://" + hy_password + "@" + server + ":" + server_port;
                                        std::string params = "?";
                                        if (!hy_sni.empty()) params += "sni=" + urlEncode(hy_sni) + "&";
                                        if (!hy_alpn.empty()) params += "alpn=" + urlEncode(hy_alpn) + "&";
                                        if (!hy_obfs.empty()) params += "obfs=" + urlEncode(hy_obfs) + "&";
                                        if (!hy_obfs_password.empty()) params += "obfs-password=" + urlEncode(hy_obfs_password) + "&";
                                        
                                        if (params.size() > 1) uri += params;
                                        if (!remarks.empty()) uri += "#" + urlEncode(remarks);
                                        xray_nodes += uri + "\n";
                                    }
                                } else if (protocol == "tuic") {
                                    // TUIC 协议解析
                                    std::string tuic_uuid, tuic_password, tuic_congestion_control, tuic_alpn, tuic_sni;
                                    
                                    if (outbound.HasMember("settings") && outbound["settings"].IsObject()) {
                                        auto &settings = outbound["settings"];
                                        if (settings.HasMember("servers") && settings["servers"].IsArray() && !settings["servers"].Empty()) {
                                            auto &srv = settings["servers"][0];
                                            if (srv.HasMember("address") && srv["address"].IsString()) server = srv["address"].GetString();
                                            if (srv.HasMember("port")) server_port = srv["port"].IsInt() ? std::to_string(srv["port"].GetInt()) : srv["port"].GetString();
                                        }
                                        if (settings.HasMember("uuid") && settings["uuid"].IsString()) tuic_uuid = settings["uuid"].GetString();
                                        if (settings.HasMember("password") && settings["password"].IsString()) tuic_password = settings["password"].GetString();
                                    }
                                    // Singbox 格式
                                    else {
                                        if (outbound.HasMember("server") && outbound["server"].IsString()) server = outbound["server"].GetString();
                                        if (outbound.HasMember("server_port")) server_port = outbound["server_port"].IsInt() ? std::to_string(outbound["server_port"].GetInt()) : outbound["server_port"].GetString();
                                        if (outbound.HasMember("uuid") && outbound["uuid"].IsString()) tuic_uuid = outbound["uuid"].GetString();
                                        if (outbound.HasMember("password") && outbound["password"].IsString()) tuic_password = outbound["password"].GetString();
                                    }
                                    
                                    // 提取 TUIC 配置
                                    if (outbound.HasMember("congestion_control") && outbound["congestion_control"].IsString()) {
                                        tuic_congestion_control = outbound["congestion_control"].GetString();
                                    }
                                    if (outbound.HasMember("alpn") && outbound["alpn"].IsArray() && !outbound["alpn"].Empty()) {
                                        tuic_alpn = outbound["alpn"][0].IsString() ? outbound["alpn"][0].GetString() : "";
                                    }
                                    
                                    // 提取 TLS 配置
                                    if (outbound.HasMember("tls") && outbound["tls"].IsObject()) {
                                        auto &tls = outbound["tls"];
                                        if (tls.HasMember("server_name") && tls["server_name"].IsString()) tuic_sni = tls["server_name"].GetString();
                                    }
                                    
                                    // 构建 TUIC URI
                                    if (!server.empty() && !server_port.empty() && !tuic_uuid.empty() && !tuic_password.empty()) {
                                        std::string uri = "tuic://" + tuic_uuid + ":" + tuic_password + "@" + server + ":" + server_port;
                                        std::string params = "?";
                                        if (!tuic_congestion_control.empty()) params += "congestion_control=" + tuic_congestion_control + "&";
                                        if (!tuic_alpn.empty()) params += "alpn=" + tuic_alpn + "&";
                                        if (!tuic_sni.empty()) params += "sni=" + urlEncode(tuic_sni) + "&";
                                        
                                        if (params.size() > 1) uri += params;
                                        if (!remarks.empty()) uri += "#" + urlEncode(remarks);
                                        xray_nodes += uri + "\n";
                                    }
                                }
                            }
                        }
                        // 关键修复：数组分支构建的 xray_nodes 必须写回 sub，否则后续 explode() 拿不到节点
                        if (!xray_nodes.empty()) {
                            sub = xray_nodes;
                        }
                    }
                    // 支持单个对象格式：{...}
                    else if (json.IsObject() && json.HasMember("outbounds") && json["outbounds"].IsArray()) {
                        std::string remarks;
                        if (json.HasMember("remarks") && json["remarks"].IsString()) {
                            remarks = json["remarks"].GetString();
                        }
                        
                        for (rapidjson::SizeType j = 0; j < json["outbounds"].Size(); ++j) {
                            if (!json["outbounds"][j].IsObject()) continue;
                            auto &outbound = json["outbounds"][j];
                            
                            std::string protocol;
                            if (outbound.HasMember("protocol") && outbound["protocol"].IsString()) {
                                protocol = outbound["protocol"].GetString();
                            }
                            else if (outbound.HasMember("type") && outbound["type"].IsString()) {
                                protocol = outbound["type"].GetString();
                            }
                            else {
                                continue;
                            }
                            
                                if (protocol != "vless" && protocol != "trojan" && protocol != "vmess" && 
                                    protocol != "shadowsocks" && protocol != "ss" && protocol != "shadowsocksr" && 
                                    protocol != "ssr" && protocol != "hysteria2" && protocol != "tuic") continue;
                            
                            // VLESS 和 Trojan 的解析逻辑已经在上面实现
                            // 这里需要添加 VMess, SS, SSR, Hysteria2, TUIC 的支持
                            // 由于代码复用性，建议在 JSON 数组部分统一处理
                            
                            // 对于单个对象格式，也支持同样的协议
                            if (protocol == "vmess" || protocol == "shadowsocks" || protocol == "ss" || 
                                protocol == "shadowsocksr" || protocol == "ssr" || 
                                protocol == "hysteria2" || protocol == "tuic") {
                                // 这些协议已经在上面的数组处理中实现
                                // 单个对象格式会走同样的逻辑
                            }
                            
                            // 提取必要字段
                            std::string server, server_port, uuid, password, flow, sni;
                            std::string network = "tcp", path, host, security = "none";
                            
                            if (protocol == "vless") {
                                // Xray 核心格式：从 settings.vnext 提取
                                if (outbound.HasMember("settings") && outbound["settings"].IsObject()) {
                                    auto &settings = outbound["settings"];
                                    if (settings.HasMember("vnext") && settings["vnext"].IsArray() && !settings["vnext"].Empty()) {
                                        auto &vnext = settings["vnext"][0];
                                        if (vnext.HasMember("address") && vnext["address"].IsString())
                                            server = vnext["address"].GetString();
                                        if (vnext.HasMember("port")) {
                                            if (vnext["port"].IsInt())
                                                server_port = std::to_string(vnext["port"].GetInt());
                                            else if (vnext["port"].IsString())
                                                server_port = vnext["port"].GetString();
                                        }
                                        if (vnext.HasMember("users") && vnext["users"].IsArray() && !vnext["users"].Empty()) {
                                            auto &user = vnext["users"][0];
                                            if (user.HasMember("id") && user["id"].IsString())
                                                uuid = user["id"].GetString();
                                            if (user.HasMember("flow") && user["flow"].IsString())
                                                flow = user["flow"].GetString();
                                        }
                                    }
                                }
                                // Singbox 格式：直接提取字段
                                else {
                                    if (outbound.HasMember("server") && outbound["server"].IsString())
                                        server = outbound["server"].GetString();
                                    if (outbound.HasMember("server_port")) {
                                        if (outbound["server_port"].IsInt())
                                            server_port = std::to_string(outbound["server_port"].GetInt());
                                        else if (outbound["server_port"].IsString())
                                            server_port = outbound["server_port"].GetString();
                                    }
                                    if (outbound.HasMember("uuid") && outbound["uuid"].IsString())
                                        uuid = outbound["uuid"].GetString();
                                    if (outbound.HasMember("flow") && outbound["flow"].IsString())
                                        flow = outbound["flow"].GetString();
                                }
                                
                                // Xray 核心格式：从 streamSettings 提取传输配置
                                if (outbound.HasMember("streamSettings") && outbound["streamSettings"].IsObject()) {
                                    auto &streamSettings = outbound["streamSettings"];
                                    if (streamSettings.HasMember("network") && streamSettings["network"].IsString())
                                        network = streamSettings["network"].GetString();
                                    if (streamSettings.HasMember("security") && streamSettings["security"].IsString())
                                        security = streamSettings["security"].GetString();
                                    
                                    // 提取 ws 配置
                                    if (network == "ws" && streamSettings.HasMember("wsSettings") && streamSettings["wsSettings"].IsObject()) {
                                        auto &wsSettings = streamSettings["wsSettings"];
                                        if (wsSettings.HasMember("path") && wsSettings["path"].IsString())
                                            path = wsSettings["path"].GetString();
                                        if (wsSettings.HasMember("headers") && wsSettings["headers"].IsObject()) {
                                            if (wsSettings["headers"].HasMember("Host") && wsSettings["headers"]["Host"].IsString())
                                                host = wsSettings["headers"]["Host"].GetString();
                                        }
                                    }
                                    
                                    // 提取 tls 配置
                                    if (streamSettings.HasMember("tlsSettings") && streamSettings["tlsSettings"].IsObject()) {
                                        auto &tlsSettings = streamSettings["tlsSettings"];
                                        if (tlsSettings.HasMember("serverName") && tlsSettings["serverName"].IsString())
                                            sni = tlsSettings["serverName"].GetString();
                                    }
                                }
                                // Singbox 格式：从 transport 和 tls 提取
                                else {
                                    if (outbound.HasMember("transport") && outbound["transport"].IsObject()) {
                                        auto &transport = outbound["transport"];
                                        if (transport.HasMember("type") && transport["type"].IsString())
                                            network = transport["type"].GetString();
                                        if (transport.HasMember("path") && transport["path"].IsString())
                                            path = transport["path"].GetString();
                                        if (transport.HasMember("headers") && transport["headers"].IsObject()) {
                                            if (transport["headers"].HasMember("Host") && transport["headers"]["Host"].IsString())
                                                host = transport["headers"]["Host"].GetString();
                                        }
                                    }
                                    
                                    if (outbound.HasMember("tls") && outbound["tls"].IsObject()) {
                                        auto &tls = outbound["tls"];
                                        if (tls.HasMember("enabled") && tls["enabled"].IsBool() && tls["enabled"].GetBool())
                                            security = "tls";
                                        if (tls.HasMember("server_name") && tls["server_name"].IsString())
                                            sni = tls["server_name"].GetString();
                                    }
                                }
                                
                                // 构建 VLESS URI
                                if (!server.empty() && !server_port.empty() && !uuid.empty()) {
                                    std::string uri = "vless://" + uuid + "@" + server + ":" + server_port;
                                    uri += "?encryption=none";
                                    uri += "&security=" + security;
                                    if (!network.empty()) uri += "&type=" + network;
                                    if (!host.empty()) uri += "&host=" + urlEncode(host);
                                    if (!path.empty()) uri += "&path=" + urlEncode(path);
                                    if (!sni.empty()) uri += "&sni=" + urlEncode(sni);
                                    if (!flow.empty()) uri += "&flow=" + flow;
                                    if (!remarks.empty()) uri += "#" + urlEncode(remarks);
                                    xray_nodes += uri + "\n";
                                }
                            }
                            else if (protocol == "trojan") {
                                // Xray 核心格式：从 settings.servers 提取
                                if (outbound.HasMember("settings") && outbound["settings"].IsObject()) {
                                    auto &settings = outbound["settings"];
                                    if (settings.HasMember("servers") && settings["servers"].IsArray() && !settings["servers"].Empty()) {
                                        auto &srv = settings["servers"][0];
                                        if (srv.HasMember("address") && srv["address"].IsString())
                                            server = srv["address"].GetString();
                                        if (srv.HasMember("port")) {
                                            if (srv["port"].IsInt())
                                                server_port = std::to_string(srv["port"].GetInt());
                                            else if (srv["port"].IsString())
                                                server_port = srv["port"].GetString();
                                        }
                                        if (srv.HasMember("password") && srv["password"].IsString())
                                            password = srv["password"].GetString();
                                    }
                                }
                                // Singbox 格式：直接提取字段
                                else {
                                    if (outbound.HasMember("server") && outbound["server"].IsString())
                                        server = outbound["server"].GetString();
                                    if (outbound.HasMember("server_port")) {
                                        if (outbound["server_port"].IsInt())
                                            server_port = std::to_string(outbound["server_port"].GetInt());
                                        else if (outbound["server_port"].IsString())
                                            server_port = outbound["server_port"].GetString();
                                    }
                                    if (outbound.HasMember("password") && outbound["password"].IsString())
                                        password = outbound["password"].GetString();
                                }
                                
                                // Xray 核心格式：从 streamSettings 提取
                                if (outbound.HasMember("streamSettings") && outbound["streamSettings"].IsObject()) {
                                    auto &streamSettings = outbound["streamSettings"];
                                    if (streamSettings.HasMember("network") && streamSettings["network"].IsString())
                                        network = streamSettings["network"].GetString();
                                    
                                    if (network == "ws" && streamSettings.HasMember("wsSettings") && streamSettings["wsSettings"].IsObject()) {
                                        auto &wsSettings = streamSettings["wsSettings"];
                                        if (wsSettings.HasMember("path") && wsSettings["path"].IsString())
                                            path = wsSettings["path"].GetString();
                                        if (wsSettings.HasMember("headers") && wsSettings["headers"].IsObject()) {
                                            if (wsSettings["headers"].HasMember("Host") && wsSettings["headers"]["Host"].IsString())
                                                host = wsSettings["headers"]["Host"].GetString();
                                        }
                                    }
                                    
                                    if (streamSettings.HasMember("tlsSettings") && streamSettings["tlsSettings"].IsObject()) {
                                        auto &tlsSettings = streamSettings["tlsSettings"];
                                        if (tlsSettings.HasMember("serverName") && tlsSettings["serverName"].IsString())
                                            sni = tlsSettings["serverName"].GetString();
                                    }
                                }
                                // Singbox 格式：从 transport 和 tls 提取
                                else {
                                    if (outbound.HasMember("transport") && outbound["transport"].IsObject()) {
                                        auto &transport = outbound["transport"];
                                        if (transport.HasMember("type") && transport["type"].IsString())
                                            network = transport["type"].GetString();
                                        if (transport.HasMember("path") && transport["path"].IsString())
                                            path = transport["path"].GetString();
                                        if (transport.HasMember("headers") && transport["headers"].IsObject()) {
                                            if (transport["headers"].HasMember("Host") && transport["headers"]["Host"].IsString())
                                                host = transport["headers"]["Host"].GetString();
                                        }
                                    }
                                    
                                    if (outbound.HasMember("tls") && outbound["tls"].IsObject()) {
                                        auto &tls = outbound["tls"];
                                        if (tls.HasMember("server_name") && tls["server_name"].IsString())
                                            sni = tls["server_name"].GetString();
                                    }
                                }
                                
                                // 构建 Trojan URI
                                if (!server.empty() && !server_port.empty() && !password.empty()) {
                                    std::string uri = "trojan://" + urlEncode(password) + "@" + server + ":" + server_port;
                                    uri += "?security=tls";
                                    if (!network.empty() && network != "tcp") uri += "&type=" + network;
                                    if (!host.empty()) uri += "&host=" + urlEncode(host);
                                    if (!path.empty()) uri += "&path=" + urlEncode(path);
                                    if (!sni.empty()) uri += "&sni=" + urlEncode(sni);
                                    if (!remarks.empty()) uri += "#" + urlEncode(remarks);
                                    xray_nodes += uri + "\n";
                                }
                            }
                        }
                        
                        // 如果成功解析了 Xray JSON 节点，替换原始内容
                        if (!xray_nodes.empty()) {
                            sub = xray_nodes;
                        }
                    }
                }
            } catch (...) {
                // JSON 解析失败，继续后续处理
            }
        }
        
        // 处理 v2rayN 客户端导出的订阅格式
        // 格式示例：
        // ----------------------------
        // v2rayn://hysteria2/Base64JSONConfig
        // v2rayn://tuic/Base64JSONConfig
        if (sub.find("v2rayn://") != std::string::npos) {
            std::stringstream v2rayn_stream(sub);
            std::string v2rayn_line;
            std::string v2rayn_nodes;
            while (std::getline(v2rayn_stream, v2rayn_line)) {
                if (v2rayn_line.rfind('\r') != std::string::npos)
                    v2rayn_line.pop_back();
                if (!startsWith(v2rayn_line, "v2rayn://"))
                    continue;
                // 去掉 "v2rayn://" 前缀
                std::string node_config = v2rayn_line.substr(9);
                // 找到第一个 '/'，后面是Base64配置
                size_t slash_pos = node_config.find('/');
                if (slash_pos == std::string::npos)
                    continue;
                std::string protocol = node_config.substr(0, slash_pos);
                std::string config_b64 = node_config.substr(slash_pos + 1);
                
                // 解码Base64配置为JSON
                std::string json_str = urlSafeBase64Decode(config_b64);
                
                // 解析JSON并提取节点信息
                try {
                    rapidjson::Document json;
                    json.Parse(json_str.c_str());
                    if (!json.HasParseError() && json.IsObject()) {
                        std::string address, port, password, remarks;
                        
                        // 提取通用字段
                        if (json.HasMember("Address") && json["Address"].IsString())
                            address = json["Address"].GetString();
                        if (json.HasMember("Port") && json["Port"].IsInt())
                            port = std::to_string(json["Port"].GetInt());
                        if (json.HasMember("Password") && json["Password"].IsString())
                            password = json["Password"].GetString();
                        if (json.HasMember("Remarks") && json["Remarks"].IsString())
                            remarks = json["Remarks"].GetString();
                        
                        // 根据协议类型构建节点URI
                        if (protocol == "hysteria2" && !address.empty() && !port.empty()) {
                            std::string uri = "hysteria2://" + password + "@" + address + ":" + port;
                            // 添加可选参数
                            if (json.HasMember("StreamSecurity") && json["StreamSecurity"].IsString()) {
                                std::string security = json["StreamSecurity"].GetString();
                                if (security == "tls") {
                                    uri += "?insecure=1";
                                }
                            }
                            if (!remarks.empty()) {
                                uri += "#" + urlEncode(remarks);
                            }
                            v2rayn_nodes += uri + "\n";
                        }
                        else if (protocol == "tuic" && !address.empty() && !port.empty()) {
                            // TUIC需要uuid和password
                            std::string uuid = password;  // v2rayN中password可能包含uuid
                            std::string tuic_pass = password;
                            if (json.HasMember("UserId") && json["UserId"].IsString())
                                uuid = json["UserId"].GetString();
                            
                            std::string uri = "tuic://" + uuid + ":" + tuic_pass + "@" + address + ":" + port;
                            // 添加参数
                            std::string params = "?";
                            if (json.HasMember("CongestionControl") && json["CongestionControl"].IsString())
                                params += "congestion_control=" + std::string(json["CongestionControl"].GetString()) + "&";
                            if (json.HasMember("Alpn") && json["Alpn"].IsString())
                                params += "alpn=" + std::string(json["Alpn"].GetString()) + "&";
                            if (json.HasMember("AllowInsecure") && json["AllowInsecure"].IsBool() && json["AllowInsecure"].GetBool())
                                params += "allow_insecure=1&";
                            if (json.HasMember("Sni") && json["Sni"].IsString())
                                params += "sni=" + std::string(json["Sni"].GetString()) + "&";
                            
                            if (params.size() > 1)  // 如果有参数
                                uri += params;
                            if (!remarks.empty())
                                uri += "#" + urlEncode(remarks);
                            v2rayn_nodes += uri + "\n";
                        }
                        // 其他协议类型可以继续添加...
                    }
                } catch (...) {
                    // JSON解析失败，忽略
                }
            }
            // 如果成功解析了v2rayN节点，替换原始内容
            if (!v2rayn_nodes.empty()) {
                if (!v2rayn_nodes.empty()) {
                    if (sub.empty() || sub.find("://") == std::string::npos)
                        sub = v2rayn_nodes;
                    else
                        sub += "\n" + v2rayn_nodes;
                }
            }
        }
        strstream << sub;
        char delimiter =
                count(sub.begin(), sub.end(), '\n') < 1 ? count(sub.begin(), sub.end(), '\r') < 1 ? ' ' : '\r' : '\n';
        while (getline(strstream, strLink, delimiter)) {
            Proxy node;
            if (strLink.rfind('\r') != std::string::npos)
                strLink.erase(strLink.size() - 1);
            explode(strLink, node);
            if (strLink.empty() || node.Type == ProxyType::Unknown) {
                continue;
            }
            nodes.emplace_back(std::move(node));
        }
    }
}
