#include <algorithm>
#include <iostream>
#include <numeric>
#include <cmath>
#include <climits>


#include "config/regmatch.h"
#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "handler/settings.h"
#include "parser/config/proxy.h"
#include "script/script_quickjs.h"
#include "utils/bitwise.h"
#include "utils/file_extra.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/rapidjson_extra.h"
#include "utils/regexp.h"
#include "utils/stl_extra.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "nodemanip.h"
#include "ruleconvert.h"

extern string_array ss_ciphers, ssr_ciphers;

const string_array clashr_protocols = {
    "origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a",
    "auth_chain_b"
};
const string_array clashr_obfs = {
    "plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth",
    "tls1.2_ticket_fastauth"
};
const string_array clash_ssr_ciphers = {
    "rc4-md5", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb",
    "aes-192-cfb", "aes-256-cfb", "chacha20-ietf", "xchacha20", "none"
};
bool isNumeric(const std::string &str) {
    for (char c: str) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}


std::string
vmessLinkConstruct(const std::string &remarks, const std::string &add, const std::string &port, const std::string &type,
                   const std::string &id, const std::string &aid, const std::string &net, const std::string &path,
                   const std::string &host, const std::string &tls) {
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    writer.StartObject();
    writer.Key("v");
    writer.String("2");
    writer.Key("ps");
    writer.String(remarks.data());
    writer.Key("add");
    writer.String(add.data());
    writer.Key("port");
    writer.String(port.data());
    writer.Key("type");
    writer.String(type.empty() ? "none" : type.data());
    writer.Key("id");
    writer.String(id.data());
    writer.Key("aid");
    writer.String(aid.data());
    writer.Key("net");
    writer.String(net.empty() ? "tcp" : net.data());
    writer.Key("path");
    writer.String(path.data());
    writer.Key("host");
    writer.String(host.data());
    writer.Key("tls");
    writer.String(tls.data());
    writer.EndObject();
    return sb.GetString();
}

bool matchRange(const std::string &range, int target) {
    string_array vArray = split(range, ",");
    bool match = false;
    std::string range_begin_str, range_end_str;
    int range_begin, range_end;
    static const std::string reg_num = "-?\\d+", reg_range = "(\\d+)-(\\d+)", reg_not = "\\!-?(\\d+)", reg_not_range =
            "\\!(\\d+)-(\\d+)", reg_less = "(\\d+)-", reg_more = "(\\d+)\\+";
    for (std::string &x: vArray) {
        if (regMatch(x, reg_num)) {
            if (to_int(x, INT_MAX) == target)
                match = true;
        } else if (regMatch(x, reg_range)) {
            regGetMatch(x, reg_range, 3, 0, &range_begin_str, &range_end_str);
            range_begin = to_int(range_begin_str, INT_MAX);
            range_end = to_int(range_end_str, INT_MIN);
            if (target >= range_begin && target <= range_end)
                match = true;
        } else if (regMatch(x, reg_not)) {
            match = true;
            if (to_int(regReplace(x, reg_not, "$1"), INT_MAX) == target)
                match = false;
        } else if (regMatch(x, reg_not_range)) {
            match = true;
            regGetMatch(x, reg_range, 3, 0, &range_begin_str, &range_end_str);
            range_begin = to_int(range_begin_str, INT_MAX);
            range_end = to_int(range_end_str, INT_MIN);
            if (target >= range_begin && target <= range_end)
                match = false;
        } else if (regMatch(x, reg_less)) {
            if (to_int(regReplace(x, reg_less, "$1"), INT_MAX) >= target)
                match = true;
        } else if (regMatch(x, reg_more)) {
            if (to_int(regReplace(x, reg_more, "$1"), INT_MIN) <= target)
                match = true;
        }
    }
    return match;
}

bool applyMatcher(const std::string &rule, std::string &real_rule, const Proxy &node) {
    std::string target, ret_real_rule;
    static const std::string groupid_regex = R"(^!!(?:GROUPID|INSERT)=([\d\-+!,]+)(?:!!(.*))?$)", group_regex =
            R"(^!!(?:GROUP)=(.+?)(?:!!(.*))?$)";
    static const std::string type_regex = R"(^!!(?:TYPE)=(.+?)(?:!!(.*))?$)", port_regex =
            R"(^!!(?:PORT)=(.+?)(?:!!(.*))?$)", server_regex = R"(^!!(?:SERVER)=(.+?)(?:!!(.*))?$)";
    static const std::map<ProxyType, const char *> types = {
        {ProxyType::Shadowsocks, "SS"},
        {ProxyType::ShadowsocksR, "SSR"},
        {ProxyType::VMess, "VMESS"},
        {ProxyType::Trojan, "TROJAN"},
        {ProxyType::Snell, "SNELL"},
        {ProxyType::HTTP, "HTTP"},
        {ProxyType::HTTPS, "HTTPS"},
        {ProxyType::SOCKS5, "SOCKS5"},
        {ProxyType::WireGuard, "WIREGUARD"},
        {ProxyType::VLESS, "VLESS"},
        {ProxyType::Hysteria, "HYSTERIA"},
        {ProxyType::Hysteria2, "HYSTERIA2"},
        {ProxyType::TUIC, "TUIC"}
    };
    if (startsWith(rule, "!!GROUP=")) {
        regGetMatch(rule, group_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return regFind(node.Group, target);
    } else if (startsWith(rule, "!!GROUPID=") || startsWith(rule, "!!INSERT=")) {
        int dir = startsWith(rule, "!!INSERT=") ? -1 : 1;
        regGetMatch(rule, groupid_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return matchRange(target, dir * node.GroupId);
    } else if (startsWith(rule, "!!TYPE=")) {
        regGetMatch(rule, type_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        if (node.Type == ProxyType::Unknown)
            return false;
        return regMatch(types.at(node.Type), target);
    } else if (startsWith(rule, "!!PORT=")) {
        regGetMatch(rule, port_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return matchRange(target, node.Port);
    } else if (startsWith(rule, "!!SERVER=")) {
        regGetMatch(rule, server_regex, 3, 0, &target, &ret_real_rule);
        real_rule = ret_real_rule;
        return regFind(node.Hostname, target);
    } else
        real_rule = rule;
    return true;
}

void processRemark(std::string &remark, const string_array &remarks_list, bool proc_comma = true) {
    // Replace every '=' with '-' in the remark string to avoid parse errors from the clients.
    //     Surge is tested to yield an error when handling '=' in the remark string,
    //     not sure if other clients have the same problem.
    std::replace(remark.begin(), remark.end(), '=', '-');

    if (proc_comma) {
        if (remark.find(',') != std::string::npos) {
            remark.insert(0, "\"");
            remark.append("\"");
        }
    }
    std::string tempRemark = remark;
    int cnt = 2;
    while (std::find(remarks_list.cbegin(), remarks_list.cend(), tempRemark) != remarks_list.cend()) {
        tempRemark = remark + " " + std::to_string(cnt);
        cnt++;
    }
    remark = tempRemark;
}

void
groupGenerate(const std::string &rule, std::vector<Proxy> &nodelist, string_array &filtered_nodelist, bool add_direct,
              extra_settings &ext) {
    std::string real_rule;
    if (startsWith(rule, "[]") && add_direct) {
        filtered_nodelist.emplace_back(rule.substr(2));
    }
#ifndef NO_JS_RUNTIME
    else if (startsWith(rule, "script:") && ext.authorized) {
        script_safe_runner(ext.js_runtime, ext.js_context, [&](qjs::Context &ctx) {
            std::string script = fileGet(rule.substr(7), true);
            try {
                ctx.eval(script);
                auto filter = (std::function<std::string(const std::vector<Proxy> &)>) ctx.eval("filter");
                std::string result_list = filter(nodelist);
                filtered_nodelist = split(regTrim(result_list), "\n");
            } catch (qjs::exception) {
                script_print_stack(ctx);
            }
        }, global.scriptCleanContext);
    }
#endif // NO_JS_RUNTIME
    else {
        for (Proxy &x: nodelist) {
            if (applyMatcher(rule, real_rule, x) && (real_rule.empty() || regFind(x.Remark, real_rule)) &&
                std::find(filtered_nodelist.begin(), filtered_nodelist.end(), x.Remark) == filtered_nodelist.end())
                filtered_nodelist.emplace_back(x.Remark);
        }
    }
}

void
proxyToClash(std::vector<Proxy> &nodes, YAML::Node &yamlnode, const ProxyGroupConfigs &extra_proxy_group, bool clashR,
             extra_settings &ext) {
    YAML::Node proxies, original_groups;
    std::vector<Proxy> nodelist;
    string_array remarks_list;
    /// proxies style

    bool proxy_block = false, proxy_compact = false, group_block = false, group_compact = false;
    switch (hash_(ext.clash_proxies_style)) {
        case "block"_hash:
            proxy_block = true;
            break;
        default:
        case "flow"_hash:
            break;
        case "compact"_hash:
            proxy_compact = true;
            break;
    }
    switch (hash_(ext.clash_proxy_groups_style)) {
        case "block"_hash:
            group_block = true;
            break;
        default:
        case "flow"_hash:
            break;
        case "compact"_hash:
            group_compact = true;
            break;
    }

    for (Proxy &x: nodes) {
        YAML::Node singleproxy;

        std::string type = getProxyTypeName(x.Type);
        std::string pluginopts = replaceAllDistinct(x.PluginOption, ";", "&");
        if (ext.append_proxy_type)
            x.Remark = "[" + type + "] " + x.Remark;

        processRemark(x.Remark, remarks_list, false);

        tribool udp = ext.udp;
        tribool xudp = ext.xudp;
        tribool scv = ext.skip_cert_verify;
        tribool tfo = ext.tfo;
        udp.define(x.UDP);
        xudp.define(x.XUDP);
        scv.define(x.AllowInsecure);
        tfo.define(x.TCPFastOpen);
        singleproxy["name"] = x.Remark;
        singleproxy["server"] = x.Hostname;
        singleproxy["port"] = x.Port;

        switch (x.Type) {
            case ProxyType::Shadowsocks:
                //latest clash core removed support for chacha20 encryption
                if (ext.filter_deprecated && x.EncryptMethod == "chacha20")
                    continue;
                singleproxy["type"] = "ss";
                singleproxy["cipher"] = x.EncryptMethod;
                singleproxy["password"] = x.Password;
                if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty())
                    singleproxy["password"].SetTag("str");
                switch (hash_(x.Plugin)) {
                    case "simple-obfs"_hash:
                    case "obfs-local"_hash:
                        singleproxy["plugin"] = "obfs";
                        singleproxy["plugin-opts"]["mode"] = urlDecode(getUrlArg(pluginopts, "obfs"));
                        singleproxy["plugin-opts"]["host"] = urlDecode(getUrlArg(pluginopts, "obfs-host"));
                        break;
                    case "v2ray-plugin"_hash:
                        singleproxy["plugin"] = "v2ray-plugin";
                        singleproxy["plugin-opts"]["mode"] = getUrlArg(pluginopts, "mode");
                        singleproxy["plugin-opts"]["host"] = getUrlArg(pluginopts, "host");
                        singleproxy["plugin-opts"]["path"] = getUrlArg(pluginopts, "path");
                        singleproxy["plugin-opts"]["tls"] = pluginopts.find("tls") != std::string::npos;
                        singleproxy["plugin-opts"]["mux"] = pluginopts.find("mux") != std::string::npos;
                        if (!scv.is_undef())
                            singleproxy["plugin-opts"]["skip-cert-verify"] = scv.get();
                        break;
                }
                break;
            case ProxyType::VMess:
                singleproxy["type"] = "vmess";
                singleproxy["uuid"] = x.UserId;
                singleproxy["alterId"] = x.AlterId;
                singleproxy["cipher"] = x.EncryptMethod;
                singleproxy["tls"] = x.TLSSecure;
                if (!x.AlpnList.empty()) {
                    for (auto &item: x.AlpnList) {
                        singleproxy["alpn"].push_back(item);
                    }
                } else if (!x.Alpn.empty())
                    singleproxy["alpn"].push_back(x.Alpn);
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (!x.ServerName.empty())
                    singleproxy["servername"] = x.ServerName;
                switch (hash_(x.TransferProtocol)) {
                    case "tcp"_hash:
                        break;
                    case "ws"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        if (ext.clash_new_field_name) {
                            singleproxy["ws-opts"]["path"] = x.Path;
                            if (!x.Host.empty())
                                singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                            if (!x.Edge.empty())
                                singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
                        } else {
                            singleproxy["ws-path"] = x.Path;
                            if (!x.Host.empty())
                                singleproxy["ws-headers"]["Host"] = x.Host;
                            if (!x.Edge.empty())
                                singleproxy["ws-headers"]["Edge"] = x.Edge;
                        }
                        break;
                    case "http"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["http-opts"]["method"] = "GET";
                        singleproxy["http-opts"]["path"].push_back(x.Path);
                        if (!x.Host.empty())
                            singleproxy["http-opts"]["headers"]["Host"].push_back(x.Host);
                        if (!x.Edge.empty())
                            singleproxy["http-opts"]["headers"]["Edge"].push_back(x.Edge);
                        break;
                    case "h2"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["h2-opts"]["path"] = x.Path;
                        if (!x.Host.empty())
                            singleproxy["h2-opts"]["host"].push_back(x.Host);
                        break;
                    case "grpc"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["servername"] = x.Host;
                        singleproxy["grpc-opts"]["grpc-service-name"] = x.Path;
                        break;
                    default:
                        continue;
                }
                break;
            case ProxyType::ShadowsocksR:
                //ignoring all nodes with unsupported obfs, protocols and encryption
                if (ext.filter_deprecated) {
                    if (!clashR &&
                        std::find(clash_ssr_ciphers.cbegin(), clash_ssr_ciphers.cend(), x.EncryptMethod) ==
                        clash_ssr_ciphers.cend())
                        continue;
                    if (std::find(clashr_protocols.cbegin(), clashr_protocols.cend(), x.Protocol) ==
                        clashr_protocols.cend())
                        continue;
                    if (std::find(clashr_obfs.cbegin(), clashr_obfs.cend(), x.OBFS) == clashr_obfs.cend())
                        continue;
                }

                singleproxy["type"] = "ssr";
                singleproxy["cipher"] = x.EncryptMethod == "none" ? "dummy" : x.EncryptMethod;
                singleproxy["password"] = x.Password;
                if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty())
                    singleproxy["password"].SetTag("str");
                singleproxy["protocol"] = x.Protocol;
                singleproxy["obfs"] = x.OBFS;
                if (clashR) {
                    singleproxy["protocolparam"] = x.ProtocolParam;
                    singleproxy["obfsparam"] = x.OBFSParam;
                } else {
                    singleproxy["protocol-param"] = x.ProtocolParam;
                    singleproxy["obfs-param"] = x.OBFSParam;
                }
                break;
            case ProxyType::SOCKS5:
                singleproxy["type"] = "socks5";
                if (!x.Username.empty())
                    singleproxy["username"] = x.Username;
                if (!x.Password.empty()) {
                    singleproxy["password"] = x.Password;
                    if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit))
                        singleproxy["password"].SetTag("str");
                }
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                break;
            case ProxyType::HTTP:
            case ProxyType::HTTPS:
                singleproxy["type"] = "http";
                if (!x.Username.empty())
                    singleproxy["username"] = x.Username;
                if (!x.Password.empty()) {
                    singleproxy["password"] = x.Password;
                    if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit))
                        singleproxy["password"].SetTag("str");
                }
                singleproxy["tls"] = x.TLSSecure;
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                break;
            case ProxyType::Trojan:
                singleproxy["type"] = "trojan";
                singleproxy["password"] = x.Password;
                if (!x.ServerName.empty())
                    singleproxy["sni"] = x.ServerName;
                else if (!x.Host.empty()) {
                    singleproxy["sni"] = x.Host;
                }
                if (!x.AlpnList.empty()) {
                    for (auto &item: x.AlpnList) {
                        singleproxy["alpn"].push_back(item);
                    }
                } else if (!x.Alpn.empty())
                    singleproxy["alpn"].push_back(x.Alpn);
                if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty()) {
                    singleproxy["password"].SetTag("str");
                }
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                switch (hash_(x.TransferProtocol)) {
                    case "tcp"_hash:
                        break;
                    case "grpc"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        if (!x.Path.empty())
                            singleproxy["grpc-opts"]["grpc-service-name"] = x.Path;
                        break;
                    case "ws"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["ws-opts"]["path"] = x.Path;
                        if (!x.Host.empty())
                            singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                        break;
                }
                break;
            case ProxyType::Snell:
                if (x.SnellVersion >= 4)
                    continue;
                singleproxy["type"] = "snell";
                singleproxy["psk"] = x.Password;
                if (x.SnellVersion != 0)
                    singleproxy["version"] = x.SnellVersion;
                if (!x.OBFS.empty()) {
                    singleproxy["obfs-opts"]["mode"] = x.OBFS;
                    if (!x.Host.empty())
                        singleproxy["obfs-opts"]["host"] = x.Host;
                }
                if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) && !x.Password.empty())
                    singleproxy["password"].SetTag("str");
                break;
            case ProxyType::WireGuard:
                singleproxy["type"] = "wireguard";
                singleproxy["public-key"] = x.PublicKey;
                singleproxy["private-key"] = x.PrivateKey;
                singleproxy["ip"] = x.SelfIP;
                if (!x.SelfIPv6.empty())
                    singleproxy["ipv6"] = x.SelfIPv6;
                if (!x.PreSharedKey.empty())
                    singleproxy["preshared-key"] = x.PreSharedKey;
                if (!x.DnsServers.empty())
                    singleproxy["dns"] = x.DnsServers;
                if (x.Mtu > 0)
                    singleproxy["mtu"] = x.Mtu;
                break;
            case ProxyType::Hysteria:
                singleproxy["type"] = "hysteria";
                singleproxy["auth_str"] = x.Auth;
                singleproxy["auth-str"] = x.Auth;
                singleproxy["up"] = x.UpMbps;
                singleproxy["down"] = x.DownMbps;
                if (!x.Ports.empty()) {
                    singleproxy["ports"] = x.Ports;
                }
                if (!tfo.is_undef()) {
                    singleproxy["fast-open"] = tfo.get();
                }
                if (!x.FakeType.empty())
                    singleproxy["protocol"] = x.FakeType;
                if (!x.ServerName.empty())
                    singleproxy["sni"] = x.ServerName;
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (x.Insecure == "1")
                    singleproxy["skip-cert-verify"] = true;
                if (!x.Alpn.empty())
                    singleproxy["alpn"].push_back(x.Alpn);
                if (!x.OBFSParam.empty())
                    singleproxy["obfs"] = x.OBFSParam;
                break;
            case ProxyType::Hysteria2:
                singleproxy["type"] = "hysteria2";
                singleproxy["password"] = x.Password;
                singleproxy["auth"] = x.Password;
                if (!x.PublicKey.empty()) {
                    singleproxy["ca-str"] = x.PublicKey;
                }
                if (!x.ServerName.empty()) {
                    singleproxy["sni"] = x.ServerName;
                }
                if (!x.UpMbps.empty())
                    singleproxy["up"] = x.UpMbps;
                if (!x.DownMbps.empty())
                    singleproxy["down"] = x.DownMbps;
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (!x.Alpn.empty())
                    singleproxy["alpn"].push_back(x.Alpn);
                if (!x.OBFSParam.empty())
                    singleproxy["obfs"] = x.OBFSParam;
                if (!x.OBFSPassword.empty())
                    singleproxy["obfs-password"] = x.OBFSPassword;
                if (!x.Ports.empty())
                    singleproxy["ports"] = x.Ports;
                break;
            case ProxyType::TUIC:
                singleproxy["type"] = "tuic";
                if (!x.Password.empty()) {
                    singleproxy["password"] = x.Password;
                }
                if (!x.UserId.empty()) {
                    singleproxy["uuid"] = x.UserId;
                }
                if (!x.token.empty()) {
                    singleproxy["token"] = x.token;
                }
                if (!x.ServerName.empty()) {
                    singleproxy["sni"] = x.ServerName;
                }
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (!x.Alpn.empty())
                    singleproxy["alpn"].push_back(x.Alpn);
                singleproxy["disable-sni"] = x.DisableSni.get();
                singleproxy["reduce-rtt"] = x.ReduceRtt.get();
                singleproxy["request-timeout"] = x.RequestTimeout;
                if (!x.UdpRelayMode.empty()) {
                    if (x.UdpRelayMode == "native" || x.UdpRelayMode == "quic") {
                        singleproxy["udp-relay-mode"] = x.UdpRelayMode;
                    }
                }
                if (!x.CongestionControl.empty()) {
                    singleproxy["congestion-controller"] = x.CongestionControl;
                }
                break;
            case ProxyType::AnyTLS:
                singleproxy["type"] = "anytls";
                if (!x.Password.empty()) {
                    singleproxy["password"] = x.Password;
                }
                if (!x.Fingerprint.empty()) {
                    singleproxy["client-fingerprint"] = x.Fingerprint;
                }
                if (!udp.is_undef()) {
                    singleproxy["udp"] = udp.get();
                }
                if (!x.ServerName.empty()) {
                    singleproxy["sni"] = x.SNI;
                }
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (!x.AlpnList.empty()) {
                    for (auto &item: x.AlpnList) {
                        singleproxy["alpn"].push_back(item);
                    }
                }
                break;
            case ProxyType::Mieru:
                singleproxy["type"] = "mieru";
                if (!x.Password.empty()) {
                    singleproxy["password"] = x.Password;
                }
                if (!x.Username.empty()) {
                    singleproxy["username"] = x.Username;
                }
                if (!x.Multiplexing.empty()) {
                    singleproxy["multiplexing"] = x.Multiplexing;
                }
                if (!x.TransferProtocol.empty()) {
                    singleproxy["transport"] = x.TransferProtocol;
                }
                if (!x.Ports.empty()) {
                    singleproxy["port-range"] = x.Ports;
                    singleproxy.remove("port");
                }
                break;
            case ProxyType::VLESS:
                singleproxy["type"] = "vless";
                singleproxy["uuid"] = x.UserId;
                singleproxy["tls"] = x.TLSSecure;
                if (!x.AlpnList.empty()) {
                    for (auto &item: x.AlpnList) {
                        singleproxy["alpn"].push_back(item);
                    }
                }
                if (!tfo.is_undef())
                    singleproxy["tfo"] = tfo.get();
                if (xudp && udp)
                    singleproxy["xudp"] = true;
                if (!x.PacketEncoding.empty()) {
                    singleproxy["packet-encoding"] = x.PacketEncoding;
                }
                if (!x.Flow.empty())
                    singleproxy["flow"] = x.Flow;
                if (!scv.is_undef())
                    singleproxy["skip-cert-verify"] = scv.get();
                if (!x.PublicKey.empty()) {
                    singleproxy["reality-opts"]["public-key"] = x.PublicKey;
                }
                if (!x.ServerName.empty())
                    singleproxy["servername"] = x.ServerName;
                if (!x.ShortId.empty()) {
                    singleproxy["reality-opts"]["short-id"] = "" + x.ShortId;
                }
                if (!x.PublicKey.empty() || x.Flow == "xtls-rprx-vision") {
                    singleproxy["client-fingerprint"] = "chrome";
                }
                if (!x.Fingerprint.empty()) {
                    singleproxy["client-fingerprint"] = x.Fingerprint;
                }
                switch (hash_(x.TransferProtocol)) {
                    case "tcp"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        break;
                    case "ws"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        if (ext.clash_new_field_name) {
                            singleproxy["ws-opts"]["path"] = x.Path;
                            if (!x.Host.empty())
                                singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
                            if (!x.Edge.empty())
                                singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
                            if (!x.V2rayHttpUpgrade.is_undef()) {
                                singleproxy["ws-opts"]["v2ray-http-upgrade"] = x.V2rayHttpUpgrade.get();
                            }
                        } else {
                            singleproxy["ws-path"] = x.Path;
                            if (!x.Host.empty())
                                singleproxy["ws-headers"]["Host"] = x.Host;
                            if (!x.Edge.empty())
                                singleproxy["ws-headers"]["Edge"] = x.Edge;
                        }
                        break;
                    case "http"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["http-opts"]["method"] = "GET";
                        singleproxy["http-opts"]["path"].push_back(x.Path);
                        if (!x.Host.empty())
                            singleproxy["http-opts"]["headers"]["Host"].push_back(x.Host);
                        if (!x.Edge.empty())
                            singleproxy["http-opts"]["headers"]["Edge"].push_back(x.Edge);
                        break;
                    case "h2"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["h2-opts"]["path"] = x.Path;
                        if (!x.Host.empty())
                            singleproxy["h2-opts"]["host"].push_back(x.Host);
                        break;
                    case "grpc"_hash:
                        singleproxy["network"] = x.TransferProtocol;
                        singleproxy["grpc-opts"]["grpc-mode"] = x.GRPCMode;
                        singleproxy["grpc-opts"]["grpc-service-name"] = x.GRPCServiceName;
                        break;
                    default:
                        continue;
                }
                break;
            default:
                continue;
        }

        // UDP is not supported yet in clash using snell
        // sees in https://dreamacro.github.io/clash/configuration/outbound.html#snell
        if (udp && x.Type != ProxyType::Snell && x.Type != ProxyType::TUIC)
            singleproxy["udp"] = true;
        if (proxy_block)
            singleproxy.SetStyle(YAML::EmitterStyle::Block);
        else
            singleproxy.SetStyle(YAML::EmitterStyle::Flow);
        proxies.push_back(singleproxy);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if (proxy_compact)
        proxies.SetStyle(YAML::EmitterStyle::Flow);

    if (ext.nodelist) {
        YAML::Node provider;
        provider["proxies"] = proxies;
        yamlnode.reset(provider);
        return;
    }

    if (ext.clash_new_field_name)
        yamlnode["proxies"] = proxies;
    else
        yamlnode["Proxy"] = proxies;


    for (const ProxyGroupConfig &x: extra_proxy_group) {
        YAML::Node singlegroup;
        string_array filtered_nodelist;

        singlegroup["name"] = x.Name;
        if (x.Type == ProxyGroupType::Smart)
            singlegroup["type"] = "url-test";
        else
            singlegroup["type"] = x.TypeStr();

        switch (x.Type) {
            case ProxyGroupType::Select:
            case ProxyGroupType::Relay:
                break;
            case ProxyGroupType::LoadBalance:
                singlegroup["strategy"] = x.StrategyStr();
                [[fallthrough]];
            case ProxyGroupType::Smart:
                [[fallthrough]];
            case ProxyGroupType::URLTest:
                if (!x.Lazy.is_undef())
                    singlegroup["lazy"] = x.Lazy.get();
                [[fallthrough]];
            case ProxyGroupType::Fallback:
                singlegroup["url"] = x.Url;
                if (x.Interval > 0)
                    singlegroup["interval"] = x.Interval;
                if (x.Tolerance > 0)
                    singlegroup["tolerance"] = x.Tolerance;
                break;
            default:
                continue;
        }
        if (!x.DisableUdp.is_undef())
            singlegroup["disable-udp"] = x.DisableUdp.get();

        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (!x.UsingProvider.empty())
            singlegroup["use"] = x.UsingProvider;
        else {
            if (filtered_nodelist.empty())
                filtered_nodelist.emplace_back("DIRECT");
        }
        if (!filtered_nodelist.empty())
            singlegroup["proxies"] = filtered_nodelist;
        if (group_block)
            singlegroup.SetStyle(YAML::EmitterStyle::Block);
        else
            singlegroup.SetStyle(YAML::EmitterStyle::Flow);

        bool replace_flag = false;
        for (auto &&original_group: original_groups) {
            if (original_group["name"].as<std::string>() == x.Name) {
                original_group.reset(singlegroup);
                replace_flag = true;
                break;
            }
        }
        if (!replace_flag)
            original_groups.push_back(singlegroup);
    }
    if (group_compact)
        original_groups.SetStyle(YAML::EmitterStyle::Flow);

    if (ext.clash_new_field_name)
        yamlnode["proxy-groups"] = original_groups;
    else
        yamlnode["Proxy Group"] = original_groups;
}


void formatterShortId(std::string &input) {
    std::string target = "short-id:";
    size_t startPos = input.find(target);

    while (startPos != std::string::npos) {
        // 查找对应实例的结束位置
        size_t endPos = input.find("}", startPos);

        if (endPos != std::string::npos) {
            // 提取原始id
            std::string originalId = input.substr(startPos + target.length(), endPos - startPos - target.length());

            // 去除原始id中的空格
            originalId.erase(remove_if(originalId.begin(), originalId.end(), ::isspace), originalId.end());

            // 添加引号
            std::string modifiedId = " \"" + originalId + "\" ";

            // 替换原始id为修改后的id
            input.replace(startPos + target.length(), endPos - startPos - target.length(), modifiedId);
        }

        // 继续查找下一个实例
        startPos = input.find(target, startPos + 1);
    }
}

std::string proxyToClash(std::vector<Proxy> &nodes, const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         bool clashR, extra_settings &ext) {
    YAML::Node yamlnode;

    try {
        yamlnode = YAML::Load(base_conf);
    } catch (std::exception &e) {
        writeLog(0, std::string("Clash base loader failed with error: ") + e.what(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToClash(nodes, yamlnode, extra_proxy_group, clashR, ext);

    if (ext.nodelist)
        return YAML::Dump(yamlnode);

    /*
    if(ext.enable_rule_generator)
        rulesetToClash(yamlnode, ruleset_content_array, ext.overwrite_original_rules, ext.clash_new_field_name);

    return YAML::Dump(yamlnode);
    */
    if (!ext.enable_rule_generator)
        return YAML::Dump(yamlnode);

    if (!ext.managed_config_prefix.empty() || ext.clash_script) {
        if (yamlnode["mode"].IsDefined()) {
            if (ext.clash_new_field_name)
                yamlnode["mode"] = ext.clash_script ? "script" : "rule";
            else
                yamlnode["mode"] = ext.clash_script ? "Script" : "Rule";
        }

        renderClashScript(yamlnode, ruleset_content_array, ext.managed_config_prefix, ext.clash_script,
                          ext.overwrite_original_rules, ext.clash_classical_ruleset);
        return YAML::Dump(yamlnode);
    }

    std::string output_content = rulesetToClashStr(yamlnode, ruleset_content_array, ext.overwrite_original_rules,
                                                   ext.clash_new_field_name);
    std::string yamlnode_str = YAML::Dump(yamlnode);
    output_content.insert(0, yamlnode_str);
    //rulesetToClash(yamlnode, ruleset_content_array, ext.overwrite_original_rules, ext.clash_new_field_name);
    //std::string output_content = YAML::Dump(yamlnode);
    replaceAll(output_content, "!<str> ", "");
    formatterShortId(output_content);
    return output_content;
}

void replaceAll(std::string &input, const std::string &search, const std::string &replace) {
    size_t pos = 0;
    while ((pos = input.find(search, pos)) != std::string::npos) {
        input.replace(pos, search.length(), replace);
        pos += replace.length();
    }
}

// peer = (public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, allowed-ips = "0.0.0.0/0, ::/0", endpoint = engage.cloudflareclient.com:2408, client-id = 139/184/125),(public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, endpoint = engage.cloudflareclient.com:2408)
std::string generatePeer(Proxy &node, bool client_id_as_reserved = false) {
    std::string result;
    result += "public-key = " + node.PublicKey;
    result += ", endpoint = " + node.Hostname + ":" + std::to_string(node.Port);
    if (!node.AllowedIPs.empty())
        result += ", allowed-ips = \"" + node.AllowedIPs + "\"";
    if (!node.ClientId.empty()) {
        if (client_id_as_reserved)
            result += ", reserved = [" + node.ClientId + "]";
        else
            result += ", client-id = " + node.ClientId;
    }
    return result;
}

std::string proxyToSurge(std::vector<Proxy> &nodes, const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         int surge_ver, extra_settings &ext) {
    INIReader ini;
    std::string output_nodelist;
    std::vector<Proxy> nodelist;
    unsigned short local_port = 1080;
    string_array remarks_list;

    ini.store_any_line = true;
    // filter out sections that requires direct-save
    ini.add_direct_save_section("General");
    ini.add_direct_save_section("Replica");
    ini.add_direct_save_section("Rule");
    ini.add_direct_save_section("MITM");
    ini.add_direct_save_section("Script");
    ini.add_direct_save_section("Host");
    ini.add_direct_save_section("URL Rewrite");
    ini.add_direct_save_section("Header Rewrite");
    if (ini.parse(base_conf) != 0 && !ext.nodelist) {
        writeLog(0, "Surge base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    ini.set_current_section("Proxy");
    ini.erase_section();
    ini.set("{NONAME}", "DIRECT = direct");

    for (Proxy &x: nodes) {
        if (ext.append_proxy_type) {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &sni = x.ServerName, &username = x.Username, &password = x.Password, &method
                = x.EncryptMethod, &id = x.UserId, &transproto = x.TransferProtocol, &host = x.Host, &edge = x.Edge, &
                path = x.Path, &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.
                OBFSParam, &plugin = x.Plugin, &pluginopts = x.PluginOption, &underlying_proxy = x.UnderlyingProxy;
        std::string port = std::to_string(x.Port);;
        bool &tlssecure = x.TLSSecure;

        tribool udp = ext.udp, tfo = ext.tfo, scv = ext.skip_cert_verify, tls13 = ext.tls13;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);
        tls13.define(x.TLS13);

        std::string proxy, section, real_section;
        string_array args, headers;
        std::string search = " Mbps";

        switch (x.Type) {
            case ProxyType::Shadowsocks:
                if (surge_ver >= 3 || surge_ver == -3) {
                    proxy = "ss, " + hostname + ", " + port + ", encrypt-method=" + method + ", password=" +
                            password;
                } else {
                    proxy = "custom, " + hostname + ", " + port + ", " + method + ", " + password +
                            ", https://github.com/pobizhe/SSEncrypt/raw/master/SSEncrypt.module";
                }
                if (!plugin.empty()) {
                    switch (hash_(plugin)) {
                        case "simple-obfs"_hash:
                        case "obfs-local"_hash:
                            if (!pluginopts.empty())
                                proxy += "," + replaceAllDistinct(pluginopts, ";", ",");
                            break;
                        default:
                            continue;
                    }
                }
                break;
            case ProxyType::VMess:
                if (surge_ver < 4 && surge_ver != -3)
                    continue;
                proxy = "vmess, " + hostname + ", " + port + ", username=" + id + ", tls=" +
                        (tlssecure ? "true" : "false") + ", vmess-aead=" + (x.AlterId == 0 ? "true" : "false");
                if (tlssecure && !tls13.is_undef())
                    proxy += ", tls13=" + std::string(tls13 ? "true" : "false");
                switch (hash_(transproto)) {
                    case "tcp"_hash:
                        break;
                    case "ws"_hash:
                        if (host.empty())
                            proxy += ", ws=true, ws-path=" + path + ", sni=" + hostname;
                        else
                            proxy += ", ws=true, ws-path=" + path + ", sni=" + host;
                        if (!host.empty())
                            headers.push_back("Host:" + host);
                        if (!edge.empty())
                            headers.push_back("Edge:" + edge);
                        if (!headers.empty())
                            proxy += ", ws-headers=" + join(headers, "|");
                        break;
                    default:
                        continue;
                }
                if (!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                break;
            case ProxyType::ShadowsocksR:
                if (ext.surge_ssr_path.empty() || surge_ver < 2)
                    continue;
                proxy = "external, exec=\"" + ext.surge_ssr_path + "\", args=\"";
                args = {
                    "-l", std::to_string(local_port), "-s", hostname, "-p", port, "-m", method, "-k", password,
                    "-o", obfs, "-O", protocol
                };
                if (!obfsparam.empty()) {
                    args.emplace_back("-g");
                    args.emplace_back(std::move(obfsparam));
                }
                if (!protoparam.empty()) {
                    args.emplace_back("-G");
                    args.emplace_back(std::move(protoparam));
                }
                proxy += join(args, "\", args=\"");
                proxy += "\", local-port=" + std::to_string(local_port);
                if (isIPv4(hostname) || isIPv6(hostname))
                    proxy += ", addresses=" + hostname;
                else if (global.surgeResolveHostname)
                    proxy += ", addresses=" + hostnameToIPAddr(hostname);
                local_port++;
                break;
            case ProxyType::SOCKS5:
                proxy = "socks5, " + hostname + ", " + port;
                if (!username.empty())
                    proxy += ", username=" + username;
                if (!password.empty()) {
                    proxy += ", password=" + password;
                }
                if (!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                break;
            case ProxyType::HTTPS:
                if (surge_ver == -3) {
                    proxy = "https, " + hostname + ", " + port + ", " + username + ", " + password;
                    if (!scv.is_undef())
                        proxy += ", skip-cert-verify=" + scv.get_str();
                    break;
                }
                [[fallthrough]];
            case ProxyType::HTTP:
                proxy = "http, " + hostname + ", " + port;
                if (!username.empty())
                    proxy += ", username=" + username;
                if (!password.empty())
                    proxy += ", password=" + password;
                proxy += std::string(", tls=") + (x.TLSSecure ? "true" : "false");
                if (!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                break;
            case ProxyType::Trojan:
                if (surge_ver < 4 && surge_ver != -3)
                    continue;
                proxy = "trojan, " + hostname + ", " + port + ", password=" + password;
                if (x.SnellVersion != 0)
                    proxy += ", version=" + std::to_string(x.SnellVersion);
                if (!sni.empty()) {
                    proxy += ", sni=" + sni;
                } else if (!host.empty()) {
                    proxy += ", sni=" + host;
                }
                if (!scv.is_undef())
                    proxy += ", skip-cert-verify=" + scv.get_str();
                break;
            case ProxyType::Snell:
                proxy = "snell, " + hostname + ", " + port + ", psk=" + password;
                if (!obfs.empty()) {
                    proxy += ", obfs=" + obfs;
                    if (!host.empty())
                        proxy += ", obfs-host=" + host;
                }
                if (x.SnellVersion != 0)
                    proxy += ", version=" + std::to_string(x.SnellVersion);
                break;
            case ProxyType::Hysteria2:
                if (surge_ver < 4)
                    continue;
                proxy = "hysteria2, " + hostname + ", " + port + ", password=" + password;
                if (!x.DownMbps.empty()) {
                    if (!isNumeric(x.DownMbps)) {
                        size_t pos = x.DownMbps.find(search);
                        if (pos != std::string::npos) {
                            x.DownMbps.replace(pos, search.length(), "");
                        }
                    }
                    proxy += ", download-bandwidth=" +x.DownMbps;
                }

                if (!scv.is_undef())
                    proxy += ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
                if (!x.Fingerprint.empty())
                    proxy += ",server-cert-fingerprint-sha256=" + x.Fingerprint;
                if (!x.ServerName.empty())
                    proxy += ",sni=" + x.ServerName;
                if (!x.Ports.empty())
                    proxy += ",port-hopping=" + x.Ports;
                break;
            case ProxyType::WireGuard:
                if (surge_ver < 4 && surge_ver != -3)
                    continue;
                section = randomStr(5);
                real_section = "WireGuard " + section;
                proxy = "wireguard, section-name=" + section;
                if (!x.TestUrl.empty())
                    proxy += ", test-url=" + x.TestUrl;
                ini.set(real_section, "private-key", x.PrivateKey);
                ini.set(real_section, "self-ip", x.SelfIP);
                if (!x.SelfIPv6.empty())
                    ini.set(real_section, "self-ip-v6", x.SelfIPv6);
                if (!x.PreSharedKey.empty())
                    ini.set(real_section, "preshared-key", x.PreSharedKey);
                if (!x.DnsServers.empty())
                    ini.set(real_section, "dns-server", join(x.DnsServers, ","));
                if (x.Mtu > 0)
                    ini.set(real_section, "mtu", std::to_string(x.Mtu));
                if (x.KeepAlive > 0)
                    ini.set(real_section, "keepalive", std::to_string(x.KeepAlive));
                ini.set(real_section, "peer", "(" + generatePeer(x) + ")");
                break;
            default:
                continue;
        }

        if (!tfo.is_undef())
            proxy += ", tfo=" + tfo.get_str();
        if (!udp.is_undef())
            proxy += ", udp-relay=" + udp.get_str();
        if (underlying_proxy != "")
            proxy += ", underlying-proxy=" + underlying_proxy;
        if (ext.nodelist)
            output_nodelist += x.Remark + " = " + proxy + "\n";
        else {
            ini.set("{NONAME}", x.Remark + " = " + proxy);
            nodelist.emplace_back(x);
        }
        remarks_list.emplace_back(x.Remark);
    }

    if (ext.nodelist)
        return output_nodelist;

    ini.set_current_section("Proxy Group");
    ini.erase_section();
    for (const ProxyGroupConfig &x: extra_proxy_group) {
        string_array filtered_nodelist;
        std::string group;

        switch (x.Type) {
            case ProxyGroupType::Select:
            case ProxyGroupType::Smart:
            case ProxyGroupType::URLTest:
            case ProxyGroupType::Fallback:
                break;
            case ProxyGroupType::LoadBalance:
                if (surge_ver < 1 && surge_ver != -3)
                    continue;
                break;
            case ProxyGroupType::SSID:
                group = x.TypeStr() + ",default=" + x.Proxies[0] + ",";
                group += join(x.Proxies.begin() + 1, x.Proxies.end(), ",");
                ini.set("{NONAME}", x.Name + " = " + group); //insert order
                continue;
            default:
                continue;
        }

        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        if (filtered_nodelist.size() == 1) {
            group = toLower(filtered_nodelist[0]);
            switch (hash_(group)) {
                case "direct"_hash:
                case "reject"_hash:
                case "reject-tinygif"_hash:
                    ini.set("Proxy", "{NONAME}", x.Name + " = " + group);
                    continue;
            }
        }

        group = x.TypeStr() + ",";
        group += join(filtered_nodelist, ",");
        if (x.Type == ProxyGroupType::URLTest || x.Type == ProxyGroupType::Fallback ||
            x.Type == ProxyGroupType::LoadBalance) {
            group += ",url=" + x.Url + ",interval=" + std::to_string(x.Interval);
            if (x.Tolerance > 0)
                group += ",tolerance=" + std::to_string(x.Tolerance);
            if (x.Timeout > 0)
                group += ",timeout=" + std::to_string(x.Timeout);
            if (!x.Persistent.is_undef())
                group += ",persistent=" + x.Persistent.get_str();
            if (!x.EvaluateBeforeUse.is_undef())
                group += ",evaluate-before-use=" + x.EvaluateBeforeUse.get_str();
        }

        ini.set("{NONAME}", x.Name + " = " + group); //insert order
    }

    if (ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, surge_ver, ext.overwrite_original_rules,
                       ext.managed_config_prefix);

    return ini.to_string();
}

std::string proxyToSingle(std::vector<Proxy> &nodes, int types, extra_settings &ext) {
    /// types: SS=1 SSR=2 VMess=4 Trojan=8,hysteria2=16,vless=32,tuic=64,HTTP=128,HTTPS=256,SOCKS5=512,Snell=1024,Hysteria=2048,WireGuard=4096,AnyTLS=8192,Mieru=16384
    std::string proxyStr, allLinks;
    bool ss = (types & 1);
    bool ssr = (types & 2);
    bool vmess = (types & 4);
    bool trojan = (types & 8);
    bool hysteria2 = (types & 16);
    bool vless = (types & 32);
    bool tuic = (types & 64);
    bool http = (types & 128);
    bool https = (types & 256);
    bool socks5 = (types & 512);
    bool snell = (types & 1024);
    bool hysteria = (types & 2048);
    bool wireguard = (types & 4096);
    bool anytls = (types & 8192);
    bool mieru = (types & 16384);

    // Hack: 如果开启了 VLESS，通常也应该开启 VMess，以防 types 参数传递错误
    if (vless) vmess = true;

    for (Proxy &x: nodes) {
        proxyStr = "";
        std::string remark = x.Remark;
        std::string &hostname = x.Hostname, &sni = x.ServerName, &password = x.Password, &method = x.EncryptMethod, &
                        plugin = x.Plugin, &pluginopts = x.PluginOption, &protocol = x.Protocol, &protoparam = x.
                        ProtocolParam, &flow = x.Flow, &pbk = x.PublicKey, &sid = x.ShortId, &fp = x.Fingerprint,
                &packet_encoding = x.PacketEncoding, &fake_type = x.FakeType, &mode = x.GRPCMode,
                &obfs = x.OBFS, &obfsparam = x.OBFSParam, &obfsPassword = x.OBFSPassword, &id = x.UserId, &transproto =
                        x.TransferProtocol, &host = x.
                        Host, &tls = x.TLSStr, &path = x.Path, &faketype = x.FakeType, &ports = x.Ports;
        bool &tlssecure = x.TLSSecure;
        std::vector<string> alpns = x.AlpnList;
        std::string port = std::to_string(x.Port);
        std::string aid = std::to_string(x.AlterId);
        switch (x.Type) {
            case ProxyType::Shadowsocks:
                if (ss) {
                    proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port;
                    if (!plugin.empty() && !pluginopts.empty()) {
                        proxyStr += "/?plugin=" + urlEncode(plugin + ";" + pluginopts);
                    }
                    proxyStr += "#" + urlEncode(remark);
                } else if (ssr) {
                    if (std::find(ssr_ciphers.begin(), ssr_ciphers.end(), method) != ssr_ciphers.end() &&
                        plugin.empty())
                        proxyStr = "ssr://" + urlSafeBase64Encode(
                                       hostname + ":" + port + ":origin:" + method + ":plain:" +
                                       urlSafeBase64Encode(password)
                                       + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(
                                           remark));
                } else
                    continue;
                break;
            case ProxyType::ShadowsocksR:
                if (ssr) {
                    proxyStr = "ssr://" + urlSafeBase64Encode(
                                   hostname + ":" + port + ":" + protocol + ":" + method + ":" + obfs + ":" +
                                   urlSafeBase64Encode(password)
                                   + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(
                                       remark)
                                   + "&obfsparam=" + urlSafeBase64Encode(obfsparam) + "&protoparam=" +
                                   urlSafeBase64Encode(protoparam));
                } else if (ss) {
                    if (std::find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() &&
                        protocol == "origin" && obfs == "plain")
                        proxyStr =
                                "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" +
                                port +
                                "#" + urlEncode(remark);
                } else
                    continue;
                break;
            case ProxyType::VMess:
                if (!vmess)
                    continue;
                proxyStr = "vmess://" + base64Encode(
                               vmessLinkConstruct(remark, hostname, port, faketype, id, aid, transproto, path, host,
                                                  tlssecure ? "tls" : ""));
                break;
            case ProxyType::Hysteria2:
                if (!hysteria2)
                    continue;
                proxyStr = "hysteria2://" + password + "@" + hostname + ":" + port + (ports.empty() ? "" : "," + ports)
                           + "?insecure=" +
                           (x.AllowInsecure.get() ? "1" : "0");
                if (!obfsparam.empty()) {
                    proxyStr += "&obfs=" + obfsparam;
                    if (!obfsPassword.empty()) {
                        proxyStr += "&obfs-password=" + obfsparam;
                    }
                }
                if (!sni.empty()) {
                    proxyStr += "&sni=" + sni;
                }
                proxyStr += "#" + urlEncode(remark);
                break;
            case ProxyType::VLESS:
                if (!vless)
                    continue;
            // tls = getUrlArg(addition, "security");
            // net = getUrlArg(addition, "type");
            // flow = getUrlArg(addition, "flow");
            // pbk = getUrlArg(addition, "pbk");
            // sid = getUrlArg(addition, "sid");
            // fp = getUrlArg(addition, "fp");
            // std::string packet_encoding = getUrlArg(addition, "packet-encoding");
            // std::string alpn = getUrlArg(addition, "alpn");
                proxyStr = "vless://" + (id.empty()
                               ? "00000000-0000-0000-0000-000000000000"
                               : id) + "@" + hostname + ":" + port+"?";
                if (!tls.empty()) {
                    if (!pbk.empty()) {
                        proxyStr += "&security=reality";
                    }else {
                        proxyStr += "&security=" + tls;
                    }
                }

                if (!flow.empty()) {
                    proxyStr += "&flow=" + flow;
                }
                if (!pbk.empty()) {
                    proxyStr += "&pbk=" + pbk;
                }
                if (!sid.empty()) {
                    proxyStr += "&sid=" + sid;
                }
                if (!fp.empty()) {
                    proxyStr += "&fp=" + fp;
                }
                if (!packet_encoding.empty()) {
                    proxyStr += "&packet-encoding=" + packet_encoding;
                }
                if (!alpns.empty()) {
                    proxyStr += "&alpn=" + alpns[0];
                }
                if (!sni.empty()) {
                    proxyStr += "&sni=" + sni;
                }
                if (!transproto.empty()) {
                    proxyStr += "&type=" + transproto;
                    switch (hash_(transproto)) {
                        case "tcp"_hash:
                        case "ws"_hash:
                        case "h2"_hash:
                            proxyStr += "&headerType=" + fake_type;
                            if (!host.empty()) {
                                proxyStr += "&host=" + host;
                            }
                            proxyStr += "&path=" + urlEncode(path.empty() ? "/" : path);
                            break;
                        case "grpc"_hash:
                            proxyStr += "&serviceName=" + path;
                            proxyStr += "&mode=" + mode;
                            break;
                        case "quic"_hash:
                            proxyStr += "&headerType=" + fake_type;
                            proxyStr += "&quicSecurity=" + (host.empty() ? sni : host);
                            proxyStr += "&key=" + path;
                            break;
                        default:
                            break;
                    }
                }
                proxyStr += "#" + urlEncode(remark);
                break;
            case ProxyType::Trojan:
                if (!trojan)
                    continue;
                proxyStr = "trojan://" + password + "@" + hostname + ":" + port + "?allowInsecure=" +
                           (x.AllowInsecure.get() ? "1" : "0");
                if (!sni.empty()) {
                    proxyStr += "&sni=" + sni;
                } else if (!host.empty()) {
                    proxyStr += "&sni=" + host;
                }
                if (transproto == "ws") {
                    proxyStr += "&ws=1";
                    if (!path.empty())
                        proxyStr += "&wspath=" + urlEncode(path);
                }
                proxyStr += "#" + urlEncode(remark);
                break;
            case ProxyType::TUIC:
                if (!tuic)
                    continue;
                proxyStr = "tuic://" + x.UserId + ":" + x.Password + "@" + hostname + ":" + port + "?";
                if (!x.CongestionControl.empty())
                    proxyStr += "&congestion_control=" + x.CongestionControl;
                if (!x.UdpRelayMode.empty())
                    proxyStr += "&udp_relay_mode=" + x.UdpRelayMode;
                if (!x.Alpn.empty())
                    proxyStr += "&alpn=" + x.Alpn;
                if (!x.ServerName.empty())
                    proxyStr += "&sni=" + x.ServerName;
                if (x.AllowInsecure.get())
                    proxyStr += "&allow_insecure=1";
                if (x.DisableSni.get())
                    proxyStr += "&disable_sni=1";
                if (x.ReduceRtt.get())
                    proxyStr += "&reduce_rtt=1";

                proxyStr += "#" + urlEncode(remark);
                break;
            case ProxyType::HTTP:
                if (!http)
                    continue;
                proxyStr = "http://";
                if (!x.Username.empty() && !x.Password.empty()) {
                    proxyStr += urlSafeBase64Encode(x.Username) + ":" + urlSafeBase64Encode(x.Password) + "@";
                }
                proxyStr += hostname + ":" + port;
                proxyStr += "#" + urlEncode(remark);
                break;
            case ProxyType::HTTPS:
                if (!https)
                    continue;
                proxyStr = "https://";
                if (!x.Username.empty() && !x.Password.empty()) {
                    proxyStr += urlSafeBase64Encode(x.Username) + ":" + urlSafeBase64Encode(x.Password) + "@";
                }
                proxyStr += hostname + ":" + port;
                proxyStr += "#" + urlEncode(remark);
                break;
            case ProxyType::SOCKS5:
                if (!socks5)
                    continue;
                proxyStr = "socks5://";
                if (!x.Username.empty() && !x.Password.empty()) {
                    proxyStr += urlSafeBase64Encode(x.Username) + ":" + urlSafeBase64Encode(x.Password) + "@";
                }
                proxyStr += hostname + ":" + port;
                proxyStr += "#" + urlEncode(remark);
                break;
            case ProxyType::Snell:
                if (!snell)
                    continue;
                proxyStr = "snell://" + password + "@" + hostname + ":" + port + "?";
                if (x.SnellVersion > 0) {
                    proxyStr += "version=" + std::to_string(x.SnellVersion);
                }
                proxyStr += "#" + urlEncode(remark);
                break;
            case ProxyType::Hysteria:
                if (!hysteria)
                    continue;
                proxyStr = "hysteria://" + hostname + ":" + port + "?";
                if (!x.Auth.empty()) {
                    proxyStr += "auth=" + x.Auth + "&";
                }
                if (!x.UpMbps.empty()) {
                    proxyStr += "upmbps=" + x.UpMbps + "&";
                }
                if (!x.DownMbps.empty()) {
                    proxyStr += "downmbps=" + x.DownMbps + "&";
                }
                if (!x.Ports.empty()) {
                    proxyStr += "port=" + x.Ports + "&";
                }
                if (x.Insecure == "1") {
                    proxyStr += "insecure=1&";
                }
                if (!x.FakeType.empty()) {
                    proxyStr += "protocol=" + x.FakeType + "&";
                }
                if (!x.ServerName.empty()) {
                    proxyStr += "sni=" + x.ServerName + "&";
                }
                // 移除末尾的&
                if (proxyStr.back() == '&') {
                    proxyStr.pop_back();
                }
                proxyStr += "#" + urlEncode(remark);
                break;
            case ProxyType::WireGuard:
                if (!wireguard)
                    continue;
                // WireGuard协议不支持URL格式，跳过
                continue;
            case ProxyType::AnyTLS:
                if (!anytls)
                    continue;
                // AnyTLS协议不支持直接的URL格式，跳过
                continue;
            case ProxyType::Mieru:
                if (!mieru)
                    continue;
                // Mieru协议不支持直接的URL格式，跳过
                continue;
            default:
                continue;
        }
        allLinks += proxyStr + "\n";
    }

    if (ext.nodelist)
        return allLinks;
    return base64Encode(allLinks);
}

std::string proxyToSSSub(std::string base_conf, std::vector<Proxy> &nodes, extra_settings &ext) {
    using namespace rapidjson_ext;
    rapidjson::Document base;

    auto &alloc = base.GetAllocator();

    base_conf = trimWhitespace(base_conf);
    if (base_conf.empty())
        base_conf = "{}";
    rapidjson::ParseResult result = base.Parse(base_conf.data());
    if (!result)
        writeLog(0, std::string("SIP008 base loader failed with error: ") +
                    rapidjson::GetParseError_En(result.Code()) +
                    " (" + std::to_string(result.Offset()) + ")", LOG_LEVEL_ERROR);

    rapidjson::Value proxies(rapidjson::kArrayType);
    for (Proxy &x: nodes) {
        std::string &remark = x.Remark;
        std::string &hostname = x.Hostname;
        std::string &password = x.Password;
        std::string &method = x.EncryptMethod;
        std::string &plugin = x.Plugin;
        std::string &pluginopts = x.PluginOption;
        std::string &protocol = x.Protocol;
        std::string &obfs = x.OBFS;

        switch (x.Type) {
            case ProxyType::Shadowsocks:
                if (plugin == "simple-obfs")
                    plugin = "obfs-local";
                break;
            case ProxyType::ShadowsocksR:
                if (std::find(ss_ciphers.begin(), ss_ciphers.end(), method) == ss_ciphers.end() ||
                    protocol != "origin" || obfs != "plain")
                    continue;
                break;
            default:
                continue;
        }
        rapidjson::Value proxy(rapidjson::kObjectType);
        proxy.CopyFrom(base, alloc)
                | AddMemberOrReplace("remarks", rapidjson::Value(remark.c_str(), remark.size()), alloc)
                | AddMemberOrReplace("server", rapidjson::Value(hostname.c_str(), hostname.size()), alloc)
                | AddMemberOrReplace("server_port", rapidjson::Value(x.Port), alloc)
                | AddMemberOrReplace("method", rapidjson::Value(method.c_str(), method.size()), alloc)
                | AddMemberOrReplace("password", rapidjson::Value(password.c_str(), password.size()), alloc)
                | AddMemberOrReplace("plugin", rapidjson::Value(plugin.c_str(), plugin.size()), alloc)
                | AddMemberOrReplace("plugin_opts", rapidjson::Value(pluginopts.c_str(), pluginopts.size()), alloc);
        proxies.PushBack(proxy, alloc);
    }
    return proxies | SerializeObject();
}

std::string
proxyToQuan(std::vector<Proxy> &nodes, const std::string &base_conf,
            std::vector<RulesetContent> &ruleset_content_array,
            const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    INIReader ini;
    ini.store_any_line = true;
    if (!ext.nodelist && ini.parse(base_conf) != 0) {
        writeLog(0, "Quantumult base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToQuan(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    if (ext.nodelist) {
        string_array allnodes;
        std::string allLinks;
        ini.get_all("SERVER", "{NONAME}", allnodes);
        if (!allnodes.empty())
            allLinks = join(allnodes, "\n");
        return base64Encode(allLinks);
    }
    return ini.to_string();
}

void proxyToQuan(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array,
                 const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    std::string proxyStr;
    std::vector<Proxy> nodelist;
    string_array remarks_list;

    ini.set_current_section("SERVER");
    ini.erase_section();
    for (Proxy &x: nodes) {
        if (ext.append_proxy_type) {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &method = x.EncryptMethod, &password = x.Password, &id = x.UserId, &
                        transproto = x.TransferProtocol, &host = x.Host, &path = x.Path, &edge = x.Edge, &protocol = x.
                        Protocol,
                &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &plugin = x.Plugin, &pluginopts
                        = x.
                        PluginOption, &username = x.Username;
        std::string port = std::to_string(x.Port);
        bool &tlssecure = x.TLSSecure;
        tribool scv;

        switch (x.Type) {
            case ProxyType::VMess:
                scv = ext.skip_cert_verify;
                scv.define(x.AllowInsecure);

                if (method == "auto")
                    method = "chacha20-ietf-poly1305";
                proxyStr =
                        x.Remark + " = vmess, " + hostname + ", " + port + ", " + method + ", \"" + id +
                        "\", group=" +
                        x.Group;
                if (tlssecure) {
                    proxyStr += ", over-tls=true, tls-host=" + host;
                    if (!scv.is_undef())
                        proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
                }
                if (transproto == "ws") {
                    proxyStr += ", obfs=ws, obfs-path=\"" + path + "\", obfs-header=\"Host: " + host;
                    if (!edge.empty())
                        proxyStr += "[Rr][Nn]Edge: " + edge;
                    proxyStr += "\"";
                }

                if (ext.nodelist)
                    proxyStr = "vmess://" + urlSafeBase64Encode(proxyStr);
                break;
            case ProxyType::ShadowsocksR:
                if (ext.nodelist) {
                    proxyStr = "ssr://" + urlSafeBase64Encode(
                                   hostname + ":" + port + ":" + protocol + ":" + method + ":" + obfs + ":" +
                                   urlSafeBase64Encode(password)
                                   + "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(
                                       x.Remark)
                                   + "&obfsparam=" + urlSafeBase64Encode(obfsparam) + "&protoparam=" +
                                   urlSafeBase64Encode(protoparam));
                } else {
                    proxyStr = x.Remark + " = shadowsocksr, " + hostname + ", " + port + ", " + method + ", \"" +
                               password + "\", group=" + x.Group + ", protocol=" + protocol + ", obfs=" + obfs;
                    if (!protoparam.empty())
                        proxyStr += ", protocol_param=" + protoparam;
                    if (!obfsparam.empty())
                        proxyStr += ", obfs_param=" + obfsparam;
                }
                break;
            case ProxyType::Shadowsocks:
                if (ext.nodelist) {
                    proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port;
                    if (!plugin.empty() && !pluginopts.empty()) {
                        proxyStr += "/?plugin=" + urlEncode(plugin + ";" + pluginopts);
                    }
                    proxyStr += "&group=" + urlSafeBase64Encode(x.Group) + "#" + urlEncode(x.Remark);
                } else {
                    proxyStr =
                            x.Remark + " = shadowsocks, " + hostname + ", " + port + ", " + method + ", \"" +
                            password +
                            "\", group=" + x.Group;
                    if (plugin == "obfs-local" && !pluginopts.empty()) {
                        proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
                    }
                }
                break;
            case ProxyType::HTTP:
            case ProxyType::HTTPS:
                proxyStr =
                        x.Remark + " = http, upstream-proxy-address=" + hostname + ", upstream-proxy-port=" + port +
                        ", group=" + x.Group;
                if (!username.empty() && !password.empty())
                    proxyStr += ", upstream-proxy-auth=true, upstream-proxy-username=" + username +
                            ", upstream-proxy-password=" + password;
                else
                    proxyStr += ", upstream-proxy-auth=false";

                if (tlssecure) {
                    proxyStr += ", over-tls=true";
                    if (!host.empty())
                        proxyStr += ", tls-host=" + host;
                    if (!scv.is_undef())
                        proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
                }

                if (ext.nodelist)
                    proxyStr = "http://" + urlSafeBase64Encode(proxyStr);
                break;
            case ProxyType::SOCKS5:
                proxyStr = "socks, upstream-proxy-address=" + hostname + ", upstream-proxy-port=" +
                           port +
                           ", group=" + x.Group;
                if (!username.empty() && !password.empty())
                    proxyStr += ", upstream-proxy-auth=true, upstream-proxy-username=" + username +
                            ", upstream-proxy-password=" + password;
                else
                    proxyStr += ", upstream-proxy-auth=false";

                if (tlssecure) {
                    proxyStr += ", over-tls=true";
                    if (!host.empty())
                        proxyStr += ", tls-host=" + host;
                    if (!scv.is_undef())
                        proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
                }

                if (ext.nodelist)
                    proxyStr = "socks://" + urlSafeBase64Encode(proxyStr);
                break;
            default:
                continue;
        }

        ini.set("{NONAME}", proxyStr);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if (ext.nodelist)
        return;

    ini.set_current_section("POLICY");
    ini.erase_section();

    for (const ProxyGroupConfig &x: extra_proxy_group) {
        string_array filtered_nodelist;
        std::string type;
        std::string singlegroup;
        std::string name, proxies;

        switch (x.Type) {
            case ProxyGroupType::Select:
            case ProxyGroupType::Smart:
            case ProxyGroupType::URLTest:
            case ProxyGroupType::Fallback:
                break;
            case ProxyGroupType::LoadBalance:
                break;
            case ProxyGroupType::SSID: {
                singlegroup = x.TypeStr() + ",default=" + x.Proxies[0] + ",";
                std::string content, celluar, celluar_matcher = R"(^(.*?),?celluar\s?=\s?(.*?)(,.*)$)", rem_a, rem_b;
                for (auto iter = x.Proxies.begin() + 1; iter != x.Proxies.end(); iter++) {
                    if (regGetMatch(*iter, celluar_matcher, 4, 0, &rem_a, &celluar, &rem_b)) {
                        content += *iter + "\n";
                        continue;
                    }
                    content += rem_a + rem_b + "\n";
                }
                if (!celluar.empty())
                    singlegroup += ", celluar = " + celluar;
                singlegroup += "\n" + replaceAllDistinct(trimOf(content, ','), ",", "\n");
                ini.set("{NONAME}", base64Encode(singlegroup)); //insert order
            }
                continue;
            default:
                continue;
        }

        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("direct");

        if (filtered_nodelist.size() < 2) // force groups with 1 node to be static
            type = "static";

        proxies = join(filtered_nodelist, "\n");

        singlegroup = x.Name + " : " + type;
        if (type == "static")
            singlegroup += ", " + filtered_nodelist[0];
        singlegroup += "\n" + proxies + "\n";
        ini.set("{NONAME}", base64Encode(singlegroup));
    }

    if (ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, -2, ext.overwrite_original_rules, ext.managed_config_prefix);
}

std::string proxyToQuanX(std::vector<Proxy> &nodes, const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         extra_settings &ext) {
    INIReader ini;
    ini.store_any_line = true;
    ini.add_direct_save_section("general");
    ini.add_direct_save_section("dns");
    ini.add_direct_save_section("rewrite_remote");
    ini.add_direct_save_section("rewrite_local");
    ini.add_direct_save_section("task_local");
    ini.add_direct_save_section("mitm");
    ini.add_direct_save_section("server_remote");
    if (!ext.nodelist && ini.parse(base_conf) != 0) {
        writeLog(0, "QuantumultX base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToQuanX(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    if (ext.nodelist) {
        string_array allnodes;
        std::string allLinks;
        ini.get_all("server_local", "{NONAME}", allnodes);
        if (!allnodes.empty())
            allLinks = join(allnodes, "\n");
        return allLinks;
    }
    return ini.to_string();
}

void proxyToQuanX(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array,
                  const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    std::string proxyStr;
    tribool udp, tfo, scv, tls13;
    std::vector<Proxy> nodelist;
    string_array remarks_list;

    ini.set_current_section("server_local");
    ini.erase_section();
    for (Proxy &x: nodes) {
        if (ext.append_proxy_type) {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &method = x.EncryptMethod, &id = x.UserId, &transproto = x.TransferProtocol,
                &host = x.Host, &path = x.Path, &password = x.Password, &plugin = x.Plugin, &pluginopts = x.PluginOption
                , &protocol = x.Protocol, &protoparam = x.ProtocolParam, &obfs = x.OBFS, &obfsparam = x.OBFSParam, &
                        username = x.Username;
        std::string port = std::to_string(x.Port);
        bool &tlssecure = x.TLSSecure;

        udp = ext.udp;
        tfo = ext.tfo;
        scv = ext.skip_cert_verify;
        tls13 = ext.tls13;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);
        tls13.define(x.TLS13);

        switch (x.Type) {
            case ProxyType::VMess:
                if (method == "auto")
                    method = "chacha20-ietf-poly1305";
                proxyStr = "vmess = " + hostname + ":" + port + ", method=" + method + ", password=" + id;
                if (x.AlterId != 0)
                    proxyStr += ", aead=false";
                if (tlssecure && !tls13.is_undef())
                    proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                if (transproto == "ws") {
                    if (tlssecure)
                        proxyStr += ", obfs=wss";
                    else
                        proxyStr += ", obfs=ws";
                    proxyStr += ", obfs-host=" + host + ", obfs-uri=" + path;
                } else if (tlssecure)
                    proxyStr += ", obfs=over-tls, obfs-host=" + host;
                break;
            case ProxyType::VLESS:
                if (method == "auto")
                    method = "none";
                else
                    method = "none";
                proxyStr = "vless = " + hostname + ":" + port + ", method=" + method + ", password=" + id;
                if (x.AlterId != 0)
                    proxyStr += ", aead=false";
                if (tlssecure && !tls13.is_undef())
                    proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                if (transproto == "ws") {
                    if (tlssecure)
                        proxyStr += ", obfs=wss";
                    else
                        proxyStr += ", obfs=ws";
                    proxyStr += ", obfs-host=" + host + ", obfs-uri=" + path;
                } else if (tlssecure)
                    proxyStr += ", obfs=over-tls, obfs-host=" + host;
                break;
            case ProxyType::Shadowsocks:
                proxyStr =
                        "shadowsocks = " + hostname + ":" + port + ", method=" + method + ", password=" + password;
                if (!plugin.empty()) {
                    switch (hash_(plugin)) {
                        case "simple-obfs"_hash:
                        case "obfs-local"_hash:
                            if (!pluginopts.empty())
                                proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
                            break;
                        case "v2ray-plugin"_hash: {
                            pluginopts = replaceAllDistinct(pluginopts, ";", "&");
                            std::string obfs = getUrlArg(pluginopts, "mode") == "websocket" ? "wss" : "none";
                            host = getUrlArg(pluginopts, "host");
                            path = getUrlArg(pluginopts, "path");
                            if (getUrlArg(pluginopts, "tls") == "true")
                                obfs = "wss";
                            proxyStr += ", obfs=" + obfs;
                            if (!host.empty())
                                proxyStr += ", obfs-host=" + host;
                            if (!path.empty())
                                proxyStr += ", obfs-uri=" + path;
                            break;
                        }
                        default:
                            continue;
                    }
                }

                break;
            case ProxyType::ShadowsocksR:
                proxyStr =
                        "shadowsocks = " + hostname + ":" + port + ", method=" + method + ", password=" + password +
                        ", ssr-protocol=" + protocol;
                if (!protoparam.empty())
                    proxyStr += ", ssr-protocol-param=" + protoparam;
                proxyStr += ", obfs=" + obfs;
                if (!obfsparam.empty())
                    proxyStr += ", obfs-host=" + obfsparam;
                break;
            case ProxyType::HTTP:
            case ProxyType::HTTPS:
                proxyStr =
                        "http = " + hostname + ":" + port + ", username=" + (username.empty() ? "none" : username) +
                        ", password=" + (password.empty() ? "none" : password);
                if (tlssecure) {
                    proxyStr += ", over-tls=true";
                    if (!tls13.is_undef())
                        proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                } else {
                    proxyStr += ", over-tls=false";
                }
                break;
            case ProxyType::Trojan:
                proxyStr = "trojan = " + hostname + ":" + port + ", password=" + password;
                if (tlssecure) {
                    proxyStr += ", over-tls=true, tls-host=" + host;
                    if (!tls13.is_undef())
                        proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                } else {
                    proxyStr += ", over-tls=false";
                }
                break;
            case ProxyType::SOCKS5:
                proxyStr = "socks5 = " + hostname + ":" + port;
                if (!username.empty() && !password.empty()) {
                    proxyStr += ", username=" + username + ", password=" + password;
                    if (tlssecure) {
                        proxyStr += ", over-tls=true, tls-host=" + host;
                        if (!tls13.is_undef())
                            proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
                    } else {
                        proxyStr += ", over-tls=false";
                    }
                }
                break;
            default:
                continue;
        }
        if (!tfo.is_undef())
            proxyStr += ", fast-open=" + tfo.get_str();
        if (!udp.is_undef())
            proxyStr += ", udp-relay=" + udp.get_str();
        if (tlssecure && !scv.is_undef() &&
            (x.Type != ProxyType::Shadowsocks && x.Type != ProxyType::ShadowsocksR && x.Type != ProxyType::VLESS))
            proxyStr += ", tls-verification=" + scv.reverse().get_str();
        proxyStr += ", tag=" + x.Remark;

        ini.set("{NONAME}", proxyStr);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }


    if (ext.nodelist) {
        return;
    }

    ini.set_current_section("policy");
    ini.erase_section();

    for (const ProxyGroupConfig &x: extra_proxy_group) {
        string_array filtered_nodelist;
        std::string type;
        std::string group;

        switch (x.Type) {
            case ProxyGroupType::Select:
                type = "static";
                break;
            case ProxyGroupType::URLTest:
            case ProxyGroupType::Fallback:
                type = "available";
                break;
            case ProxyGroupType::LoadBalance:
                type = "round-robin";
                break;
            case ProxyGroupType::SSID:
                type = "ssid";
                break;
            default:
                continue;
        }

        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        if (type == "ssid") {
            group = type + "=" + x.Name + ", default=" + x.Proxies[0];
            for (size_t i = 1; i < x.Proxies.size(); ++i) {
                group += ", " + x.Proxies[i];
            }
        } else {
            group = type + "=" + x.Name + ", " + join(filtered_nodelist, ", ");
            if (type == "available" || type == "round-robin") {
                if (!x.Url.empty()) group += ", url=" + x.Url;
                if (x.Interval > 0) group += ", interval=" + std::to_string(x.Interval);
                if (type == "available" && x.Tolerance > 0) group += ", tolerance=" + std::to_string(x.Tolerance);
            }
        }

        if (!x.Icon.empty()) {
            group += ", img-url=" + x.Icon;
        }

        ini.set("{NONAME}", group);
    }

    if (ext.enable_rule_generator)
        rulesetToSurge(ini, ruleset_content_array, -1, ext.overwrite_original_rules, ext.managed_config_prefix);
}

std::string formatSingBoxInterval(int seconds) {
    if (seconds % 3600 == 0)
        return std::to_string(seconds / 3600) + "h";
    if (seconds % 60 == 0)
        return std::to_string(seconds / 60) + "m";
    return std::to_string(seconds) + "s";
}

void proxyToSingBox(std::vector<Proxy> &nodes, rapidjson::Document &json, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    using namespace rapidjson_ext;
    auto &allocator = json.GetAllocator();
    rapidjson::Value outbounds(rapidjson::kArrayType);
    if (json.HasMember("outbounds")) {
        outbounds = json["outbounds"];
    }

    std::vector<Proxy> nodelist = nodes;

    for (const ProxyGroupConfig &x: extra_proxy_group) {
        string_array filtered_nodelist;
        std::string type;
        switch (x.Type) {
            case ProxyGroupType::Select: {
                type = "selector";
                break;
            }
            case ProxyGroupType::URLTest:
            case ProxyGroupType::Fallback:
            case ProxyGroupType::LoadBalance: {
                type = "urltest";
                break;
            }
            default:
                continue;
        }
        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        rapidjson::Value group(rapidjson::kObjectType);

        group.AddMember("type", rapidjson::Value(type.c_str(), allocator), allocator);
        group.AddMember("tag", rapidjson::Value(x.Name.c_str(), allocator), allocator);

        rapidjson::Value group_outbounds(rapidjson::kArrayType);
        for (const std::string &y: filtered_nodelist) {
            group_outbounds.PushBack(rapidjson::Value(y.c_str(), allocator), allocator);
        }
        group.AddMember("outbounds", group_outbounds, allocator);

        if (x.Type == ProxyGroupType::URLTest) {
            group.AddMember("url", rapidjson::Value(x.Url.c_str(), allocator), allocator);
            group.AddMember("interval", rapidjson::Value(formatSingBoxInterval(x.Interval).c_str(), allocator),
                            allocator);
            if (x.Tolerance > 0)
                group.AddMember("tolerance", x.Tolerance, allocator);
        }
        outbounds.PushBack(group, allocator);
    }

    if (global.singBoxAddClashModes) {
        auto global_group = rapidjson::Value(rapidjson::kObjectType);
        global_group.AddMember("type", "selector", allocator);
        global_group.AddMember("tag", "GLOBAL", allocator);
        global_group.AddMember("outbounds", rapidjson::Value(rapidjson::kArrayType), allocator);
        global_group["outbounds"].PushBack("DIRECT", allocator);
        for (const auto &x: nodes) {
             global_group["outbounds"].PushBack(rapidjson::Value(x.Remark.c_str(), allocator), allocator);
        }
        outbounds.PushBack(global_group, allocator);
    }

    json | AddMemberOrReplace("outbounds", outbounds, allocator);
}

std::string proxyToSingBox(std::vector<Proxy> &nodes, const std::string &base_conf,
                           std::vector<RulesetContent> &ruleset_content_array,
                           const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    using namespace rapidjson_ext;
    rapidjson::Document json;

    if (!ext.nodelist) {
        json.Parse(base_conf.data());
        if (json.HasParseError()) {
            writeLog(0, "sing-box base loader failed with error: " +
                        std::string(rapidjson::GetParseError_En(json.GetParseError())), LOG_LEVEL_ERROR);
            return "";
        }
    } else {
        json.SetObject();
    }

    proxyToSingBox(nodes, json, ruleset_content_array, extra_proxy_group, ext);

    if (ext.nodelist || !ext.enable_rule_generator)
        return json | SerializeObject();

    rulesetToSingBox(json, ruleset_content_array, ext.overwrite_original_rules);

    return json | SerializeObject();
}

void proxyToLoon(std::vector<Proxy> &nodes, INIReader &ini, std::vector<RulesetContent> &ruleset_content_array, const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
    std::string proxyStr;
    std::vector<Proxy> nodelist;
    string_array remarks_list;

    ini.set_current_section("Proxy");
    ini.erase_section();

    for (Proxy &x: nodes) {
        if (ext.append_proxy_type) {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &username = x.Username, &password = x.Password, &method = x.EncryptMethod;
        std::string port = std::to_string(x.Port);

        switch (x.Type) {
            case ProxyType::Shadowsocks:
                proxyStr = "Shadowsocks, " + hostname + ", " + port + ", " + method + ", \"" + password + "\"";
                if (!x.Plugin.empty()) {
                     if (x.Plugin == "obfs-local" || x.Plugin == "simple-obfs") {
                         proxyStr += "," + replaceAllDistinct(x.PluginOption, ";", ",");
                     }
                }
                break;
            case ProxyType::VMess:
                proxyStr = "vmess, " + hostname + ", " + port + ", " + method + ", \"" + x.UserId + "\"";
                if (x.TransferProtocol == "ws") {
                    proxyStr += ", transport=ws";
                    if (!x.Path.empty()) proxyStr += ", path=" + x.Path;
                    if (!x.Host.empty()) proxyStr += ", host=" + x.Host;
                }
                if (x.TLSSecure) {
                    proxyStr += ", over-tls=true";
                }
                break;
            case ProxyType::HTTP:
            case ProxyType::HTTPS:
                proxyStr = "http, " + hostname + ", " + port + ", " + username + ", " + password;
                if (x.TLSSecure) proxyStr += ", over-tls=true";
                break;
            case ProxyType::Trojan:
                proxyStr = "trojan, " + hostname + ", " + port + ", " + password;
                if (x.TLSSecure) proxyStr += ", over-tls=true";
                break;
            default:
                continue;
        }
        proxyStr += ", tag=" + x.Remark;
        ini.set("{NONAME}", proxyStr);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if (ext.nodelist) return;

    ini.set_current_section("Proxy Group");
    ini.erase_section();

    for (const ProxyGroupConfig &x: extra_proxy_group) {
        string_array filtered_nodelist;
        std::string group;

        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        group = x.TypeStr() + ", " + x.Name + ", " + join(filtered_nodelist, ", ");
        if (x.Type == ProxyGroupType::URLTest || x.Type == ProxyGroupType::Fallback || x.Type == ProxyGroupType::LoadBalance) {
            group += ", url=" + x.Url + ", interval=" + std::to_string(x.Interval);
        }
        ini.set("{NONAME}", group);
    }

    if (ext.enable_rule_generator)
        rulesetToLoon(ini, ruleset_content_array, ext.overwrite_original_rules);
}

std::string proxyToLoon(std::vector<Proxy> &nodes, const std::string &base_conf,
                        std::vector<RulesetContent> &ruleset_content_array,
                        const ProxyGroupConfigs &extra_proxy_group,
                        extra_settings &ext) {
    INIReader ini;
    ini.store_any_line = true;

    if (!ext.nodelist && ini.parse(base_conf) != 0) {
        writeLog(0, "Loon base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToLoon(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    if (ext.nodelist) {
        string_array allnodes;
        std::string allLinks;
        ini.get_all("Proxy", "{NONAME}", allnodes);
        if (!allnodes.empty())
            allLinks = join(allnodes, "\n");
        return allLinks;
    }

    return ini.to_string();
}

std::string proxyToMellow(std::vector<Proxy> &nodes, const std::string &base_conf,
                          std::vector<RulesetContent> &ruleset_content_array,
                          const ProxyGroupConfigs &extra_proxy_group,
                          extra_settings &ext) {
    INIReader ini;
    ini.store_any_line = true;
    ini.add_direct_save_section("common");
    ini.add_direct_save_section("update-task");
    ini.add_direct_save_section("task");
    ini.add_direct_save_section("filter");
    ini.add_direct_save_section("rewrite");
    ini.add_direct_save_section("mitm");
    ini.add_direct_save_section("script");

    if (ini.parse(base_conf) != 0 && !ext.nodelist) {
        writeLog(0, "Mellow base loader failed with error: " + ini.get_last_error(), LOG_LEVEL_ERROR);
        return "";
    }

    proxyToMellow(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

    if (ext.nodelist)
        return "";

    if (ext.enable_rule_generator)
        rulesetToMellow(ini, ruleset_content_array, ext.overwrite_original_rules);

    return ini.to_string();
}

void proxyToMellow(std::vector<Proxy> &nodes, INIReader &ini,
                   std::vector<RulesetContent> &ruleset_content_array,
                   const ProxyGroupConfigs &extra_proxy_group,
                   extra_settings &ext) {
    // 这里是 Mellow 格式的代理配置实现
    std::string proxyStr;
    tribool udp, tfo, scv;
    std::vector<Proxy> nodelist;
    string_array remarks_list;

    ini.set_current_section("Proxy");
    ini.erase_section();
    for (Proxy &x: nodes) {
        if (ext.append_proxy_type) {
            std::string type = getProxyTypeName(x.Type);
            x.Remark = "[" + type + "] " + x.Remark;
        }

        processRemark(x.Remark, remarks_list);

        std::string &hostname = x.Hostname, &method = x.EncryptMethod, &id = x.UserId, &transproto = x.TransferProtocol,
                &host = x.Host, &path = x.Path, &password = x.Password, &plugin = x.Plugin, &pluginopts = x.PluginOption
                , &username = x.Username;
        std::string port = std::to_string(x.Port);
        bool &tlssecure = x.TLSSecure;

        udp = ext.udp;
        tfo = ext.tfo;
        scv = ext.skip_cert_verify;
        udp.define(x.UDP);
        tfo.define(x.TCPFastOpen);
        scv.define(x.AllowInsecure);

        switch (x.Type) {
            case ProxyType::VMess:
                if (method == "auto")
                    method = "chacha20-ietf-poly1305";
                proxyStr = "vmess, " + hostname + ", " + port + ", " + id + ", " + method;
                if (x.AlterId != 0)
                    proxyStr += ", aead=false";
                if (tlssecure)
                    proxyStr += ", tls=" + std::string(tlssecure ? "true" : "false");
                if (!host.empty())
                    proxyStr += ", host=" + host;
                if (!path.empty())
                    proxyStr += ", path=" + path;
                if (!transproto.empty())
                    proxyStr += ", net=" + transproto;
                break;
            case ProxyType::Shadowsocks:
                proxyStr = "shadowsocks, " + hostname + ", " + port + ", " + method + ", " + password;
                if (!plugin.empty()) {
                    switch (hash_(plugin)) {
                        case "simple-obfs"_hash:
                        case "obfs-local"_hash:
                            if (!pluginopts.empty()) {
                                string_array opts = split(pluginopts, ";");
                                for (const std::string &y : opts) {
                                    string_array arg = split(y, "=");
                                    if (arg.size() == 2) {
                                        if (arg[0] == "obfs")
                                            proxyStr += ", obfs=" + arg[1];
                                        else if (arg[0] == "obfs-host")
                                            proxyStr += ", host=" + arg[1];
                                        else if (arg[0] == "path")
                                            proxyStr += ", path=" + arg[1];
                                    }
                                }
                            }
                            break;
                        default:
                            continue;
                    }
                }
                break;
            case ProxyType::HTTP:
            case ProxyType::HTTPS:
                proxyStr = "http, " + hostname + ", " + port;
                if (!username.empty())
                    proxyStr += ", " + username + ", " + password;
                if (tlssecure)
                    proxyStr += ", over-tls=true, tls-name=" + host;
                break;
            case ProxyType::Trojan:
                proxyStr = "trojan, " + hostname + ", " + port + ", " + password;
                if (tlssecure)
                    proxyStr += ", over-tls=true, tls-name=" + host;
                break;
            case ProxyType::SOCKS5:
                proxyStr = "socks5, " + hostname + ", " + port;
                if (!username.empty() && !password.empty())
                    proxyStr += ", " + username + ", " + password;
                break;
            case ProxyType::TUIC:
                proxyStr = "tuic, " + hostname + ", " + port + ", " + x.Password + ", " + x.UserId;
                if (!x.CongestionControl.empty())
                    proxyStr += ", congestion-control=" + x.CongestionControl;
                if (!x.ServerName.empty())
                    proxyStr += ", sni=" + x.ServerName;
                if (!scv.is_undef())
                    proxyStr += ", skip-cert-verify=" + scv.get_str();
                if (!x.Alpn.empty())
                    proxyStr += ", alpn=" + x.Alpn;
                break;
            default:
                continue;
        }
        if (!tfo.is_undef())
            proxyStr += ", tfo=" + tfo.get_str();
        if (!udp.is_undef())
            proxyStr += ", udp=" + udp.get_str();
        if (tlssecure && !scv.is_undef())
            proxyStr += ", skip-cert-verify=" + scv.get_str();
        proxyStr += ", alias=" + x.Remark;

        ini.set("{NONAME}", proxyStr);
        remarks_list.emplace_back(x.Remark);
        nodelist.emplace_back(x);
    }

    if (ext.nodelist)
        return;

    string_multimap original_groups;
    ini.set_current_section("Rule");
    ini.get_items(original_groups);
    ini.erase_section();

    for (const ProxyGroupConfig &x: extra_proxy_group) {
        string_array filtered_nodelist;
        std::string type;
        std::string group, group_extra;

        switch (x.Type) {
            case ProxyGroupType::Select:
            case ProxyGroupType::URLTest:
            case ProxyGroupType::Fallback:
                break;
            default:
                continue;
        }

        for (const auto &y: x.Proxies)
            groupGenerate(y, nodelist, filtered_nodelist, true, ext);

        if (filtered_nodelist.empty())
            filtered_nodelist.emplace_back("DIRECT");

        group = x.TypeStr() + ", ";
        group += join(filtered_nodelist, ", ");
        if (x.Type != ProxyGroupType::Select) {
            group += ", url=" + x.Url + ", interval=" + std::to_string(x.Interval);
        }

        ini.set("{NONAME}", x.Name + " = " + group); //insert order
    }
}

std::string proxyToSSD(std::vector<Proxy> &nodes, std::string &group, std::string &userinfo, extra_settings &ext) {
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("airport");
    writer.String(group.c_str());
    writer.Key("port");
    writer.Int(1);
    writer.Key("encryption");
    writer.String("aes-128-gcm");
    writer.Key("password");
    writer.String("password");

    writer.Key("servers");
    writer.StartArray();

    for (Proxy &x: nodes) {
        writer.StartObject();
        writer.Key("id");
        writer.Int(1);
        writer.Key("remarks");
        writer.String(x.Remark.c_str());
        writer.Key("server");
        writer.String(x.Hostname.c_str());
        writer.Key("server_port");
        writer.Uint(x.Port);
        writer.Key("password");
        writer.String(x.Password.c_str());

        switch (x.Type) {
            case ProxyType::Shadowsocks:
                writer.Key("method");
                writer.String(x.EncryptMethod.c_str());
                break;
            case ProxyType::VMess:
                writer.Key("method");
                writer.String("chacha20-ietf-poly1305");
                break;
            case ProxyType::TUIC:
                writer.Key("method");
                writer.String("tuic");
                writer.Key("uuid");
                writer.String(x.UserId.c_str());
                writer.Key("token");
                writer.String(x.Password.c_str());
                if (!x.CongestionControl.empty()) {
                    writer.Key("congestion_control");
                    writer.String(x.CongestionControl.c_str());
                }
                if (!x.ServerName.empty()) {
                    writer.Key("sni");
                    writer.String(x.ServerName.c_str());
                }
                if (!x.Alpn.empty()) {
                    writer.Key("alpn");
                    writer.String(x.Alpn.c_str());
                }
                break;
            default:
                writer.Key("method");
                writer.String("aes-128-gcm");
                break;
        }

        if (!x.Plugin.empty() && !x.PluginOption.empty()) {
            writer.Key("plugin");
            writer.String(x.Plugin.c_str());
            writer.Key("plugin_opts");
            writer.String(x.PluginOption.c_str());
        }

        writer.EndObject();
    }

    writer.EndArray();

    if (!userinfo.empty()) {
        writer.Key("userinfo");
        writer.String(userinfo.c_str());
    }

    writer.EndObject();

    return sb.GetString();
}
