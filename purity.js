/*
 * Loon · 节点纯净度检测 (Node Purity Check)
 * ------------------------------------------------------------
 * 作用：检测当前出口 IP（或指定节点）的纯净度/风险画像，给出 0-100 评分。
 * 数据源：ipinfo.io（风险标记 / ASN 类型）· ip-api.com（proxy/hosting/mobile）
 *         · scamalytics.com（欺诈分）
 * 类型：generic（可从节点页对单个节点执行）或 cron（每日巡检）
 * 参数：mode=patrol  node=节点名  threshold=55  debug=1
 * 说明：评分是基于公开 IP 情报的启发式评估，不等同于任何平台的风控结论。
 * ------------------------------------------------------------
 */

var CONF = {
    timeout: 9000,        // 单个请求超时（毫秒）
    totalTimeout: 32000,  // 整体兜底超时（毫秒）
    threshold: 55,        // 巡检模式下低于该分数才提醒
    useFraud: true,       // 是否使用 scamalytics 欺诈分
    debug: false,
    ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    storeKey: "loon_node_purity_last"
};

function log(msg) {
    if (!CONF.debug) { return; }
    try { console.log("[purity] " + msg); } catch (e) {}
}

function miss(name) {
    for (var i = 0; i < S.errors.length; i++) {
        if (S.errors[i] === name) { return; }
    }
    S.errors.push(name);
}

/* ---------------- 参数与环境 ---------------- */

var ARG = (function () {
    var a = (typeof $argument === "undefined") ? null : $argument;
    var out = {};
    if (!a) { return out; }
    if (typeof a === "object") {
        for (var k in a) {
            if (Object.prototype.hasOwnProperty.call(a, k)) { out[k] = a[k]; }
        }
        return out;
    }
    var parts = String(a).split("&");
    for (var i = 0; i < parts.length; i++) {
        var kv = parts[i].split("=");
        if (kv.length >= 2) { out[kv[0]] = kv.slice(1).join("="); }
    }
    return out;
})();

var EP = (function () {
    try {
        if (typeof $environment !== "undefined" && $environment && $environment.params) {
            return $environment.params;
        }
    } catch (e) {}
    return {};
})();

// 真正用于发请求的节点名（只能是节点本身的名称）
var NODE = String(ARG.node || EP.node || "");
// 用于界面展示的节点描述
var NODE_LABEL = (function () {
    if (NODE) { return NODE; }
    var ni = EP.nodeInfo;
    if (!ni) { return ""; }
    if (typeof ni === "object") { return String(ni.name || ni.remark || ni.tag || ""); }
    var t = String(ni);
    if (t.charAt(0) === "{") {
        try {
            var o = JSON.parse(t);
            if (o && (o.name || o.remark)) { return String(o.name || o.remark); }
        } catch (e) {}
    }
    return t.replace(/\s+/g, " ").slice(0, 32);
})();

var MODE = String(ARG.mode || "manual").toLowerCase();
var THRESHOLD = (isFinite(Number(ARG.threshold)) && Number(ARG.threshold) > 0)
    ? Number(ARG.threshold) : CONF.threshold;
if (String(ARG.debug) === "1") { CONF.debug = true; }
if (String(ARG.fraud) === "0") { CONF.useFraud = false; }

/* ---------------- 小工具 ---------------- */

var NODE_FALLBACK = false;

function cp(code) {
    if (code < 0x10000) { return String.fromCharCode(code); }
    code -= 0x10000;
    return String.fromCharCode(0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF));
}

function flag(cc) {
    if (!cc || cc.length !== 2) { return ""; }
    var up = cc.toUpperCase();
    if (up.charCodeAt(0) < 65 || up.charCodeAt(1) < 65) { return ""; }
    return cp(0x1F1E6 + up.charCodeAt(0) - 65) + cp(0x1F1E6 + up.charCodeAt(1) - 65);
}

function pad(n) { return (n < 10 ? "0" : "") + n; }

function nowText(d) {
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
        " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
}

function safeJson(text) {
    try { return JSON.parse(text); } catch (e) { return null; }
}

function trimStr(s, n) {
    s = String(s == null ? "" : s);
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/* ---------------- 请求（带节点回退） ---------------- */

function httpGet(url, headers, cb) {
    var done = false;
    function once(err, body) {
        if (done) { return; }
        done = true;
        cb(err || null, body || "");
    }
    function opts(useNode) {
        var o = { url: url, timeout: CONF.timeout };
        if (headers) { o.headers = headers; }
        if (useNode && NODE) { o.node = NODE; }
        return o;
    }
    try {
        $httpClient.get(opts(true), function (err, resp, body) {
            if (err && NODE) {
                // 指定节点不可用时，退回当前策略再试一次
                NODE_FALLBACK = true;
                log("node request failed, retry with current policy: " + err);
                $httpClient.get(opts(false), function (e2, r2, b2) { once(e2, b2); });
                return;
            }
            once(err, body);
        });
    } catch (e) {
        once(String(e), "");
    }
}

/* ---------------- 解析 ---------------- */

function parseIpApi(body) {
    var o = safeJson(body);
    if (!o || o.status !== "success") { return null; }
    return {
        ip: o.query || "",
        country: o.countryCode || "",
        countryName: o.country || "",
        city: o.city || "",
        isp: o.isp || "",
        asn: o.as || "",
        org: o.org || "",
        proxy: !!o.proxy,
        hosting: !!o.hosting,
        mobile: !!o.mobile
    };
}

function parseIpinfoBasic(body) {
    var o = safeJson(body);
    if (!o || !o.ip) { return null; }
    var asn = "";
    if (o.org && String(o.org).indexOf("AS") === 0) { asn = String(o.org); }
    return {
        ip: o.ip,
        city: o.city || "",
        region: o.region || "",
        country: o.country || "",
        org: o.org || "",
        asn: asn
    };
}

function parseIpinfoWidget(body) {
    var root = safeJson(body);
    if (!root) { return null; }
    var d = root.data || root;
    if (!d || !d.ip) { return null; }
    var pv = d.privacy || {};
    var asn = d.asn || {};
    var com = d.company || {};
    var regCountry = "";
    if (d.abuse && typeof d.abuse.address === "string") {
        var m = d.abuse.address.match(/^\s*([A-Za-z]{2})\b/);
        if (m) { regCountry = m[1].toUpperCase(); }
    }
    return {
        ip: d.ip,
        country: d.country || "",
        city: d.city || "",
        region: d.region || "",
        asnNo: asn.asn || "",
        asnName: asn.name || "",
        asnType: String(asn.type || "").toLowerCase(),
        companyName: (com && com.name) || "",
        companyType: String((com && com.type) || "").toLowerCase(),
        vpn: !!pv.vpn,
        proxy: !!pv.proxy,
        tor: !!pv.tor,
        relay: !!pv.relay,
        hosting: !!pv.hosting || !!d.is_hosting,
        service: pv.service || "",
        anycast: !!d.is_anycast,
        mobile: !!d.is_mobile,
        regCountry: regCountry
    };
}

function parseFraud(body) {
    var m = body.match(/Fraud Score:\s*(\d+)/i);
    if (!m) { return null; }
    var score = parseInt(m[1], 10);
    if (!isFinite(score)) { return null; }
    var risk = "";
    var r = body.match(/class="panel_title[^"]*"[^>]*>\s*([^<]+?)\s*</i);
    if (r) { risk = r[1]; }
    return { score: score, risk: risk };
}

/* ---------------- 评分 ---------------- */

function riskWord(score) {
    if (score == null) { return "未知"; }
    if (score < 25) { return "低"; }
    if (score < 50) { return "中"; }
    if (score < 75) { return "高"; }
    return "极高";
}

function riskCN(text) {
    var t = String(text || "").toLowerCase();
    if (!t) { return ""; }
    if (t.indexOf("very high") >= 0) { return "极高"; }
    if (t.indexOf("high") >= 0) { return "高"; }
    if (t.indexOf("medium") >= 0) { return "中"; }
    if (t.indexOf("low") >= 0) { return "低"; }
    return "";
}

function parseIpSb(body) {
    var o = safeJson(body);
    if (!o || !o.ip) { return null; }
    return {
        ip: o.ip,
        country: o.country_code || "",
        countryName: o.country || "",
        city: o.city || "",
        isp: o.isp || o.organization || "",
        asn: o.asn ? ("AS" + o.asn + " " + (o.asn_organization || "")).trim() : "",
        org: o.organization || ""
    };
}

function gradeOf(score) {
    if (score >= 85) { return { label: "纯净", icon: "🟢" }; }
    if (score >= 70) { return { label: "良好", icon: "🟢" }; }
    if (score >= 55) { return { label: "一般", icon: "🟡" }; }
    if (score >= 40) { return { label: "较差", icon: "🟠" }; }
    return { label: "高危", icon: "🔴" };
}

function adviceOf(score, typeLabel) {
    if (score >= 85) { return "接近住宅网络画像，日常浏览、注册、支付都比较稳。"; }
    if (score >= 70) { return "风险标记少，日常使用与流媒体基本无压力。"; }
    if (score >= 55) { return "属于" + typeLabel + "，可正常上网；注册、支付、抢购等场景可能触发人机验证。"; }
    if (score >= 40) { return "处于风控阈值边缘，账号注册/登录容易要验证码，流媒体可能受限。"; }
    return "已被较多平台标记，不建议用于账号登录、支付与重要服务。";
}

/* ---------------- 主流程 ---------------- */

var S = {
    ip: "",
    ipapi: null,
    basic: null,
    sb: null,
    info: null,
    fraud: null,
    errors: []
};

var FINISHED = false;

function finish() {
    if (FINISHED) { return; }
    FINISHED = true;
    try { render(); } catch (e) {
        log("render error: " + e);
        notify("纯净度检测失败", "", "脚本异常：" + e);
        $done();
    }
}

function failAll() {
    if (FINISHED) { return; }
    FINISHED = true;
    var msg = S.errors.length ? S.errors.join("、") + " 无响应" : "所有数据源均不可达";
    if (MODE === "patrol") {
        log("patrol: skipped, " + msg);
        $done();
        return;
    }
    notify("纯净度检测失败", NODE_LABEL || "当前出口", "无法获取出口 IP：" + msg + "\n请确认节点可用后重试。");
    $done();
}

function render() {
    if (!S.ip) { failAll(); return; }

    var f = {
        hosting: false, proxy: false, vpn: false, tor: false,
        relay: false, mobile: false, anycast: false
    };
    var country = "", city = "", isp = "", asn = "", asnType = "", companyType = "", regCountry = "";

    if (S.ipapi) {
        country = country || S.ipapi.country;
        city = city || S.ipapi.city;
        isp = S.ipapi.isp || isp;
        asn = asn || S.ipapi.asn;
        f.hosting = f.hosting || S.ipapi.hosting;
        f.proxy = f.proxy || S.ipapi.proxy;
        f.mobile = f.mobile || S.ipapi.mobile;
    }
    if (S.sb) {
        country = country || S.sb.country;
        city = city || S.sb.city;
        isp = isp || S.sb.isp;
        asn = asn || S.sb.asn;
    }
    if (S.basic) {
        country = country || S.basic.country;
        city = city || S.basic.city;
        asn = asn || S.basic.asn;
    }
    if (S.info) {
        country = S.info.country || country;
        city = S.info.city || city;
        asnType = S.info.asnType;
        companyType = S.info.companyType;
        asn = S.info.asnNo ? (S.info.asnNo + " " + S.info.asnName).trim() : (asn || asnNameOf(S.info));
        regCountry = S.info.regCountry;
        f.hosting = f.hosting || S.info.hosting;
        f.proxy = f.proxy || S.info.proxy;
        f.vpn = f.vpn || S.info.vpn;
        f.tor = f.tor || S.info.tor;
        f.relay = f.relay || S.info.relay;
        f.anycast = f.anycast || S.info.anycast;
        f.mobile = f.mobile || S.info.mobile;
    }

    // 类型判定
    var typeLabel;
    if (f.tor) {
        typeLabel = "Tor 出口";
    } else if (f.vpn) {
        typeLabel = "VPN IP";
    } else if (f.proxy) {
        typeLabel = (f.hosting ? "机房" : "住宅/移动") + "代理 IP";
    } else if (f.hosting || asnType === "hosting" || companyType === "hosting") {
        typeLabel = "机房 IP（数据中心）";
    } else if (asnType === "isp" && f.mobile) {
        typeLabel = "移动网络 IP";
    } else if (asnType === "isp") {
        typeLabel = "家庭宽带 IP";
    } else if (asnType === "business" || asnType === "company") {
        typeLabel = "企业专线 IP";
    } else if (asnType === "education") {
        typeLabel = "教育网 IP";
    } else {
        typeLabel = "普通公网 IP";
    }

    // 评分
    var score = 100;
    var reasons = [];
    if (f.tor) { score -= 30; reasons.push("Tor 出口 -30"); }
    if (f.vpn) { score -= 15; reasons.push("VPN 标记 -15"); }
    if (f.proxy) { score -= 15; reasons.push("代理标记 -15"); }
    if (f.relay) { score -= 8; reasons.push("中继节点 -8"); }
    if (f.hosting) { score -= 38; reasons.push("机房 IP -38"); }
    if (f.anycast) { score -= 4; reasons.push("Anycast -4"); }

    var fraudScore = S.fraud ? S.fraud.score : null;
    if (CONF.useFraud && fraudScore != null) {
        var cut = Math.round(fraudScore * 0.3);
        if (cut > 0) { score -= cut; reasons.push("欺诈分 " + fraudScore + " -" + cut); }
    }

    var mismatch = false;
    if (regCountry && country && regCountry !== country.toUpperCase()) {
        mismatch = true;
        if (!f.anycast) { score -= 6; reasons.push("注册地与定位不一致 -6"); }
    }
    if (score < 0) { score = 0; }
    if (score > 100) { score = 100; }

    var grade = gradeOf(score);
    var parts = [];
    if (country) { parts.push(flag(country) + " " + country.toUpperCase()); }
    if (city) { parts.push(city); }

    var last = null;
    try {
        var raw = $persistentStore.read(CONF.storeKey);
        if (raw) { last = safeJson(raw); }
    } catch (e) {}

    var lines = [];
    lines.push("🛡 节点纯净度报告");
    lines.push("————————————");
    lines.push("节点：" + (NODE_LABEL || "当前出口策略"));
    if (NODE_FALLBACK) { lines.push("提示：节点请求失败，已改用当前策略重试"); }
    lines.push("出口 IP：" + S.ip);
    lines.push("位置：" + (parts.filter(Boolean).join(" · ") || "未知"));
    if (asn) { lines.push("ASN：" + trimStr(asn, 50)); }
    if (isp) { lines.push("运营商：" + trimStr(isp, 50)); }
    lines.push("类型：" + typeLabel);
    lines.push("欺诈分：" + (fraudScore == null
        ? "未获取"
        : fraudScore + "/100（" + (riskCN(S.fraud.risk) || riskWord(fraudScore)) + "）"));
    lines.push("纯净评分：" + score + "/100 · " + grade.label);
    if (last && typeof last.score === "number" && last.ip === S.ip) {
        var diff = score - last.score;
        if (diff !== 0) { lines.push("较上次：" + (diff > 0 ? "+" : "") + diff); }
    }
    lines.push("————————————");
    lines.push("标记：" +
        "机房" + (f.hosting ? "●" : "○") + "  " +
        "代理" + (f.proxy ? "●" : "○") + "  " +
        "VPN" + (f.vpn ? "●" : "○") + "  " +
        "Tor" + (f.tor ? "●" : "○"));
    if (regCountry) {
        lines.push("注册地：" + regCountry.toUpperCase() + (mismatch ? "（与定位不一致，疑似广播 IP）" : "（与定位一致）"));
    }
    if (S.info && S.info.service) {
        lines.push("识别为：" + trimStr(S.info.service, 30));
    }
    lines.push("建议：" + adviceOf(score, typeLabel));
    if (reasons.length) { lines.push("扣分项：" + reasons.join("、")); }
    lines.push("————————————");
    lines.push("数据源：" + ["ipinfo.io", S.ipapi ? "ip-api.com" : "", S.sb ? "ip.sb" : "", S.fraud ? "scamalytics.com" : ""].filter(Boolean).join(" · "));
    lines.push("时间：" + nowText(new Date()));
    if (S.errors.length) { lines.push("未响应：" + S.errors.join(" · ")); }
    lines.push("注：第三方数据库存在偏差，评分仅供参考");

    var report = lines.join("\n");

    try {
        $persistentStore.write(JSON.stringify({ score: score, ip: S.ip, time: Date.now() }), CONF.storeKey);
    } catch (e) {}

    var subtitle = (NODE_LABEL ? NODE_LABEL + " · " : "") + S.ip;

    if (MODE === "patrol") {
        var needNotify = score < THRESHOLD ||
            (last && typeof last.score === "number" && last.score - score >= 10) ||
            (last && last.ip && last.ip !== S.ip && score < 70);
        if (needNotify) {
            notify(grade.icon + " 纯净度 " + score + " · " + grade.label + "（低于 " + THRESHOLD + "）", subtitle,
                typeLabel + " · " + (country || "??") + "\n轻点通知可复制完整报告", report);
        } else {
            log("patrol: score " + score + " ok, silent");
        }
        $done();
        return;
    }

    notify(grade.icon + " 纯净度 " + score + " · " + grade.label, subtitle,
        typeLabel + " · " + (country || "??") + " · " + score + "/100\n轻点通知可复制完整报告", report);
    $done();
}

function asnNameOf(info) {
    return (info.asnName || "").trim();
}

function notify(title, subtitle, content, clipboard) {
    try {
        var attach = clipboard ? { clipboard: clipboard } : null;
        if (attach) {
            $notification.post(title, subtitle, content, attach);
        } else {
            $notification.post(title, subtitle, content);
        }
    } catch (e) {
        log("notify error: " + e);
    }
}

/* ---------------- 启动 ---------------- */

(function main() {
    var guard = setTimeout(function () {
        log("total timeout hit");
        if (!S.ip) { failAll(); } else { finish(); }
    }, CONF.totalTimeout);

    var pending = 3;
    function step1Done() {
        pending--;
        if (pending > 0) { return; }
        S.ip = (S.ipapi && S.ipapi.ip) || (S.basic && S.basic.ip) || (S.sb && S.sb.ip) || "";
        if (!S.ip) { failAll(); return; }
        step2();
    }

    // 第一轮：拿到出口 IP + 基础标记（三源并发，互为兜底）
    httpGet("http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query", null, function (err, body) {
        if (err) { miss("ip-api"); log("ip-api: " + err); }
        else { S.ipapi = parseIpApi(body); if (!S.ipapi) { miss("ip-api"); } }
        step1Done();
    });

    httpGet("https://ipinfo.io/json", null, function (err, body) {
        if (err) { miss("ipinfo"); log("ipinfo: " + err); }
        else { S.basic = parseIpinfoBasic(body); if (!S.basic) { miss("ipinfo"); } }
        step1Done();
    });

    httpGet("https://api.ip.sb/geoip", null, function (err, body) {
        if (err) { log("ip.sb: " + err); }
        else { S.sb = parseIpSb(body); }
        step1Done();
    });

    function step2() {
        var p2 = 1 + (CONF.useFraud ? 1 : 0);
        function done2() {
            p2--;
            if (p2 > 0) { return; }
            try { clearTimeout(guard); } catch (e) {}
            finish();
        }

        // 第二轮：风险标记 + 欺诈分
        httpGet("https://ipinfo.io/widget/demo/" + encodeURIComponent(S.ip), null, function (err, body) {
            if (err) { miss("风控库"); log("widget: " + err); }
            else {
                S.info = parseIpinfoWidget(body);
                if (!S.info) { miss("风控库"); }
            }
            done2();
        });

        if (CONF.useFraud) {
            httpGet("https://scamalytics.com/ip/" + encodeURIComponent(S.ip), { "User-Agent": CONF.ua }, function (err, body) {
                if (err) { log("fraud: " + err); }
                else {
                    S.fraud = parseFraud(body);
                    if (!S.fraud) { log("fraud: parse failed"); }
                }
                done2();
            });
        }
    }
})();
