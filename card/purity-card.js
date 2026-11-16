/***
 * Loon · 节点纯净度详情（卡片版）
 * 交互形态仿 event-interaction：选中节点运行 → 弹出 HTML 详情卡片
 * 数据源：IPPure（主，住宅/广播/欺诈分）+ ipinfo（风险标记交叉校验）
 *
 * 写法：Loon 用 generic；Quantumult X 用 event-interaction，脚本无需改动
 * 参数：node=节点名（可选，覆盖入口节点）  debug=1
 */

var UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";
var TIMEOUT = 6000;
var IPPURE = "https://my.ippure.com/v1/info";

var CONF = { debug: false };

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

if (String(ARG.debug) === "1") { CONF.debug = true; }

function log(m) {
    if (!CONF.debug) { return; }
    try { console.log("[purity-card] " + m); } catch (e) {}
}

/* ───────── 入口参数：节点名 ───────── */

var ENTRY = (function () {
    try {
        if (typeof $environment !== "undefined" && $environment && $environment.params) {
            return $environment.params;
        }
    } catch (e) {}
    return null;
})();

var NODE = (function () {
    if (ARG.node) { return String(ARG.node); }
    if (!ENTRY) { return ""; }
    if (typeof ENTRY === "string") { return ENTRY; }
    if (ENTRY.node) { return String(ENTRY.node); }
    if (ENTRY.policy) { return String(ENTRY.policy); }
    var ni = ENTRY.nodeInfo;
    if (!ni) { return ""; }
    if (typeof ni === "object") { return String(ni.name || ni.remark || ""); }
    var t = String(ni);
    if (t.charAt(0) === "{") {
        try {
            var o = JSON.parse(t);
            if (o && (o.name || o.remark)) { return String(o.name || o.remark); }
        } catch (e) {}
    }
    return t;
})();

/* ───────── 兼容 Loon / QX 的请求 ───────── */

var NODE_DROPPED = false;

function request(url, cb) {
    var headers = { "User-Agent": UA, "Accept": "application/json" };
    var called = false;
    function once(err, body) {
        if (called) { return; }
        called = true;
        cb(err || null, body || "");
    }

    if (typeof $httpClient !== "undefined" && $httpClient && $httpClient.get) {
        var o1 = { url: url, headers: headers, timeout: TIMEOUT };
        if (NODE) { o1.node = NODE; }
        try {
            $httpClient.get(o1, function (err, resp, body) {
                if (err && NODE) {
                    NODE_DROPPED = true;
                    log("node failed, retry with current policy: " + err);
                    $httpClient.get({ url: url, headers: headers, timeout: TIMEOUT }, function (e2, r2, b2) {
                        once(e2, b2);
                    });
                    return;
                }
                once(err, body);
            });
        } catch (e) {
            once(String(e), "");
        }
        return;
    }

    if (typeof $task !== "undefined" && $task && $task.fetch) {
        var o2 = { url: url, headers: headers, timeout: TIMEOUT };
        if (NODE) { o2.opts = { policy: NODE }; }
        $task.fetch(o2).then(function (r) {
            once(null, r.body);
        }, function (e) {
            once(String((e && e.error) || e), "");
        });
        return;
    }

    once("当前环境不支持网络请求", "");
}

/* ───────── 工具 ───────── */

function cp(code) {
    if (code < 0x10000) { return String.fromCharCode(code); }
    code -= 0x10000;
    return String.fromCharCode(0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF));
}

function flag(cc) {
    if (!cc || String(cc).length !== 2) { return "🌍"; }
    var up = String(cc).toUpperCase();
    if (up.charCodeAt(0) < 65 || up.charCodeAt(1) < 65) { return "🌍"; }
    return cp(0x1F1E6 + up.charCodeAt(0) - 65) + cp(0x1F1E6 + up.charCodeAt(1) - 65);
}

function esc(s) {
    return String(s == null ? "" : s)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function cut(s, n) {
    s = String(s == null ? "" : s);
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function json(text) {
    try { return JSON.parse(text); } catch (e) { return null; }
}

/* ───────── 评级 ───────── */

function riskOf(fraud) {
    if (fraud == null) { return { text: "未知", color: "#8e8e93" }; }
    if (fraud <= 25) { return { text: "低风险", color: "#28a745" }; }
    if (fraud <= 50) { return { text: "中风险", color: "#e0a800" }; }
    if (fraud <= 75) { return { text: "高风险", color: "#ff8c00" }; }
    return { text: "极高风险", color: "#dc3545" };
}

function gradeOf(score) {
    if (score >= 85) { return { label: "干净", icon: "🟢", color: "#28a745" }; }
    if (score >= 70) { return { label: "良好", icon: "🟢", color: "#28a745" }; }
    if (score >= 55) { return { label: "一般", icon: "🟡", color: "#e0a800" }; }
    if (score >= 40) { return { label: "较差", icon: "🟠", color: "#ff8c00" }; }
    return { label: "高危", icon: "🔴", color: "#dc3545" };
}

function adviceOf(score, typeText) {
    if (score >= 85) { return "住宅画像，注册/支付/流媒体都比较稳"; }
    if (score >= 70) { return "标记少，日常与流媒体基本无压力"; }
    if (score >= 55) { return "属于" + typeText + "，可正常上网，风控场景可能弹验证"; }
    if (score >= 40) { return "处于风控边缘，账号操作容易要验证码"; }
    return "已被大量平台标记，不建议登录或支付";
}

/* ───────── 主流程 ───────── */

var DONE = false;

function finish(payload) {
    if (DONE) { return; }
    DONE = true;
    try { $done(payload); } catch (e) { log("done error: " + e); }
}

function failCard(msg) {
    var html = '<div style="text-align:center;font-family:-apple-system;font-size:15px;line-height:1.6;">' +
        '<div style="font-size:34px;margin:6px 0;">🛑</div>' +
        '<div style="font-weight:600;">' + esc(msg) + "</div>" +
        '<div style="color:#8e8e93;font-size:13px;margin-top:6px;">请确认节点可用后重试</div>' +
        "</div>";
    finish({ title: "🔎 节点纯净度详情", content: "查询失败：" + msg, htmlMessage: html });
}

request(IPPURE, function (err, body) {
    if (err) { log("ippure error: " + err); failCard("查询超时（IPPure 不可达）"); return; }
    var d = json(body);
    if (!d || !d.ip) { log("ippure parse failed"); failCard("数据解析失败"); return; }
    render(d);
});

function render(d) {
    var ip = d.ip;
    var country = d.countryCode || "";
    var fraud = (typeof d.fraudScore === "number") ? d.fraudScore : null;
    var residential = !!d.isResidential;
    var broadcast = !!d.isBroadcast;

    // 先用 IPPure 出一版卡片，再用 ipinfo 补风险标记（失败不影响）
    request("https://ipinfo.io/widget/demo/" + encodeURIComponent(ip), function (err2, body2) {
        var privacy = null;
        if (!err2) {
            var root = json(body2);
            var dd = root && (root.data || root);
            if (dd && dd.privacy) { privacy = dd.privacy; }
        }
        output(d, privacy);
    });

    function output(d, privacy) {
        var vpn = !!(privacy && privacy.vpn);
        var proxy = !!(privacy && privacy.proxy);
        var tor = !!(privacy && privacy.tor);
        var relay = !!(privacy && privacy.relay);

        var score = 100;
        if (!residential) { score -= 38; }
        if (broadcast) { score -= 12; }
        if (fraud != null) { score -= Math.round(fraud * 0.35); }
        if (tor) { score -= 30; }
        if (vpn) { score -= 15; }
        if (proxy) { score -= 15; }
        if (relay) { score -= 8; }
        if (score < 0) { score = 0; }
        if (score > 100) { score = 100; }

        var grade = gradeOf(score);
        var risk = riskOf(fraud);

        var typeText = residential ? "住宅网络" : "数据中心";
        var typeIcon = residential ? "🏠" : "🏢";
        if (broadcast) { typeText += " / 广播 IP"; }

        var loc = flag(country) + " " + (country || "??");
        if (d.region) { loc += " - " + d.region; }
        if (d.city) { loc += " - " + d.city; }

        var isp = d.asOrganization || "N/A";
        var asn = d.asn ? ("AS" + d.asn) : "N/A";

        var rows = [
            ["IP", ip],
            ["ISP", cut(isp, 30)],
            ["ASN", asn],
            ["位置", loc],
            ["类型", typeText + " " + typeIcon],
            ["欺诈值", (fraud == null ? "N/A" : fraud + " 分")],
            ["风险等级", '<font color="' + risk.color + '">' + risk.text + "</font>"]
        ];

        var html = '<div style="text-align:center;font-family:-apple-system;font-size:15px;line-height:1.6;">';
        html += '<div style="font-size:12px;color:#8e8e93;letter-spacing:1px;">纯净评分</div>';
        html += '<div style="font-size:38px;font-weight:700;line-height:1.15;color:' + grade.color + ';">' + score +
            '<span style="font-size:16px;font-weight:400;color:#8e8e93;"> /100</span></div>';
        html += '<div style="margin:2px 0 8px;font-size:13px;color:' + grade.color + ';">' +
            grade.icon + " " + grade.label + "</div>";
        html += '<hr style="margin:10px 0;border:0;border-top:1px solid #e5e5ea;"/>';

        for (var i = 0; i < rows.length; i++) {
            html += '<div style="margin:3px 0;">' +
                '<b style="display:inline-block;width:64px;text-align:right;color:#8e8e93;font-weight:600;">' + rows[i][0] + "</b>" +
                '<span style="margin-left:8px;">' + rows[i][1] + "</span></div>";
        }

        html += '<hr style="margin:10px 0;border:0;border-top:1px solid #e5e5ea;"/>';
        html += '<div style="font-size:13px;color:#8e8e93;">' + esc(adviceOf(score, typeText)) + "</div>";
        html += '<div style="margin-top:8px;font-size:13px;"><font color="#6959CD"><b>节点</b> ➟ ' +
            esc(NODE || "当前出口") + "</font></div>";
        if (NODE_DROPPED) {
            html += '<div style="margin-top:4px;font-size:12px;color:#ff8c00;">节点请求失败，已改用当前策略</div>';
        }
        html += '<div style="margin-top:10px;font-size:11px;color:#c7c7cc;">IPPure · ipinfo</div>';
        html += "</div>";

        var lines = [
            score + "/100 · " + grade.icon + " " + grade.label,
            "IP：" + ip,
            "ISP：" + cut(isp, 30),
            "ASN：" + asn,
            "位置：" + loc,
            "类型：" + typeText + " " + typeIcon,
            "欺诈值：" + (fraud == null ? "N/A" : fraud + " 分（" + risk.text + "）"),
            "节点：" + (NODE || "当前出口")
        ];

        finish({
            title: "🔎 节点纯净度详情",
            content: lines.join("\n"),
            htmlMessage: html
        });
    }
}
