/* =============================================================================
 * 22 · 三条演示规则：标准测试串 / 下载执行组合 / 硬编码 IP 端点
 * 语法骨架：rule <名字> : <标签> { meta: … strings: … condition: … }
 *   strings   文本（"text"，可加 nocase）· 十六进制（{ 6A 40 ?? }）· 正则（/re/）
 *   condition 逻辑组合：$s、any/all of them、1 of ($a*)、filesize、偏移……
 * ============================================================================= */

rule EICAR_Test_File : test
{
    meta:
        description = "EICAR 标准反病毒测试文件（行业通用的无害测试串）"
        severity    = "info"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Suspicious_Download_And_Execute : malware
{
    meta:
        description = "可疑的「下载 → 赋权/执行」组合（脚本落地即执行的常见形态）"
        severity    = "high"
    strings:
        $dl1 = "curl -s" nocase
        $dl2 = "wget http" nocase
        $x1  = "chmod +x" nocase
        $x2  = "| bash" nocase
    condition:
        1 of ($dl*) and 1 of ($x*)
}

rule Hardcoded_IP_Endpoint : c2
{
    meta:
        description = "硬编码 IP 的 web 端点（下载器/回连的常用形态）"
        severity    = "medium"
    strings:
        $ipurl = /https?:\/\/[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?\/[a-z_]+\.php/ nocase
    condition:
        $ipurl
}
