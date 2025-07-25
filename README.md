# AdBlock DNS Filters
适用于AdGuard的去广告合并规则，每8个小时更新一次。

## 说明
1. 定时从上游各规则源获取更新，合并去重。
2. 使用国内、国外各 3 组 DNS 服务，分别对上游各规则源拦截的域名进行解析，去除已无法解析的域名。（上游各规则源中存在大量已无法解析的域名，无需加入拦截规则）
3. 本项目仅对上游规则进行合并、去重、去除无效域名，不做任何修改。如发现误拦截情况，可临时添加放行规则（如 `@@||www.example.com^$important`），并向上游规则反馈。

## 订阅链接
1. AdGuard Home 等DNS拦截服务使用规则1
2. AdGuard 等浏览器插件使用规则1 + 规则2

| 规则 | 原始链接 | 加速链接 |
|:-|:-|:-|
| 规则1：DNS 拦截 | [原始链接](https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/adblockdns.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/adblockdns.txt) |
| 规则2：插件拦截 | [原始链接](https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/adblockfilters.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/adblockfilters.txt) |

| 规则 | 类型 | 原始链接 | 加速链接 | 更新日期 |
|:-|:-|:-|:-|:-|
| AdGuard Base filter | filter | [原始链接](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/AdGuard_Base_filter.txt) | 2025/07/26 |
| AdGuard Tracking Protection filter | filter | [原始链接](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/AdGuard_Tracking_Protection_filter.txt) | 2025/07/26 |
| AdGuard URL Tracking filter | filter | [原始链接](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/AdGuard_URL_Tracking_filter.txt) | 2025/07/26 |
| AdGuard Chinese filter | filter | [原始链接](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/AdGuard_Chinese_filter.txt) | 2025/07/26 |
| anti-AD | filter | [原始链接](https://anti-ad.net/adguard.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/anti-AD.txt) | 2025/07/26 |
| CJX's Annoyance List | filter | [原始链接](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/CJX's_Annoyance_List.txt) | 2025/05/26 |
| xinggsf mv | filter | [原始链接](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/xinggsf_mv.txt) | 2025/07/08 |
| jiekouAD | filter | [原始链接](https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/jiekouAD.txt) | 2025/07/26 |
| 1Hosts (Lite) | dns | [原始链接](https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/1Hosts_(Lite).txt) | 2025/07/26 |
| AdGuard DNS filter | dns | [原始链接](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/AdGuard_DNS_filter.txt) | 2025/07/26 |
| AdRules DNS List | dns | [原始链接](https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/AdRules_DNS_List.txt) | 2025/07/26 |
| anti-AD | dns | [原始链接](https://anti-ad.net/easylist.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/anti-AD.txt) | 2025/07/26 |
| AWAvenue Ads Rule | dns | [原始链接](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/AWAvenue_Ads_Rule.txt) | 2025/07/24 |
| Hblock | dns | [原始链接](https://hblock.molinero.dev/hosts_adblock.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/Hblock.txt) | 2025/07/26 |
| NEO DEV HOST | dns | [原始链接](https://raw.githubusercontent.com/neodevpro/neodevhost/master/lite_adblocker) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/NEO_DEV_HOST.txt) | 2025/02/18 |
| OISD Basic | dns | [原始链接](https://abp.oisd.nl/basic/) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/OISD_Basic.txt) | 2025/07/26 |
| SmartTV Blocklist | dns | [原始链接](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/SmartTV_Blocklist.txt) | 2023/10/11 |
| 1024 hosts | host | [原始链接](https://raw.githubusercontent.com/Goooler/1024_hosts/master/hosts) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/1024_hosts.txt) | 2023/08/31 |
| ad-wars hosts | host | [原始链接](https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/ad-wars_hosts.txt) | 2023/11/17 |
| StevenBlack hosts | host | [原始链接](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/sleel/adblockfilters/main/rules/StevenBlack_hosts.txt) | 2025/07/24 |

