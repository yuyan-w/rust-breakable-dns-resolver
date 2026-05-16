| ファイル            | 説明                                                     |
| ------------------- | -------------------------------------------------------- |
| `src/main.rs`       | UDP受信、worker制御、cache確認、レスポンス返却を行う入口 |
| `src/resolver.rs`   | delegation / CNAME追跡など、名前解決の流れを制御する     |
| `src/cache.rs`      | positive cache / negative cache と TTL 管理を行う        |
| `src/dns_packet.rs` | DNSパケットの読み書き、TTL書き換え、応答判定を行う       |
| `src/dns/parser.rs` | DNS Header / Question を解析する                         |
