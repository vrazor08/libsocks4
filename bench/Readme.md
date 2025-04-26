# Bench

Bench command:
```sh
hyperfine "./target/release/bench -C 450 -P 10 --proxy-addr 127.0.0.2:6969 --target-addr 127.0.0.2:5252 -s 10 -p <socks_proxy pid> test" --runs=15 --warmup 1 --prepare="sleep 0.5" -n "some name"
```
