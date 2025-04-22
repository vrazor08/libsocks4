# Bench

Bench command:
```sh
hyperfine "./target/release/bench -C 450 -P 10 -p 127.0.0.2:6969 -t 127.0.0.2:5252 -s 10 bench" --runs=15 --warmup 1 --prepare="sleep 0.5" -n "some name"
```
