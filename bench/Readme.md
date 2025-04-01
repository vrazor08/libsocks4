# Bench

Bench command:
```sh
hyperfine ./target/release/bench --runs=15 --warmup 1 --prepare="sleep 0.5" -n "some name"
```
