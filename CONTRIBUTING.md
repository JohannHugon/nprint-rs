# CONTRIBUTING
Thanks for wanting to help the development process, we take any help from remarks, ask for features to concrete contribution.
## Solving an issue
### Step by step
- Assign yourself to an issue
- Create a branch
- Write unit tests
- Fix the issue 
- Make sure your code passes the CI's tests
- Create a PR 
### Run tests
Please make sure your code passes the tests before creating a PR. Otherwise your PR will not be merged.
```
make test
```
### Run Benchmark
As we want to make the library usable in real world deployment, avoiding high overhead for packet processing is crucial. So before doing any PR, make sure your code does not add an unjustifiable overhead to the benchmark. Otherwise your PR will not be merged.
```
on-your-local-branch->$ cargo bench -- --save-baseline changes
on-main-branch->$ cargo bench -- --save-baseline base
$ critcmp base changes
```
