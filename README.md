# Sysdig Log Insider
Sysdig system call log processor and analyzer.

## Usage
* `sli-gen-training`: SLI training dataset generation tool.
  - `-l, --log-root`: Sysdig logs root directory path.
  - `-n, --log-amount-map`: JSON map file containing log amount for each log category.
  - `-o, --output`: Output training dataset file path.
  - `-f, --log-features`: Log features to use (Defaults to "option-arg,fd")
* `sli-gen-detection`: SLI detection dataset generation tool.
  - `-d, --dataset-path`: Training dataset file path.
  - `-l, --log-path`: Log file or log file directory path.
  - `-n, --n-logs`: Number os logs to process (Log directory only).
  - `-o, --output`: Output detection dataset file path.

## License
[MIT License](LICENSE)

