# Hammer
A Python-based Blind Boolean SQL injection script that uses multiprocessing to infer the results of SELECT queries.

To Do: 

    - update for Python 3
    - Update logic - for each character, instead of iterating over every possible letter/number/symbol, first check character type using < or > (based on ascii ranges), then only iterate over that smaller range.
