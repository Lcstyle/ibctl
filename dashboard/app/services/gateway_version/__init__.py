"""Gateway version tracking.

ibctl knows which IB Gateway build it runs, what IB currently offers on the
stable and latest channels, and any desupport cutoff IB has announced, and
warns well ahead of that cutoff. IB announces a cutoff by telling every API
connection (error 2172, e.g. that 10.47.1 would be desupported on
2026-12-15); only the API clients see it, so on its own nothing alerts.
"""
