def list_stats(lst, round_decimal=2):
    if not lst:
        return {"avg": 0, "median": 0, "min": 0, "max": 0}
    lst = sorted(lst)
    return {
        "avg": round(sum(lst) / len(lst), round_decimal),
        "median": lst[len(lst) // 2],
        "min": lst[0],
        "max": lst[-1]
    }
