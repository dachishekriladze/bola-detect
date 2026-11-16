from detector.behavioral import (ConsecutiveIdsRule, DistinctObjectsRule, FailedRequestsRule,
                                 FirstAccessRule, RequestRateRule)


def make_rule(cfg):
    """Build a behavioral rule from a configuration dict (see evaluation/frozen_config.json)."""
    kind = cfg["rule"]
    if kind == "B1":
        return DistinctObjectsRule(cfg["window"], cfg["threshold"])
    if kind == "B2":
        quiet = cfg["window"] if cfg["quiet"] == "window" else cfg["quiet"]
        return ConsecutiveIdsRule(cfg["window"], cfg["run"], quiet)
    if kind == "B3":
        return FirstAccessRule(cfg["window"], cfg["threshold"])
    if kind == "B4":
        return RequestRateRule(cfg["window"], cfg["threshold"])
    if kind == "B5":
        return FailedRequestsRule(cfg["window"], cfg["threshold"])
    raise ValueError(kind)