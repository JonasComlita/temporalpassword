"""Helpers for canonical temporal-password encoding."""


def encode_temporal_password_groups(groups):
    """
    Encode text groups into an unambiguous representation.

    Example: ["ab", "c"] -> "2:ab1:c"
    """
    return "".join(f"{len(group)}:{group}" for group in groups)


def encode_temporal_intervals(intervals):
    """Encode interval list as a colon-separated sequence."""
    return ":".join(str(interval) for interval in intervals)


def encode_temporal_combined_secret(password_groups, time_intervals):
    """
    Canonical combined encoding for temporal authentication.

    Uses explicit section labels and list sizes to avoid ambiguity.
    """
    if len(password_groups) != len(time_intervals):
        raise ValueError("password_groups and time_intervals length mismatch")

    encoded_groups = encode_temporal_password_groups(password_groups)
    encoded_intervals = encode_temporal_intervals(time_intervals)
    return f"g:{len(password_groups)}|{encoded_groups}|t:{len(time_intervals)}|{encoded_intervals}"
