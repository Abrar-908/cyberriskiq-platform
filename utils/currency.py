import pandas as pd
import numpy as np

def format_inr(number: float, precision: int = 0) -> str:
    """
    Formats a number into the Indian Rupee (INR) numbering system (Lakhs and Crores).
    Examples:
      1000000 -> ₹10,00,000
      45000000 -> ₹4.50 Cr
    """
    if number is None or np.isnan(number):
        return "₹0"
    
    val = float(number)
    is_negative = val < 0
    val = abs(val)

    if val >= 10000000:  # 1 Crore = 10 Million
        cr_val = val / 10000000.0
        res = f"₹{cr_val:.2f} Cr"
    elif val >= 100000:  # 1 Lakh = 100 Thousand
        lakh_val = val / 100000.0
        res = f"₹{lakh_val:.2f} L"
    else:
        # Standard Indian comma grouping
        s = f"{int(round(val))}"
        if len(s) <= 3:
            res = f"₹{s}"
        else:
            last3 = s[-3:]
            remaining = s[:-3]
            groups = []
            while len(remaining) > 2:
                groups.insert(0, remaining[-2:])
                remaining = remaining[:-2]
            if remaining:
                groups.insert(0, remaining)
            res = f"₹{','.join(groups)},{last3}"

    return f"-{res}" if is_negative else res

def format_inr_full(number: float) -> str:
    """Formats an integer into standard Indian comma grouping (e.g. ₹10,00,000)."""
    if number is None or np.isnan(number):
        return "₹0"
    val = abs(int(round(number)))
    s = str(val)
    if len(s) <= 3:
        res = f"₹{s}"
    else:
        last3 = s[-3:]
        remaining = s[:-3]
        groups = []
        while len(remaining) > 2:
            groups.insert(0, remaining[-2:])
            remaining = remaining[:-2]
        if remaining:
            groups.insert(0, remaining)
        res = f"₹{','.join(groups)},{last3}"
    return f"-{res}" if number < 0 else res
