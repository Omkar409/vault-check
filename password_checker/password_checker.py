#!/usr/bin/env python3
"""
Password Strength Analyzer for Kali Linux
Analyzes password security using entropy, pattern matching, and NIST guidelines.
Author: Security Tool Suite
"""

import re
import math
import sys
import getpass
from collections import Counter

# Color codes for Kali terminal
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"
    DIM = "\033[2m"

# Common weak patterns to detect
COMMON_PATTERNS = [
    (r'^(password|pass|passwd|pwd|admin|root|user|login|guest|test|qwerty|abc123|letmein|welcome|monkey|dragon|master|sunshine|princess|football|baseball|iloveyou|trustno1|shadow|ashley|michael|jesus|mustang|access|love|pussy|696969|qwertyuiop|1234567890|superman|batman|harley|ranger|thomas|robert|george|chester|killer|matthew|martin|andrew|joshua|daniel|william|joseph|jessica|amanda|jennifer|michelle|melissa|nicole|stephanie|rebecca|lauren|ashley|megan|brittany|kayla|samantha|heather|elizabeth|tiffany|christina|amber|emily|rachel|brianna|katherine|victoria|destiny|morgan|hannah|jasmine|alexandra|sierra|maria|anna|erica|mary|kelly|laura|lisa|andrea|james|john|robert|michael|david|william|richard|joseph|thomas|charles|daniel|matthew|anthony|mark|donald|steven|paul|andrew|kenneth|joshua|kevin|brian|george|edward|ronald|timothy|jason|jeffrey|ryan|jacob|gary|nicholas|eric|jonathan|stephen|larry|justin|scott|brandon|benjamin|samuel|gregory|frank|alexander|raymond|patrick|jack|dennis|jerry|tyler|aaron|jose|adam|nathan|henry|douglas|zachary|peter|kyle|walter|ethan|jeremy|harold|keith|christian|roger|noah|gerald|carl|terry|sean|austin|arthur|lawrence|jesse|dylan|bryan|joe|jordan|billy|bruce|albert|willie|gabriel|logan|alan|juan|wayne|roy|ralph|randy|eugene|vincent|russell|eli|bobby|philip|mary|patricia|jennifer|linda|elizabeth|barbara|susan|jessica|sarah|karen|nancy|lisa|betty|margaret|sandra|ashley|kimberly|emily|donna|michelle|dorothy|carol|amanda|melissa|deborah|stephanie|rebecca|laura|sharon|cynthia|kathleen|amy|shirley|angela|helen|anna|brenda|pamela|nicole|emma|samantha|katherine|christine|debra|rachel|catherine|carolyn|janet|ruth|maria|heather|diane|virginia|julie|joyce|victoria|olivia|kelly|christina|lauren|joan|evelyn|judith|megan|cheryl|andrea|hannah|martha|jacqueline|frances|gloria|ann|teresa|kathryn|sara|janice|jean|alice|madison|doris|abigail|julia|judy|grace|denise|amber|marilyn|beverly|danielle|theresa|sophia|marie|diana|brittany|natalie|isabella|charlotte|rose|alexis|kayla)$', "Common dictionary word"),
    (r'\d{4,}$', "Trailing numbers (dates/years)"),
    (r'^\d+', "Leading numbers"),
    (r'(.)\1{2,}', "Repeated characters (3+)"),
    (r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)', "Keyboard sequence"),
    (r'(19|20)\d{2}', "Birth year pattern"),
]

# Common password lists (top 1000 would be loaded from file in production)
TOP_PASSWORDS = {
    '123456', 'password', '12345678', 'qwerty', '123456789', 'letmein', '1234567',
    'football', 'iloveyou', 'admin', 'welcome', 'monkey', 'login', 'abc123',
    '111111', '123123', 'password1', '1234', 'baseball', 'qwertyuiop', 'princess',
    'solo', 'dragon', 'sunshine', 'master', 'photoshop', '1q2w3e4r', '1qaz2wsx',
    'trustno1', 'batman', 'harley', 'hacker', 'kalilinux', 'kali', 'root', 'toor'
}


def calculate_entropy(password):
    """Calculate Shannon entropy of the password."""
    if not password:
        return 0

    length = len(password)
    counts = Counter(password)
    entropy = 0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy * length  # Total entropy in bits


def estimate_crack_time(password, gpu_speed=100_000_000_000):
    """Estimate time to crack using brute force (assuming GPU at 100B hashes/sec)."""
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'\d', password): charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset_size += 33

    if charset_size == 0:
        return "instant", 0

    combinations = charset_size ** len(password)
    seconds = combinations / gpu_speed

    if seconds < 1:
        return "instant", seconds
    elif seconds < 60:
        return f"{seconds:.1f} seconds", seconds
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes", seconds
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours", seconds
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days", seconds
    elif seconds < 3153600000:
        return f"{seconds/31536000:.1f} years", seconds
    else:
        return f"{seconds/3153600000:.1f} centuries", seconds


def check_patterns(password):
    """Detect weak patterns in password."""
    issues = []

    for pattern, description in COMMON_PATTERNS:
        if re.search(pattern, password, re.IGNORECASE):
            issues.append(description)

    # Check for common passwords
    if password.lower() in TOP_PASSWORDS:
        issues.append("Found in common password list")

    # Check for leetspeak that's easily reversed
    leet_reversed = password.lower().replace('0', 'o').replace('1', 'i').replace('3', 'e').replace('4', 'a').replace('5', 's').replace('7', 't').replace('9', 'g').replace('@', 'a').replace('$', 's')
    if leet_reversed in TOP_PASSWORDS and leet_reversed != password.lower():
        issues.append("Leetspeak variant of common password")

    return issues


def analyze_password(password):
    """Main analysis function."""
    results = {
        'length': len(password),
        'has_lower': bool(re.search(r'[a-z]', password)),
        'has_upper': bool(re.search(r'[A-Z]', password)),
        'has_digit': bool(re.search(r'\d', password)),
        'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
        'entropy': calculate_entropy(password),
        'patterns': check_patterns(password),
        'crack_time': estimate_crack_time(password)
    }

    # Calculate score (0-100)
    score = 0

    # Length scoring
    if results['length'] >= 16: score += 25
    elif results['length'] >= 12: score += 20
    elif results['length'] >= 8: score += 10
    elif results['length'] >= 6: score += 5

    # Character variety
    variety_count = sum([results['has_lower'], results['has_upper'], 
                          results['has_digit'], results['has_special']])
    score += variety_count * 15

    # Entropy bonus
    if results['entropy'] > 80: score += 15
    elif results['entropy'] > 60: score += 10
    elif results['entropy'] > 40: score += 5

    # Penalties
    if results['patterns']:
        score -= min(len(results['patterns']) * 10, 30)
    if results['length'] < 8:
        score -= 20

    results['score'] = max(0, min(100, score))

    # Determine strength label
    if results['score'] >= 80:
        results['strength'] = "STRONG"
        results['color'] = Colors.GREEN
    elif results['score'] >= 50:
        results['strength'] = "MODERATE"
        results['color'] = Colors.YELLOW
    elif results['score'] >= 25:
        results['strength'] = "WEAK"
        results['color'] = Colors.RED
    else:
        results['strength'] = "VERY WEAK"
        results['color'] = Colors.RED + Colors.BOLD

    return results


def print_banner():
    """Display tool banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗
║           PASSWORD STRENGTH ANALYZER v2.0                    ║
║         Kali Linux Security Assessment Tool                  ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)


def print_results(results, password):
    """Display analysis results in formatted output."""
    masked = password[:2] + '*' * (len(password) - 4) + password[-2:] if len(password) > 4 else '*' * len(password)

    print(f"\n{Colors.BOLD}┌─ Analysis Results ─────────────────────────────────────┐{Colors.END}")
    print(f"{Colors.BOLD}│{Colors.END} Password:     {Colors.CYAN}{masked}{Colors.END}")
    print(f"{Colors.BOLD}│{Colors.END} Length:       {results['length']} characters")

    # Strength meter
    bar_length = 20
    filled = int(results['score'] / 100 * bar_length)
    bar = '█' * filled + '░' * (bar_length - filled)
    print(f"{Colors.BOLD}│{Colors.END} Strength:     {results['color']}{results['strength']}{Colors.END} ({results['score']}/100)")
    print(f"{Colors.BOLD}│{Colors.END} Meter:        [{results['color']}{bar}{Colors.END}]")

    print(f"{Colors.BOLD}│{Colors.END} Entropy:      {results['entropy']:.1f} bits")
    print(f"{Colors.BOLD}│{Colors.END} Crack Time:   {results['crack_time'][0]}")
    print(f"{Colors.BOLD}├─ Character Composition ────────────────────────────────┤{Colors.END}")

    checks = [
        ("Lowercase", results['has_lower']),
        ("Uppercase", results['has_upper']),
        ("Digits", results['has_digit']),
        ("Special", results['has_special'])
    ]

    for name, present in checks:
        status = f"{Colors.GREEN}✓{Colors.END}" if present else f"{Colors.RED}✗{Colors.END}"
        print(f"{Colors.BOLD}│{Colors.END} {status} {name:12} {'Present' if present else 'Missing'}")

    if results['patterns']:
        print(f"{Colors.BOLD}├─ Security Warnings ────────────────────────────────────┤{Colors.END}")
        for issue in results['patterns']:
            print(f"{Colors.BOLD}│{Colors.END} {Colors.YELLOW}⚠{Colors.END}  {issue}")
    else:
        print(f"{Colors.BOLD}├─ Security Warnings ────────────────────────────────────┤{Colors.END}")
        print(f"{Colors.BOLD}│{Colors.END} {Colors.GREEN}✓{Colors.END}  No common patterns detected")

    print(f"{Colors.BOLD}└────────────────────────────────────────────────────────┘{Colors.END}")

    # Recommendations
    print(f"\n{Colors.BOLD}Recommendations:{Colors.END}")
    if results['length'] < 12:
        print(f"  {Colors.YELLOW}→{Colors.END} Use at least 12 characters (16+ recommended)")
    if not results['has_special']:
        print(f"  {Colors.YELLOW}→{Colors.END} Add special characters (!@#$%^&*)")
    if not results['has_upper']:
        print(f"  {Colors.YELLOW}→{Colors.END} Include uppercase letters")
    if not results['has_digit']:
        print(f"  {Colors.YELLOW}→{Colors.END} Add numeric digits")
    if results['patterns']:
        print(f"  {Colors.YELLOW}→{Colors.END} Avoid dictionary words, keyboard patterns, and personal info")
    if results['score'] >= 80:
        print(f"  {Colors.GREEN}→{Colors.END} Excellent password! Consider using a password manager.")

    print()


def generate_password(length=16):
    """Generate a secure random password."""
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"

    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Ensure all character types are present
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)):
            return password


def interactive_mode():
    """Interactive password analysis loop."""
    print_banner()

    while True:
        print(f"{Colors.DIM}Options: [analyze] password | [generate] length | [quit]{Colors.END}")
        try:
            choice = input(f"\n{Colors.CYAN}cmd>{Colors.END} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.YELLOW}Exiting...{Colors.END}")
            break

        if choice in ('quit', 'exit', 'q'):
            print(f"{Colors.GREEN}Goodbye!{Colors.END}")
            break

        elif choice.startswith('generate') or choice.startswith('gen'):
            parts = choice.split()
            length = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 16
            length = max(8, min(64, length))

            password = generate_password(length)
            print(f"\n{Colors.GREEN}Generated Password:{Colors.END} {Colors.BOLD}{password}{Colors.END}")
            results = analyze_password(password)
            print_results(results, password)

        elif choice.startswith('analyze') or choice.startswith('check'):
            parts = choice.split(maxsplit=1)
            if len(parts) > 1:
                password = parts[1]
            else:
                password = getpass.getpass(f"{Colors.CYAN}Enter password (hidden):{Colors.END} ")

            if not password:
                print(f"{Colors.RED}Error: Empty password{Colors.END}")
                continue

            results = analyze_password(password)
            print_results(results, password)

        else:
            # Default: treat as password to analyze
            if choice:
                results = analyze_password(choice)
                print_results(results, choice)


def main():
    """Main entry point with CLI argument support."""
    if len(sys.argv) > 1:
        if sys.argv[1] in ('-h', '--help'):
            print(f"""
{Colors.BOLD}Password Strength Analyzer{Colors.END}

Usage:
  python3 password_checker.py              # Interactive mode
  python3 password_checker.py <password>   # Analyze single password
  python3 password_checker.py -g [length]  # Generate secure password
  python3 password_checker.py -h           # Show this help

Features:
  • Entropy calculation (Shannon)
  • Brute-force crack time estimation
  • Pattern detection (keyboard walks, dates, repeats)
  • Common password list checking
  • NIST SP 800-63B compliance hints
  • Secure password generation
""")
            return
        elif sys.argv[1] in ('-g', '--generate'):
            length = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 16
            password = generate_password(length)
            print(password)
            return
        else:
            password = sys.argv[1]
            print_banner()
            results = analyze_password(password)
            print_results(results, password)
            return

    interactive_mode()


if __name__ == "__main__":
    main()
