import re

def assess_password_strength(password):
    length_criteria = len(password) >= 8
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    digit_criteria = bool(re.search(r'\d', password))
    special_char_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    feedback = []
    
    if length_criteria:
        feedback.append("✅ Sufficient length (8 or more characters)")
    else:
        feedback.append("❌ Password is too short (at least 8 characters needed)")
        
    if lowercase_criteria:
        feedback.append("✅ Contains lowercase letter(s)")
    else:
        feedback.append("❌ Add at least one lowercase letter")
        
    if uppercase_criteria:
        feedback.append("✅ Contains uppercase letter(s)")
    else:
        feedback.append("❌ Add at least one uppercase letter")
        
    if digit_criteria:
        feedback.append("✅ Contains digit(s)")
    else:
        feedback.append("❌ Add at least one digit")
        
    if special_char_criteria:
        feedback.append("✅ Contains special character(s) (e.g., !, @, #)")
    else:
        feedback.append("❌ Add at least one special character (e.g., !, @, #)")
    
    score = sum([length_criteria, lowercase_criteria, uppercase_criteria, digit_criteria, special_char_criteria])
    
    if score == 5:
        strength = "🔒 Very Strong"
    elif score == 4:
        strength = "🛡️ Strong"
    elif score == 3:
        strength = "⚠️ Moderate"
    else:
        strength = "❗ Weak"
    
    return strength, feedback


# Example usage
password = input("Enter your password: ")
strength, feedback = assess_password_strength(password)

print(f"Password Strength: {strength}")
for comment in feedback:
    print(comment)