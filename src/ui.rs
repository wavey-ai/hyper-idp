use bytes::Bytes;

const WAVEY_LOGO_BASE64: &str = include_str!("../assets/wavey-128.b64");

pub fn login_page() -> Bytes {
    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - wavey</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 24px;
            padding: 48px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            max-width: 400px;
            width: 90%;
        }}
        .logo {{
            width: 96px;
            height: 96px;
            margin-bottom: 24px;
            border-radius: 20px;
        }}
        h1 {{
            color: #fff;
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        .tagline {{
            color: rgba(255, 255, 255, 0.6);
            font-size: 16px;
            margin-bottom: 32px;
        }}
        .btn {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            background: #fff;
            color: #1a1a2e;
            border: none;
            padding: 14px 32px;
            font-size: 16px;
            font-weight: 600;
            border-radius: 12px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s ease;
            width: 100%;
        }}
        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.3);
        }}
        .btn svg {{
            width: 20px;
            height: 20px;
        }}
        .divider {{
            display: flex;
            align-items: center;
            margin: 24px 0;
            color: rgba(255, 255, 255, 0.4);
            font-size: 14px;
        }}
        .divider::before, .divider::after {{
            content: '';
            flex: 1;
            height: 1px;
            background: rgba(255, 255, 255, 0.2);
        }}
        .divider::before {{ margin-right: 16px; }}
        .divider::after {{ margin-left: 16px; }}
        .footer {{
            margin-top: 32px;
            color: rgba(255, 255, 255, 0.4);
            font-size: 12px;
        }}
        .footer a {{
            color: rgba(255, 255, 255, 0.6);
            text-decoration: none;
        }}
        .footer a:hover {{
            color: #fff;
        }}
    </style>
</head>
<body>
    <div class="container">
        <img src="data:image/png;base64,{logo}" alt="wavey" class="logo">
        <h1>Welcome to wavey</h1>
        <p class="tagline">Sign in to continue</p>

        <a href="/login" class="btn">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M13.8 12H3"/>
            </svg>
            Continue with Auth0
        </a>

        <div class="footer">
            <p>By signing in, you agree to our Terms and Privacy Policy</p>
        </div>
    </div>
</body>
</html>"#, logo = WAVEY_LOGO_BASE64.trim());

    Bytes::from(html)
}

pub fn callback_success_page(email: &str) -> Bytes {
    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Signed in - wavey</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 24px;
            padding: 48px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            max-width: 400px;
            width: 90%;
        }}
        .checkmark {{
            width: 64px;
            height: 64px;
            margin: 0 auto 24px;
            background: #10b981;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .checkmark svg {{ width: 32px; height: 32px; color: #fff; }}
        h1 {{ color: #fff; font-size: 24px; margin-bottom: 8px; }}
        .email {{ color: rgba(255, 255, 255, 0.6); font-size: 14px; margin-bottom: 24px; }}
        .btn {{
            display: inline-block;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-size: 14px;
            transition: background 0.2s;
        }}
        .btn:hover {{ background: rgba(255, 255, 255, 0.2); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                <path d="M20 6L9 17l-5-5"/>
            </svg>
        </div>
        <h1>You're signed in!</h1>
        <p class="email">{email}</p>
        <a href="/profile" class="btn">View Profile</a>
    </div>
</body>
</html>"#, email = email);

    Bytes::from(html)
}
