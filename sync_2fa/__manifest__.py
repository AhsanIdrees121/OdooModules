# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

{
    'name': 'Two Factor Authentication',
    'version': '1.0.1',
    'summary': """Provide extra layer of security on desktop using google time based OTP (TOTP).
    In our application user needs to enter time-based OTP while logged in to his Odoo account. OTP will be Auto generated/changed every 30 seconds. One-Time Password will be generated only on your phone using the Google Authenticator App or user can receive this OTP on his registered email address in Odoo.
    Authentication
Two factor authentication
google
otp
google time based otp
2fa
two step verification
dual factor authentication
login
login security
secure
secure login
two factor login
dual factor login
security token
token
odoo account
odoo user
odoo user login
odoo user authentication
user
user login
QR code
2fa login
google authenticator
google auth
verification
certificate
authority
identity
code
sms
email
password
google
time based otp
totp
single factor authentication
Digits Access Token
    
    """,
    'description': """
                    In our application user needs to enter time-based OTP while logged in to his Odoo account. OTP will be Auto generated/changed every 30 seconds. One-Time Password will be generated only on your phone using the Google Authenticator App or user can receive this OTP on his registered email address in Odoo.
                    
                    Provide extra layer of security using
                    google time based OTP (TOTP).
               """,
    'category': 'Extra Tools',
    'author': 'Synconics Technologies Pvt. Ltd.',
    'website': 'http://www.synconics.com',
    'depends': ['base', 'mail'],
    'data': [
        'data/mail_template.xml',
        'views/website_client.xml',
        'views/res_user_view.xml',
        'views/2fa_auth_login.xml',
    ],
    'demo': [],
    'images': [
        'static/description/main_screen.png'
    ],
    'external_dependencies': {
        'python': ['pyotp', 'qrcode'],
    },
    'price': 40.0,
    'currency': 'EUR',
    'installable': True,
    'application': True,
    'auto_install': False,
    'license': 'OPL-1',
}
