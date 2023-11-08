# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import pyotp
import odoo
from odoo import fields, http, _
from odoo.http import request
from odoo.addons.web.controllers.main import ensure_db, Home
from odoo.service import security
from datetime import datetime


class DoubleAuthLogin(Home):

    @http.route('/web/login', type='http', auth="none", sitemap=False)
    def web_login(self, redirect=None, **kw):
        ensure_db()
        request.params['login_success'] = False
        if request.httprequest.method == 'GET' and redirect and request.session.uid:
            return http.redirect_with_hash(redirect)

        if not request.params.get('login') and not request.uid:
            request.uid = request.env.ref('base.public_user').id
        if not request.uid:
            request.uid = request.env.ref('base.public_user').id

        values = request.params.copy()
        try:
            values['databases'] = http.db_list()
        except odoo.exceptions.AccessDenied:
            values['databases'] = None

        if request.httprequest.method == 'POST':
            old_uid = request.uid
            try:
                # Add logic for google 2fa
                request.session['password'] = request.params['password']
                request.session['login'] = request.params['login']
                if 'login' in values and not request.session.get('auth_complete'):
                    user = request.env['res.users'].sudo().search([('login', '=', values['login'])], limit=1)
                    if user:
                        security.check(request.session.db, user.id, request.params['password'])
                    if user and user.user_2f_enable_status:
                        request.session['login_user'] = user.id
                        return http.redirect_with_hash('/web/auth_login')

                uid = request.session.authenticate(request.session.db, request.params['login'], request.params['password'])
                if uid is not False:
                    request.params['login_success'] = True
                    return http.redirect_with_hash(self._login_redirect(uid, redirect=redirect))
                request.uid = old_uid
                values['error'] = _("Wrong login/password")
            except odoo.exceptions.AccessDenied as e:
                request.uid = old_uid
                if e.args == odoo.exceptions.AccessDenied().args:
                    values['error'] = _("Wrong login/password")
                else:
                    values['error'] = e.args[0]
        else:
            if 'error' in request.params and request.params.get('error') == 'access':
                values['error'] = _('Only employee can access this database. Please contact the administrator.')

        if 'login' not in values and request.session.get('auth_login'):
            values['login'] = request.session.get('auth_login')

        if not odoo.tools.config['list_db']:
            values['disable_database_manager'] = True

        # otherwise no real way to test debug mode in template as ?debug =>
        # values['debug'] = '' but that's also the fallback value when
        # missing variables in qweb
        if 'debug' in values:
            values['debug'] = True

        response = request.render('web.login', values)
        response.headers['X-Frame-Options'] = 'DENY'
        response.qcontext.update(self.get_auth_signup_config())
        return response

    @http.route(['/web/auth_login'], type='http', auth="public", website=True, csrf=False)
    def auth_login(self, *args, **kw):
        values = request.params.copy()
        if 'login_user' in request.session:
            user = request.env['res.users'].sudo().browse(request.session['login_user'])
            values['email'] = ''
            if user and user.partner_id and user.partner_id.email:
                values['email'] = user.partner_id.email
            if values.get('send_code_mail') == 'on':
                template_id = request.env.ref('sync_2fa.2fa_code_email')
                if template_id:
                    totp = pyotp.TOTP(user.secret_key, interval=user.time_limit)
                    request.session.update({'tootp_email': totp.now()})
                    request.session.update({'tootp_email_time': [datetime.now()]})
                    context = dict(request.env.context or {})
                    request.env.context = context
                    template_id.sudo().with_context({'tootp_now': totp.now()}).send_mail(user.id, force_send=True, raise_exception=False, email_values={'email_to': user.email, 'email_from': user.company_id.email or user.email}, notif_layout='mail.mail_notification_light')

            else:
                totp = pyotp.TOTP(user.secret_key)
                tootp_now = totp.now()
                request.params['login_success'] = True
                if values.get('auth_code'):
                    if tootp_now == values['auth_code'] or values['auth_code'] == request.session.get('tootp_email', False):
                        time_diff = datetime.now() - request.session.get('tootp_email_time')[0]
                        if time_diff.seconds <= user.time_limit and time_diff.days < 1:
                            redirect = '/web'
                            request.session['auth_complete'] = True
                            request.params['login_success'] = True
                            uid = request.session.authenticate(request.session.db, request.session.login, request.session.password)
                            user_id = request.env['res.users'].sudo().browse(uid)
                            if user_id.has_group('base.group_portal'):
                                redirect = '/'
                            return http.redirect_with_hash(redirect)
                        else:
                            values['expire_otp'] = 'true'
                    else:
                        values['wrong_code'] = 'false'
        return request.render('sync_2fa.auth_login', values)
