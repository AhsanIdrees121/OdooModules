# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import qrcode
import pyotp
import base64
from odoo import models, fields, api, _
from io import BytesIO
from odoo.exceptions import Warning


class ResUsers(models.Model):
    _inherit = 'res.users'

    def _generate_qr_code(self):
        for rec in self:
            rec.qrcode = False
            if rec.user_2f_enable_status:
                base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
                base_url += '/web#id=%d&view_type=form&model=%s' % (rec.id, self._name)
                base_url = pyotp.totp.TOTP(rec.secret_key).provisioning_uri(base_url, issuer_name="Secure App")
                rec.qrcode = rec.generate_qr_code(base_url)

    secret_key = fields.Char('Digits Access Token', copy=False)
    user_2f_enable_status = fields.Boolean('Enable 2FA Login', copy=False)
    qrcode = fields.Binary('QR Code', compute=_generate_qr_code)
    time_limit = fields.Integer(string="Email OTP Time Limit (Seconds)", default=60)

    @api.constrains('time_limit')
    def check_limit(self):
        # if self.time_limit < 30:
        #     raise Warning('Time Greator then to 30')
        if self.time_limit > 900:
            raise Warning('Time Less then to 900')

    @api.onchange('user_2f_enable_status')
    def update_time_limit(self):
        if self.user_2f_enable_status:
            self.time_limit = 60

    def __init__(self, pool, cr):
        """ Override of __init__ to add access rights on notification_email_send
            and alias fields. Access rights are disabled by default, but allowed
            on some specific fields defined in self.SELF_{READ/WRITE}ABLE_FIELDS.
        """
        init_res = super(ResUsers, self).__init__(pool, cr)
        # duplicate list to avoid modifying the original reference
        type(self).SELF_WRITEABLE_FIELDS = list(self.SELF_WRITEABLE_FIELDS)
        type(self).SELF_WRITEABLE_FIELDS.extend(['user_2f_enable_status','secret_key'])
        # duplicate list to avoid modifying the original reference
        type(self).SELF_READABLE_FIELDS = list(self.SELF_READABLE_FIELDS)
        type(self).SELF_READABLE_FIELDS.extend(['user_2f_enable_status','secret_key'])
        return init_res

    @api.model
    def create(self, values):
        if 'user_2f_enable_status' in values:
            values['secret_key'] = ''
            if values['user_2f_enable_status']:
                values['secret_key'] = pyotp.random_base32()
        return super(ResUsers, self).create(values)

    def write(self, values):
        template_id = self.env.ref('sync_2fa.2fa_email')
        if 'user_2f_enable_status' in values:
            values['secret_key'] = ''
            if values['user_2f_enable_status']:
                values['secret_key'] = pyotp.random_base32()
        res = super(ResUsers, self).write(values)
        for rec in self:
            if values.get('user_2f_enable_status') and template_id:
                template_id.sudo().with_context({'img': rec.qrcode.decode("utf-8")}).send_mail(rec.id,
                                                                                               force_send=True,
                                                                                               raise_exception=False)
        return res

    @api.onchange('user_2f_enable_status')
    def onchange_user_2fa(self):
        if not self.user_2f_enable_status:
            self.secret_key = ''

    def generate_qr_code(self, url):
        qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=20,
                    border=4)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image()
        temp = BytesIO()
        img.save(temp, format="PNG")
        return base64.b64encode(temp.getvalue())

    def send_2fa_mail(self):
        self.ensure_one()
        try:
            template_id = self.env.ref('sync_2fa.2fa_email')
        except ValueError:
            template_id = False
        if template_id and self.qrcode:
            template_id.sudo().with_context({'img': self.qrcode.decode("utf-8")}).send_mail(self.id, force_send=True, raise_exception=False)
