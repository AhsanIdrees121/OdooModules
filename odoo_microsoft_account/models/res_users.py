# See LICENSE file for full copyright and licensing details.
import json
from odoo import api, fields, models, tools, _
from odoo.exceptions import AccessDenied, UserError, ValidationError
from odoo.addons.auth_signup.models.res_users import SignupError


class ResUsers(models.Model):
    _inherit = 'res.users'

    microsoft_refresh_token = fields.Char('Microsoft Refresh Token')

    @api.model
    def _microsoft_generate_signup_values(self, provider, params, employee):
        pos_user_group = self.env.ref('point_of_sale.group_pos_user').id
        pos_manager_group = self.env.ref('point_of_sale.group_pos_manager').id
        email = params.get('email')
        # GROUPS_ID ADDED BY AHSAN
        return {
            'name': params.get('name', email),
            'login': email,
            # 'groups_id': [(6, 0, [self.env.ref('base.group_user').id])],
            'groups_id': [(6, 0, [self.env.ref('base.group_user').id,
                                  pos_manager_group if employee.employment_type == 'SalesPerson' else pos_user_group
                                  ])],
            'email': email,
            'oauth_provider_id': provider,
            'oauth_uid': params['user_id'],
            'oauth_access_token': params['access_token'],
            'active': False,
            'microsoft_refresh_token': params['microsoft_refresh_token']
        }

    @api.model
    def _microsoft_auth_oauth_signin(self, provider, params):
        employee = self.env['hr.employee'].search([('work_email', '=', params.get('email'))])
        try:
            oauth_uid = params['user_id']
            users = self.sudo().search([
                ("oauth_uid", "=", oauth_uid),
                ('oauth_provider_id', '=', provider)
            ], limit=1)
            if not users:
                users = self.sudo().search([
                    ("login", "=", params.get('email'))
                ], limit=1)
            if not users:
                raise AccessDenied()
            if users and employee:
                assert len(users.ids) == 1
                users.sudo().write({
                    'oauth_access_token': params['access_token'],
                    'microsoft_refresh_token': params['microsoft_refresh_token']})
                user_id = self.env['res.users'].search([('login', '=', employee.work_email)])
                if employee.user_id != user_id:
                    employee.user_id = user_id
                return users.login
        except AccessDenied as access_denied_exception:
            if self._context and self._context.get('no_user_creation'):
                return None
            values = self._microsoft_generate_signup_values(provider, params, employee)
            try:
                values['active'] = True
                # Checks for employee ADDED BY AHSAN
                if employee:
                    _, login, _ = self.with_context(
                        mail_create_nosubscribe=True, force_company=1).signup(values)
                    user_id = self.env['res.users'].search([('login', '=', employee.work_email)])
                    employee.user_id = user_id
                    return login
                if not employee:
                    _, login, _ = self.with_context(
                        mail_create_nosubscribe=True).signup(values)
                    return login
            except (SignupError, UserError):
                raise access_denied_exception

    @api.model
    def microsoft_auth_oauth(self, provider, params):
        access_token = params.get('access_token')
        # employee_id = self.env['hr.employee'].search([("work_email", "=", params.get('email'))])
        # login = self.emp_to_user(employee_id)
        login = self._microsoft_auth_oauth_signin(provider, params)
        if not login:
            raise AccessDenied()
        return self._cr.dbname, login, access_token
