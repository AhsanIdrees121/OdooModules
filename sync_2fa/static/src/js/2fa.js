odoo.define('sync_2fa.auth_code', function (require) {
    "use strict";

    var publicWidget = require('web.public.widget');

    publicWidget.registry.Auth2factor = publicWidget.Widget.extend({
        selector: '.oe_code_mail',
    /**
     * @override
     */
        start: function () {
            $('#send_code_mail').click(function(){
                if ($(this).prop('checked')) {
                    $('.submit-button').attr('value', 'Get Code');
                    $('.auth_code_lable').addClass('d-none');
                    $('#auth_code').addClass('d-none').attr('required', false);
                    $('.partner_email').removeClass('d-none');
                    $('.email_lable').removeClass('d-none');
                }else {
                    $('.submit-button').attr('value', 'Submit');
                    $('.auth_code_lable').removeClass('d-none');
                    $('#auth_code').removeClass('d-none').attr('required', true);
                    $('.partner_email').addClass('d-none');
                    $('.email_lable').addClass('d-none');
                }
            });

            return this._super.apply(this, arguments);
        },
    });
});
