{% wire id=#oidcnew
        type="submit"
        postback={oidc_provider_insert
            ondomain_error=[
                {show target="oidc-domain-error"},
                {hide target="oidc-name-error"}
            ]
            onname_error=[
                {hide target="oidc-domain-error"},
                {show target="oidc-name-error"}
            ]
        }
        delegate=`mod_sso_openidc`
%}
<form id="{{ #oidcnew }}" action="postback">
    <p>
        {_ Add a new provider for OpenID authorization via another website. _}
    </p>

    <div class="form-group">
        <div class="label-floating">
            <input id="{{ #name }}" type="text" value="" class="form-control" name="name" required autofocus placeholder="{_ Name _}" maxlength="80">
            <label class="control-label" for="name">{_ Name _}</label>
            {% validate id=#name name="name"
                        type={presence}
                        type={format pattern="^[-_a-zA-Z0-9]+$"}
            %}
            <p class="help-block">{_ This must be an unique name to identify the remote service. This can not be changed. Only a-z, A-Z, 0-9, _ and - are allowed. _}</p>
        </div>
    </div>

    <div class="form-group">
        <div class="label-floating">
            <input id="{{ #domain }}" type="domain" value="" class="form-control" name="domain" required placeholder="{_ Issuer Domain (eg. www.example.com) _}" maxlength="120">
            <label class="control-label" for="domain">{_ Issuer Domain (eg. www.example.com) _}</label>
            {% validate id=#domain name="domain"
                        type={presence}
                        type={format pattern="^([a-z0-9-]{1,60}\\.)+[a-z]{2,}(/[a-zA-Z0-9\\.\\~_-]+)*/?$"}
            %}
            <p class="help-block">{_ You can also add an optional path to the domain. For example: <tt>example.com/v2/</tt> _}</p>
        </div>
    </div>

    <div class="alert alert-danger" style="display:none" id="oidc-domain-error">
        <b>{_ Could not fetch OpenID configuration from the domain. _}</b>
        {_ Please double check the domain name. _}
    </div>

    <div class="alert alert-danger" style="display:none" id="oidc-name-error">
        <b>{_ There is already a configuration with this name. _}</b>
        {_ Please provide a unique name. _}
    </div>

    <div class="modal-footer sticky-bottom">
        {% button class="btn btn-default" text=_"Cancel" action={dialog_close} tag="a" %}
        {% button class="btn btn-primary" type="submit" text=_"Register and edit" %}
    </div>
</form>
