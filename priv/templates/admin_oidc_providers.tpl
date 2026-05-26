{% extends "admin_base.tpl" %}

{% block title %}{_ OpenID Providers _}{% endblock %}

{% block content %}
<div class="admin-header">
    <h2>{_ OpenID Providers _}</h2>

    <p>
        {_ With an OpenID Provider token this website can: _}
    </p>

    <ul>
        <li>{_ Allow users registered on the remote website to authenticate on this website. _}</li>
    </ul>
</div>

{% if m.acl.is_admin or m.acl.is_allowed.use.mod_sso_oidc %}
    <div class="well z-button-row">
        <button id="app-new" class="btn btn-primary">
            {_ Register a new provider _}
        </button>
        {% wire id="app-new"
                action={dialog_open
                    title=_"Register a new provider"
                    template="_dialog_oidc_provider_new.tpl"
                }
        %}
    </div>

    {% if q.app_id %}
        {% wire action={dialog_open
                    title=_"Edit provider"
                    template="_dialog_oidc_provider.tpl"
                    app_id=q.app_id|to_integer
                }
        %}
    {% endif %}

    <div id="oidc-providers-list">
        {% include "_admin_oidc_providers_list.tpl" %}
    </div>

    {% with `x-default` as z_language %}
        <p class="help-block">
            <span class="glyphicon glyphicon-info-sign"></span>
            {_ The redirect URL for the configuration of providers is: _}<br>
            &nbsp;&nbsp;&nbsp;&nbsp; <tt>{% url oauth2_service_redirect absolute_url %}</tt>
        </p>
    {% endwith %}
{% else %}
    <p class="alert alert-danger">
        <strong>{_ Not allowed. _}</strong>
        {_ Only admnistrators can view OpenID Providers. _}
    </p>
{% endif %}

{% endblock %}
