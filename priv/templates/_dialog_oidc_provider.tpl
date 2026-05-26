{% if m.sso_openidc.providers.byid[app_id] as app %}
    {% wire id=#update
            type="submit"
            postback={oidc_provider_update app_id=app.id}
            delegate=`mod_sso_openidc`
    %}
    <form id="{{ #update }}" action="postback">
        <p>
            {_ Update provider for OpenID authorization via another website. _}
        </p>

        {% include "_oidc_provider_fields.tpl" app=app %}

        <div class="modal-footer sticky-bottom">
            {% if not is_new %}
                {% button class="btn btn-default" text=_"Cancel" action={dialog_close} tag="a" %}
            {% endif %}
            {% button class="btn btn-primary" type="submit" text=_"Update" %}

            {% if app.token_count > 0 %}
                {% button class="btn btn-danger pull-left" type="submit" text=_"Delete"
                    action={confirm
                        text=[
                            _"Are you sure you want to delete this OpenID Provider?",
                            "<br>",
                            "<br>",
                            "<b>", _"This will disconnect all tokens and users.", "</b>"
                        ]
                        is_danger
                        ok=_"Delete OpenID Provider"
                        postback={oidc_provider_delete app_id=app.id}
                        delegate=`mod_sso_openidc`
                    }
                %}
            {% else %}
                {% button class="btn btn-danger pull-left" type="submit" text=_"Delete"
                    action={confirm
                        text=_"Are you sure you want to delete this OpenID Provider?"
                        is_danger
                        ok=_"Delete OpenID Provider"
                        postback={oidc_provider_delete app_id=app.id}
                        delegate=`mod_sso_openidc`
                    }
                %}
            {% endif %}
        </div>
    </form>
{% else %}
    <p class="alert alert-danger">
        {_ OpenID Provider not found, or no view permission. _}
    </p>
    <div class="modal-footer">
        {% button class="btn btn-default" text=_"Cancel" action={dialog_close} tag="a" %}
    </div>
{% endif %}
