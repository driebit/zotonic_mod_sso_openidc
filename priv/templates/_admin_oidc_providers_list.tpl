<table class="table table-striped do_adminLinkedTable">
    <thead>
        <tr>
            <th>{_ Enabled _}</th>
            <th>{_ Name _}</th>
            <th>{_ Domain _}</th>
            <th>{_ Description _}</th>
            <th>{_ Issuer URL _}</th>
            <th>{_ Auth _}</th>
            <th>{_ Added by _}</th>
            <th>{_ Created on _}</th>
            <th>{_ User count _}</th>
        </tr>
    </thead>
    <tbody>
        {% for app in m.sso_openidc.providers.list %}
            {% with app.id as id %}
                <tr id="{{ #app.id }}" class="clickable">
                    <td>{% if app.is_enabled %}√{% else %}&times;{% endif %}</td>
                    <td>{{ app.name|escape }}</td>
                    <td>{{ app.domain|escape }}</td>
                    <td>{{ app.description|escape }}</td>
                    <td>{{ app.issuer_url|escape }}</td>
                    <td>{% if app.is_use_auth %}√{% else %}&times;{% endif %}</td>
                    <td>
                        {% if app.user_id %}
                            <a href="{% url admin_edit_rsc id=app.user_id %}">
                                {% include "_name.tpl" id=app.user_id %}
                                ({{ app.user_id }})
                            </a>
                        {% endif %}
                    </td>
                    <td>{{ app.created|date:_"d M Y, H:i" }}</td>
                    <td>{{ app.token_count }}</td>
                </tr>
                {% wire id=#app.id
                        action={dialog_open
                            template="_dialog_oidc_provider.tpl"
                            title=_"Edit OpenID Provider"
                            app_id=app.id
                        }
                %}
            {% endwith %}
        {% empty %}
            <tr>
                <td colspan="9">
                    <span class="text-muted">{_ No providers configured. _}</span>
                </td>
            </tr>
        {% endfor %}
    </tbody>
</table>
